"""
FishingMails API server.

All /api/v1 routes require a verified HS256 JWT (see apps/agents/core/security_principal.py).
The tenant is always taken from the token; client-supplied tenant hints are only consistency checks.
"""

import asyncio
import datetime
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.investigation_service import InvestigationService, new_incident_id
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.event_system import EventStreamManager
from apps.agents.core.integration_center import IntegrationManager
from apps.agents.core.agent_builder import PlannerSettings, get_planner_settings, save_planner_settings
from apps.agents.core.trust_score import TrustScoreCalculator
from apps.agents.core.production_manager import ProductionManager, PlatformMode
from apps.agents.core.approval_manager import ApprovalManager, get_hmac_secret_key
from apps.agents.core.security_principal import (
    AuthenticatedPrincipal,
    create_principal_token,
    get_authenticated_principal,
    get_environment,
    get_jwt_secret_key,
    is_local_auth_fallback_enabled,
    is_production_mode,
    resolve_authorized_tenant,
)

MAX_EML_BYTES = int(os.getenv("FISHINGMAILS_MAX_EML_BYTES", str(25 * 1024 * 1024)))
ADMIN_ROLES = {"ADMIN", "SOC_ADMIN"}
SAMPLE_EML = os.path.join(os.path.dirname(__file__), "..", "packages", "email_parser", "samples",
                          "synthetic_cve_2023_35636_rendering_exploit.eml")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail closed on insecure configuration before serving any request.
    get_environment()
    get_jwt_secret_key()
    is_local_auth_fallback_enabled()
    get_hmac_secret_key()
    yield


app = FastAPI(title="FishingMails API", version="1.1.0", lifespan=lifespan)

_cors = [o.strip() for o in os.getenv("FISHINGMAILS_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID", "Accept"],
)

investigation_service = InvestigationService()
_investigation_pool = ThreadPoolExecutor(
    max_workers=int(os.getenv("FISHINGMAILS_MAX_CONCURRENT_INVESTIGATIONS", "4")), thread_name_prefix="investigation")
_running: Dict[str, str] = {}  # incident_id -> tenant_id for investigations still in progress
_running_lock = threading.Lock()
logger = logging.getLogger("FishingMailsAPI")
tool_registry = ToolRegistry.get_instance()
event_manager = EventStreamManager.get_instance()
integration_manager = IntegrationManager.get_instance()
prod_manager = ProductionManager.get_instance()
approval_manager = ApprovalManager.get_instance()


def record_audit_event(principal: AuthenticatedPrincipal, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    investigation_service.durable_storage.record_audit_log(
        actor=principal.subject_id, action=action, details=details or {}, tenant_id=principal.tenant_id)


def require_admin(principal: AuthenticatedPrincipal) -> None:
    if not ADMIN_ROLES.intersection(principal.roles):
        raise HTTPException(status_code=403, detail="Administrator role required.")


def _incident_or_404(incident_id: str, tenant_id: str):
    try:
        inc = investigation_service.get_incident(incident_id, tenant_id=tenant_id)
    except PermissionError:
        # Do not reveal whether an incident exists in another tenant.
        raise HTTPException(status_code=404, detail="Incident not found")
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
@app.get("/healthz")
async def healthz():
    """Unauthenticated liveness probe. Reveals no configuration."""
    return {"status": "ok"}


@app.get("/api/v1/system-health")
async def system_health(request: Request):
    principal = get_authenticated_principal(request)
    db_ok, db_msg = investigation_service.durable_storage.check_health()
    integrations = integration_manager.list_integrations(probe=False)
    return {
        "status": "HEALTHY" if db_ok else "DEGRADED",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "environment": get_environment(),
        "mode": prod_manager.current_mode.value,
        "is_production": prod_manager.is_production(),
        "database": db_msg if ADMIN_ROLES.intersection(principal.roles) else ("OK" if db_ok else "ERROR"),
        "integrations": {i["integration_id"]: i["status"] for i in integrations},
    }


@app.get("/api/v1/readiness")
async def readiness(request: Request):
    """Admin-only readiness report covering the dependencies an investigation actually needs."""
    require_admin(get_authenticated_principal(request))
    checks: Dict[str, Any] = {}
    db_ok, db_msg = investigation_service.durable_storage.check_health()
    checks["database"] = {"ok": db_ok, "detail": db_msg}
    try:
        get_hmac_secret_key()
        checks["approval_secret"] = {"ok": True}
    except RuntimeError as exc:
        checks["approval_secret"] = {"ok": False, "detail": str(exc)}
    try:
        from packages.email_parser.src.mime_parser import MimeParser
        MimeParser().parse_eml(b"From: a@b.example\r\nTo: c@d.example\r\nSubject: t\r\n\r\nbody")
        checks["parser"] = {"ok": True}
    except Exception as exc:
        checks["parser"] = {"ok": False, "detail": str(exc)}
    checks["integrations"] = integration_manager.list_integrations(probe=True)
    ready = all(v.get("ok", True) for k, v in checks.items() if isinstance(v, dict))
    return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, "checks": checks})


# --------------------------------------------------------------------------- #
# Mode & tokens
# --------------------------------------------------------------------------- #
@app.get("/api/v1/mode")
async def get_platform_mode(request: Request):
    get_authenticated_principal(request)
    return prod_manager.get_status_summary()


@app.post("/api/v1/mode")
async def set_platform_mode(request: Request):
    principal = get_authenticated_principal(request)
    require_admin(principal)
    if is_production_mode() or prod_manager.is_production():
        raise HTTPException(status_code=403, detail="Platform mode cannot be changed in a production/staging environment.")
    body = await request.json()
    try:
        new_mode = PlatformMode(str(body.get("mode", "")).upper())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid mode")
    if new_mode == PlatformMode.PRODUCTION:
        raise HTTPException(status_code=400, detail="PRODUCTION is selected by FISHINGMAILS_ENV, not at runtime.")
    prod_manager.set_mode(new_mode)
    record_audit_event(principal, "SET_PLATFORM_MODE", {"mode": new_mode.value})
    return prod_manager.get_status_summary()


@app.post("/api/v1/auth/token")
async def obtain_token(request: Request):
    """
    Development/test only: mints tokens with bounded claims. Disabled in production/staging,
    where tokens must be issued by your identity provider using FISHINGMAILS_AUTH_SECRET.
    """
    if is_production_mode():
        raise HTTPException(status_code=404, detail="Not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    allowed_roles = {"SOC_ANALYST", "INCIDENT_RESPONDER", "SOC_ADMIN", "ADMIN"}
    roles = [r for r in body.get("roles", []) if r in allowed_roles] if isinstance(body.get("roles"), list) else []
    expires = body.get("expires_in", 3600)
    if not isinstance(expires, (int, float)) or not 0 < expires <= 86400:
        expires = 3600
    subject = str(body.get("subject_id", "dev_analyst"))[:64]
    tenant = str(body.get("tenant_id", "tenant-dev"))[:64]
    token = create_principal_token(subject_id=subject, tenant_id=tenant, roles=roles or ["SOC_ANALYST"],
                                   expires_in_seconds=int(expires))
    return {"access_token": token, "token_type": "bearer", "expires_in": int(expires), "tenant_id": tenant, "subject_id": subject}


# --------------------------------------------------------------------------- #
# Incidents & investigations
# --------------------------------------------------------------------------- #
@app.get("/api/v1/incidents")
async def get_incidents(request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    limit_param = request.query_params.get("limit", "")
    limit = min(int(limit_param), 500) if limit_param.isdigit() else 100
    return [i.model_dump() for i in investigation_service.list_incidents(tenant_id=tenant_id, limit=limit)]


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_detail(incident_id: str, request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    return _incident_or_404(incident_id, tenant_id).model_dump()


@app.post("/api/v1/incidents/{incident_id}/status")
async def set_incident_status(incident_id: str, request: Request):
    """Analyst disposition of an incident."""
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    _incident_or_404(incident_id, tenant_id)
    body = await request.json()
    status = str(body.get("status", "")).upper()
    if status not in {"TRIAGED", "ESCALATED", "CLOSED", "FALSE_POSITIVE"}:
        raise HTTPException(status_code=400, detail="status must be TRIAGED, ESCALATED, CLOSED or FALSE_POSITIVE")
    rec = investigation_service.update_status(incident_id, tenant_id, status)
    record_audit_event(principal, "SET_INCIDENT_STATUS", {"incident_id": incident_id, "status": status})
    return {"incident_id": incident_id, "status": rec.status}


async def _read_upload(request: Request, file: UploadFile, tenant_id: Optional[str]):
    principal = get_authenticated_principal(request)
    if tenant_id and tenant_id != principal.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch with authenticated identity.")
    raw_eml = await file.read(MAX_EML_BYTES + 1)
    if not raw_eml:
        raise HTTPException(status_code=400, detail="Empty email payload uploaded.")
    if len(raw_eml) > MAX_EML_BYTES:
        raise HTTPException(status_code=413, detail=f"Email exceeds {MAX_EML_BYTES} bytes.")
    return principal, raw_eml


@app.post("/api/v1/investigations", status_code=202)
async def start_investigation(request: Request, file: UploadFile = File(...), tenant_id: Optional[str] = Form(None)):
    """Starts an investigation in the background and returns at once; follow it live via the events stream."""
    principal, raw_eml = await _read_upload(request, file, tenant_id)
    incident_id = new_incident_id()
    filename = (file.filename or "uploaded_email.eml")[:255]
    with _running_lock:
        _running[incident_id] = principal.tenant_id

    def job():
        try:
            incident = investigation_service.run_investigation(
                tenant_id=principal.tenant_id, raw_eml=raw_eml, autonomy_level=1,
                source_filename=filename, incident_id=incident_id)
            record_audit_event(principal, "INVESTIGATION_COMPLETED", {
                "incident_id": incident_id, "risk_score": incident.overall_risk_score, "severity": incident.severity})
        except Exception as exc:
            logger.error(f"Background investigation {incident_id} failed: {exc}")
            event_manager.publish_event(investigation_id=incident_id, agent_run_id="background", event_type="agent.failed",
                                        message=f"Investigation failed: {exc}", status="FAILED")
        finally:
            with _running_lock:
                _running.pop(incident_id, None)

    asyncio.get_running_loop().run_in_executor(_investigation_pool, job)
    return JSONResponse(status_code=202, content={
        "incident_id": incident_id, "status": "RUNNING",
        "events": f"/api/v1/investigations/{incident_id}/events"})


@app.post("/api/v1/investigate")
async def investigate_email(request: Request, file: UploadFile = File(...), tenant_id: Optional[str] = Form(None)):
    """Synchronous variant: returns the finished incident."""
    principal, raw_eml = await _read_upload(request, file, tenant_id)
    try:
        incident = investigation_service.run_investigation(
            tenant_id=principal.tenant_id, raw_eml=raw_eml, autonomy_level=1,
            source_filename=(file.filename or "uploaded_email.eml")[:255])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    record_audit_event(principal, "INVESTIGATION_COMPLETED", {
        "incident_id": incident.incident_id, "risk_score": incident.overall_risk_score, "severity": incident.severity})
    return incident.model_dump()


@app.get("/api/v1/investigations/compare")
async def compare_investigations(id_a: str, id_b: str, request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    a = _incident_or_404(id_a, tenant_id).model_dump()
    b = _incident_or_404(id_b, tenant_id).model_dump()

    def summary(d):
        return {"id": d["incident_id"], "title": d["title"], "risk_score": d["overall_risk_score"], "severity": d["severity"],
                "evidence_count": len(d["evidence_items"]), "tool_calls": len(d["tool_executions"]),
                "decisions_count": len(d["decision_trace"]), "verdict": d["threat_category"]}

    return {"investigation_a": summary(a), "investigation_b": summary(b),
            "delta": {"risk_difference": round(abs(a["overall_risk_score"] - b["overall_risk_score"]), 1),
                      "different_verdicts": a["severity"] != b["severity"],
                      "evidence_difference": abs(len(a["evidence_items"]) - len(b["evidence_items"]))}}


@app.get("/api/v1/investigations/{incident_id}/events")
async def stream_investigation_events(incident_id: str, request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    with _running_lock:
        running_tenant = _running.get(incident_id)
    if running_tenant is None:
        _incident_or_404(incident_id, tenant_id)
    elif running_tenant != tenant_id:
        raise HTTPException(status_code=404, detail="Incident not found")

    async def sse():
        async for event in event_manager.subscribe(incident_id):
            if await request.is_disconnected():
                break
            yield ": keepalive\n\n" if event is None else event.to_sse_payload()

    return StreamingResponse(sse(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/v1/investigations/{incident_id}/replay")
async def replay_investigation(incident_id: str, request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    _incident_or_404(incident_id, tenant_id)
    return [e.model_dump() for e in event_manager.get_events(incident_id)]


@app.get("/api/v1/trust-score")
async def get_agent_trust_score(request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    latest = investigation_service.list_incidents(tenant_id=tenant_id, limit=1)
    if latest and latest[0].trust_score:
        return latest[0].trust_score.model_dump()
    return TrustScoreCalculator.calculate(0, [], [], [], 0).model_dump()


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@app.get("/api/v1/integrations")
async def list_integrations(request: Request):
    get_authenticated_principal(request)
    return integration_manager.list_integrations(probe=False)


@app.post("/api/v1/integrations/{integration_id}/health")
async def test_integration_health(integration_id: str, request: Request):
    require_admin(get_authenticated_principal(request))
    try:
        return integration_manager.get(integration_id, probe=True)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown integration")


@app.get("/api/v1/planner-settings")
async def get_settings(request: Request):
    principal = get_authenticated_principal(request)
    return get_planner_settings(principal.tenant_id).model_dump()


@app.post("/api/v1/planner-settings")
async def update_settings(request: Request):
    principal = get_authenticated_principal(request)
    require_admin(principal)
    try:
        settings = PlannerSettings(**(await request.json()))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid planner settings: {exc}")
    save_planner_settings(principal.tenant_id, settings)
    record_audit_event(principal, "UPDATE_PLANNER_SETTINGS", settings.model_dump())
    return settings.model_dump()


# --------------------------------------------------------------------------- #
# Human approval
# --------------------------------------------------------------------------- #
@app.post("/api/v1/approve/{token}")
async def approve_containment(token: str, request: Request):
    principal = get_authenticated_principal(request)
    res = approval_manager.authorize_and_execute(
        tenant_id=principal.tenant_id, token=token, approver_email=principal.subject_id, approver_roles=principal.roles)
    record_audit_event(principal, "APPROVAL_ATTEMPT", {
        "token": token, "tool_name": res.get("tool_name"), "executed": res.get("executed"),
        "success": res.get("success"), "error": res.get("error")})
    if res.get("executed"):
        investigation_service.resolve_approval(principal.tenant_id, token,
                                               "DISPATCHED" if res.get("success") else "DISPATCH_FAILED", principal.subject_id)
    if res.get("success"):
        return {"status": "DISPATCHED", "message": f"Action '{res['tool_name']}' dispatched and confirmed by the connector.",
                "output": res.get("result")}
    err = res.get("error") or "Approval failed."
    if res.get("forbidden") or "Tenant mismatch" in err:
        raise HTTPException(status_code=403, detail=err)
    if res.get("executed"):
        # Approval was valid and consumed, but the connector did not confirm the action.
        raise HTTPException(status_code=502, detail={"status": "DISPATCH_FAILED", "message": err, "output": res.get("result")})
    raise HTTPException(status_code=400, detail=err)


@app.post("/api/v1/reject/{token}")
async def reject_containment(token: str, request: Request):
    principal = get_authenticated_principal(request)
    res = approval_manager.reject_action(tenant_id=principal.tenant_id, token=token, approver_email=principal.subject_id)
    if not res.get("success"):
        err = res.get("error", "Invalid approval token")
        raise HTTPException(status_code=403 if "Tenant mismatch" in err else 400, detail=err)
    investigation_service.resolve_approval(principal.tenant_id, token, "REJECTED", principal.subject_id)
    record_audit_event(principal, "REJECTED_CONTAINMENT", {"token": token})
    return {"status": "REJECTED", "message": f"Proposal {token} was rejected."}


@app.post("/api/v1/request-info/{token}")
async def request_more_investigation(token: str, request: Request):
    """Records that the analyst wants more information before deciding; the proposal stays pending."""
    principal = get_authenticated_principal(request)
    stored = approval_manager.storage.get_approval_token(token)
    if not stored or stored.get("status") != "PENDING":
        raise HTTPException(status_code=400, detail="Invalid or non-pending approval token.")
    if stored.get("tenant_id") != principal.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch for approval token")
    record_audit_event(principal, "REQUESTED_MORE_INFORMATION", {"token": token, "incident_id": stored.get("incident_id")})
    return {"status": "RECORDED", "message": "Request recorded in the audit log; the proposal remains pending."}


@app.get("/api/v1/audit-logs")
async def get_audit_logs(request: Request):
    principal = get_authenticated_principal(request)
    tenant_id = resolve_authorized_tenant(request, principal)
    return investigation_service.durable_storage.get_audit_logs(tenant_id=tenant_id, limit=200)


# --------------------------------------------------------------------------- #
# Demo (non-production only)
# --------------------------------------------------------------------------- #
@app.post("/api/v1/demo")
async def run_demo_sample(request: Request):
    principal = get_authenticated_principal(request)
    if is_production_mode() or not prod_manager.allows_fixtures():
        raise HTTPException(status_code=403, detail="Demo fixtures are only available in DEMO or TEST mode.")
    with open(SAMPLE_EML, "rb") as f:
        raw = f.read()
    incident = investigation_service.run_investigation(
        tenant_id=principal.tenant_id, raw_eml=raw, autonomy_level=1, source_filename=os.path.basename(SAMPLE_EML))
    return incident.model_dump()


@app.get("/")
async def root():
    return {"service": "FishingMails API", "docs": "/docs", "health": "/healthz"}
