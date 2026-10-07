"""Authentication, tenant isolation, RBAC and approval semantics of the HTTP API."""

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from fastapi.testclient import TestClient

from apps.server import app
from apps.agents.core.security_principal import create_principal_token, get_jwt_secret_key

SAMPLE = "packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"
BENIGN = "tests/fixtures/corpus/01_benign_auth_pass.eml"

client = TestClient(app, raise_server_exceptions=False)


def auth(tenant="tenant-a", roles=("SOC_ANALYST",), sub="alice"):
    return {"Authorization": "Bearer " + create_principal_token(sub, tenant, list(roles))}


def investigate(path, headers):
    with open(path, "rb") as f:
        r = client.post("/api/v1/investigate", headers=headers, files={"file": ("m.eml", f.read())})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def malicious_incident():
    return investigate(SAMPLE, auth())


# --------------------------------------------------------------------------- authentication
@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Token abc"},
    {"Authorization": "Bearer not.a.jwt"},
    {"Authorization": "Bearer " + jwt.encode({"sub": "a", "tenant_id": "t", "exp": time.time() - 5}, get_jwt_secret_key(), "HS256")},
    {"Authorization": "Bearer " + jwt.encode({"sub": "a", "tenant_id": "t", "exp": time.time() + 60}, "x" * 40, "HS256")},
    {"Authorization": "Bearer " + jwt.encode({"sub": "a", "exp": time.time() + 60}, get_jwt_secret_key(), "HS256")},
])
def test_invalid_credentials_rejected(headers):
    assert client.get("/api/v1/incidents", headers=headers).status_code == 401


def test_alg_none_and_tampered_claims_rejected():
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    none_token = enc({"alg": "none", "typ": "JWT"}) + "." + enc({"sub": "a", "tenant_id": "tenant-a", "exp": time.time() + 60}) + "."
    assert client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {none_token}"}).status_code == 401
    h, p, s = auth()["Authorization"].split()[1].split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims["tenant_id"] = "tenant-b"
    forged = f"{h}.{enc(claims)}.{s}"
    assert client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


@pytest.mark.parametrize("method,path", [
    ("get", "/api/v1/system-health"), ("get", "/api/v1/mode"), ("get", "/api/v1/integrations"),
    ("get", "/api/v1/trust-score"), ("post", "/api/v1/demo"), ("get", "/api/v1/audit-logs"),
    ("get", "/api/v1/planner-settings"), ("get", "/api/v1/readiness"),
])
def test_api_routes_require_authentication(method, path):
    assert getattr(client, method)(path).status_code == 401


def test_liveness_is_public_and_reveals_nothing():
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


# --------------------------------------------------------------------------- tenant isolation
def test_cross_tenant_access_is_indistinguishable_from_missing(malicious_incident):
    iid = malicious_incident["incident_id"]
    other = auth("tenant-b", sub="mallory")
    for path in (f"/api/v1/incidents/{iid}", f"/api/v1/investigations/{iid}/events",
                 f"/api/v1/investigations/compare?id_a={iid}&id_b={iid}"):
        assert client.get(path, headers=other).status_code == 404
    assert client.post(f"/api/v1/investigations/{iid}/replay", headers=other).status_code == 404
    assert iid not in client.get("/api/v1/incidents", headers=other).text
    assert iid not in client.get("/api/v1/audit-logs", headers=other).text
    assert client.get("/api/v1/incidents", headers={**other, "X-Tenant-ID": "tenant-a"}).status_code == 403


def test_cross_tenant_approval_actions_forbidden(malicious_incident):
    token = malicious_incident["pending_approvals"][0]["approval_token"]
    other = auth("tenant-b", roles=("SOC_ADMIN",), sub="mallory")
    assert client.post(f"/api/v1/approve/{token}", headers=other).status_code == 403
    assert client.post(f"/api/v1/reject/{token}", headers=other).status_code == 403
    assert client.post(f"/api/v1/request-info/{token}", headers=other).status_code == 403


def test_planner_settings_are_tenant_scoped_and_admin_only():
    assert client.post("/api/v1/planner-settings", headers=auth(), json={"planner_mode": "RULE"}).status_code == 403
    admin = auth(roles=("SOC_ADMIN",))
    r = client.post("/api/v1/planner-settings", headers=admin, json={"planner_mode": "RULE", "hybrid_arbitration_policy": "SAFETY_FIRST"})
    assert r.status_code == 200
    assert client.get("/api/v1/planner-settings", headers=auth()).json()["planner_mode"] == "RULE"
    assert client.get("/api/v1/planner-settings", headers=auth("tenant-b")).json()["planner_mode"] == "HYBRID"
    assert client.post("/api/v1/planner-settings", headers=admin, json={"planner_mode": "YOLO"}).status_code == 400
    client.post("/api/v1/planner-settings", headers=admin, json={})


# --------------------------------------------------------------------------- input handling
def test_empty_and_oversized_uploads_rejected(monkeypatch):
    import apps.server as server
    assert client.post("/api/v1/investigate", headers=auth(), files={"file": ("e.eml", b"")}).status_code == 400
    monkeypatch.setattr(server, "MAX_EML_BYTES", 100)
    assert client.post("/api/v1/investigate", headers=auth(), files={"file": ("e.eml", b"x" * 101)}).status_code == 413


def test_benign_email_produces_no_containment():
    inc = investigate(BENIGN, auth())
    assert inc["severity"] == "LOW" and inc["pending_approvals"] == [] and inc["cve"] is None


# --------------------------------------------------------------------------- approvals
def _token(incident, tool):
    return next(p["approval_token"] for p in incident["pending_approvals"] if p["tool_name"] == tool)


def test_high_risk_approval_requires_responder_role():
    inc = investigate(SAMPLE, auth())
    token = _token(inc, "revoke_session")
    r = client.post(f"/api/v1/approve/{token}", headers=auth())
    assert r.status_code == 403 and "Insufficient role" in r.text
    # Still pending: an authorized responder can act on it
    r = client.post(f"/api/v1/approve/{token}", headers=auth(roles=("INCIDENT_RESPONDER",)))
    assert r.status_code == 502  # no IdP connector configured -> honest dispatch failure


def test_unconfigured_connector_is_not_reported_as_success():
    inc = investigate(SAMPLE, auth())
    token = _token(inc, "quarantine_email")
    r = client.post(f"/api/v1/approve/{token}", headers=auth())
    assert r.status_code == 502
    assert r.json()["detail"]["output"]["status"] == "NOT_CONFIGURED"
    assert client.post(f"/api/v1/approve/{token}", headers=auth()).status_code == 400  # single use


def test_configured_connector_receives_the_approved_action(monkeypatch):
    received = []

    class Gateway(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"quarantined": 1}')

    srv = HTTPServer(("127.0.0.1", 0), Gateway)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("MAIL_GATEWAY_URL", f"http://127.0.0.1:{srv.server_port}/quarantine")
    try:
        inc = investigate(SAMPLE, auth())
        r = client.post(f"/api/v1/approve/{_token(inc, 'quarantine_email')}", headers=auth())
        assert r.status_code == 200 and r.json()["status"] == "DISPATCHED"
        assert received[0]["action"] == "quarantine_email"
        assert received[0]["parameters"]["mailbox"] == inc["recipient"]
        after = client.get(f"/api/v1/incidents/{inc['incident_id']}", headers=auth()).json()
        assert [p["tool_name"] for p in after["pending_approvals"]] == ["revoke_session"]
        assert after["resolved_approvals"][0]["outcome"] == "DISPATCHED"
        r = client.post(f"/api/v1/reject/{_token(inc, 'revoke_session')}", headers=auth())
        after = client.get(f"/api/v1/incidents/{inc['incident_id']}", headers=auth()).json()
        assert after["pending_approvals"] == [] and after["status"] == "CONTAINED"
    finally:
        srv.shutdown()


def test_concurrent_approvals_claim_exactly_once():
    inc = investigate(SAMPLE, auth())
    token = _token(inc, "quarantine_email")
    codes = []
    threads = [threading.Thread(target=lambda: codes.append(
        TestClient(app, raise_server_exceptions=False).post(f"/api/v1/approve/{token}", headers=auth()).status_code)) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert codes.count(502) == 1 and codes.count(400) == 11, codes


def test_forged_rejected_and_request_info_tokens():
    assert client.post("/api/v1/approve/APP-DEADBEEF-CAFEBABE", headers=auth()).status_code == 400
    inc = investigate(SAMPLE, auth())
    token = _token(inc, "quarantine_email")
    assert client.post(f"/api/v1/request-info/{token}", headers=auth()).json()["status"] == "RECORDED"
    assert client.post(f"/api/v1/reject/{token}", headers=auth()).status_code == 200
    assert client.post(f"/api/v1/approve/{token}", headers=auth()).status_code == 400
    assert client.post(f"/api/v1/reject/{token}", headers=auth()).status_code == 400


def test_approval_binds_to_the_incident(malicious_incident):
    assert all(p["incident_id"] == malicious_incident["incident_id"] for p in malicious_incident["pending_approvals"])


# --------------------------------------------------------------------------- configuration
def test_token_minting_disabled_in_production(monkeypatch):
    monkeypatch.setenv("FISHINGMAILS_ENV", "production")
    monkeypatch.setenv("ENVIRONMENT", "production")
    assert client.post("/api/v1/auth/token", json={"roles": ["ADMIN"]}).status_code == 404


def test_integrations_report_unconfigured_connectors_truthfully():
    data = {i["integration_id"]: i for i in client.get("/api/v1/integrations", headers=auth()).json()}
    assert data["mail-gateway"]["status"] == "NOT_CONFIGURED"
    assert data["urlhaus"]["status"] == "NOT_CONFIGURED"
    assert data["cisa-kev"]["status"] == "OPERATIONAL"
