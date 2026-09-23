"""
InvestigationService: Manages incident lifecycles, correlated investigations,
and coordinates the synthetic telemetry simulation pipelines for the SOC.
"""

import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import SecurityState
from apps.agents.graph import SecurityGraph
from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository
from packages.attack_graph.src.models import AttackGraphData

logger = logging.getLogger("InvestigationService")


class IncidentRecord(BaseModel):
    incident_id: str
    tenant_id: str
    title: str
    severity: str
    overall_risk_score: float
    confidence: float
    status: str = "OPEN"  # OPEN, TRIAGED, INVESTIGATING, CONTAINMENT_PROPOSED, CONTAINED, CLOSED
    target_identity: str
    mail_platform: str
    exposure_status: str
    interaction_required: str  # NONE, VIEW, CLICK, etc.
    cve: Optional[str] = None
    attack_chain: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_summary: List[str] = Field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)
    graph_context: Optional[Dict[str, Any]] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class InvestigationService:
    def __init__(self, graph_repo: Optional[InMemoryAttackGraphRepository] = None):
        self.graph_repo = graph_repo or InMemoryAttackGraphRepository()
        self.security_graph = SecurityGraph()
        self.security_graph.investigation_node.graph_repo = self.graph_repo
        
        self._incidents: Dict[str, IncidentRecord] = []
        self._incidents_map: Dict[str, IncidentRecord] = {}
        self._simulated_assets: List[Dict[str, Any]] = []
        self._simulated_identity_events: List[Dict[str, Any]] = []
        self._simulated_sessions: List[Dict[str, Any]] = []

    def run_investigation(self, tenant_id: str, raw_eml: bytes, autonomy_level: int = 1) -> IncidentRecord:
        """
        Executes the full LangGraph investigation on raw EML and creates an active incident record.
        """
        workflow_id = f"wf-{uuid.uuid4().hex[:8]}"
        initial_state: SecurityState = {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "autonomy_level": autonomy_level,
            "raw_eml": raw_eml
        }

        final_state = self.security_graph.run(initial_state)
        report = final_state.get("incident_report", {})
        
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        record = IncidentRecord(
            incident_id=incident_id,
            tenant_id=tenant_id,
            title=report.get("title", "Suspicious Email Activity Detected"),
            severity=report.get("severity", "MEDIUM"),
            overall_risk_score=report.get("overall_risk_score", 50.0),
            confidence=report.get("confidence", 0.85),
            status="CONTAINMENT_PROPOSED" if final_state.get("pending_approvals") else "OPEN",
            target_identity=report.get("target_identity", "unknown@corp"),
            mail_platform=report.get("mail_platform", "Exchange / OWA"),
            exposure_status=report.get("exposure_status", "Internet-Facing"),
            interaction_required=report.get("interaction_required", "VIEW"),
            cve=report.get("cve"),
            attack_chain=report.get("attack_chain", []),
            mitre_techniques=report.get("mitre_techniques", []),
            evidence_summary=report.get("evidence_summary", []),
            recommended_actions=report.get("recommended_actions", []),
            pending_approvals=final_state.get("pending_approvals", []),
            graph_context=final_state.get("graph_context")
        )

        self._incidents_map[incident_id] = record
        logger.info(f"Created incident {incident_id} with severity {record.severity} (Interaction: {record.interaction_required})")
        return record

    def list_incidents(self, tenant_id: Optional[str] = None) -> List[IncidentRecord]:
        if tenant_id:
            return [inc for inc in self._incidents_map.values() if inc.tenant_id == tenant_id]
        return list(self._incidents_map.values())

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        return self._incidents_map.get(incident_id)

    def get_attack_graph(self, incident_id: str) -> AttackGraphData:
        inc = self.get_incident(incident_id)
        if inc and inc.graph_context:
            return AttackGraphData(**inc.graph_context)
        return self.graph_repo.to_graph_json()

    # --- Simulation Methods (Dev & Demo Only) ---

    def simulate_email(self, tenant_id: str, raw_eml: bytes) -> IncidentRecord:
        """Simulates ingestion of a crafted EML and executes full investigation pipeline."""
        return self.run_investigation(tenant_id, raw_eml)

    def simulate_identity_event(self, tenant_id: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates an anomalous authentication/login event (e.g. NTLM hash relay)."""
        event_id = f"evt-{uuid.uuid4().hex[:8]}"
        record = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "event_type": event_data.get("event_type", "ANOMALOUS_NTLM_AUTHENTICATION"),
            "user_id": event_data.get("user_id", "cfo@enterprise-corp.internal"),
            "source_ip": event_data.get("source_ip", "198.51.100.42"),
            "target_service": event_data.get("target_service", "OWA / ActiveDirectory"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "LOGGED"
        }
        self._simulated_identity_events.append(record)
        return record

    def simulate_session(self, tenant_id: str, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates an active user webmail session."""
        session_id = session_data.get("session_id", f"sess-{uuid.uuid4().hex[:8]}")
        record = {
            "session_id": session_id,
            "tenant_id": tenant_id,
            "user_id": session_data.get("user_id", "cfo@enterprise-corp.internal"),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "ACTIVE",
            "client_type": "OWA_WEB_CLIENT"
        }
        self._simulated_sessions.append(record)
        return record

    def simulate_asset(self, tenant_id: str, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates an exposed email asset."""
        asset_id = asset_data.get("asset_id", f"asset-{uuid.uuid4().hex[:8]}")
        record = {
            "asset_id": asset_id,
            "tenant_id": tenant_id,
            "host": asset_data.get("host", "owa.enterprise-corp.internal"),
            "product": asset_data.get("product", "Microsoft Exchange / Outlook Web Access (OWA)"),
            "version": asset_data.get("version", "15.1.2507.17"),
            "is_internet_facing": True
        }
        self._simulated_assets.append(record)
        return record
