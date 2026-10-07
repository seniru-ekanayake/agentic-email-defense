"""
Agent Node: Report & attack-chain reconstruction.
Builds the incident report from the computed verdict and the typed evidence in the
InvestigationState. Attack-chain stages are only emitted for evidence that was observed.
"""

import logging
from typing import Any, Dict, List

from packages.schemas.python.models import SecurityState, EmailAttackRepresentation
from packages.attack_surface.src.campaign_dedup import CampaignAggregator
from packages.threat_intel.src.mitre_attack import MitreAttackIngestor
from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository

logger = logging.getLogger("InvestigationNode")


class InvestigationNode:
    def __init__(self, graph_repo=None, campaign_aggregator=None):
        self.mitre_ingestor = MitreAttackIngestor()
        self.graph_repo = graph_repo or InMemoryAttackGraphRepository()
        self.campaign_aggregator = campaign_aggregator or CampaignAggregator.get_instance()

    def execute(self, state: SecurityState) -> SecurityState:
        email_dict = state.get("email_representation", {}) or {}
        verdict = state["verdict"]
        inv = state["investigation_state"]
        types = {e.evidence_type for e in inv.evidence.values()}

        sender = (email_dict.get("sender") or {})
        sender_addr = sender.get("address") or "unknown"
        sender_domain = sender.get("domain") or "unknown"
        target = ((email_dict.get("recipients") or [{}])[0].get("address")) or "unknown"

        state["scores"] = {"overall_risk_score": verdict.risk_score, "severity": verdict.severity}
        state["confidence"] = verdict.confidence

        campaign_context: Dict[str, Any] = {}
        try:
            rep = EmailAttackRepresentation(**email_dict)
            cluster, is_new = self.campaign_aggregator.register_email(ear=rep, risk_score=verdict.risk_score, severity=verdict.severity)
            campaign_context = {
                "campaign_id": cluster.campaign_id,
                "is_new_campaign": is_new,
                "total_emails_in_campaign": cluster.total_email_count,
                "unique_recipients_count": len(cluster.recipients_targeted),
                "is_campaign_outbreak": cluster.total_email_count >= 5,
                "target_cve": verdict.cve,
            }
        except Exception as exc:
            logger.warning(f"Campaign aggregation skipped: {exc}")
        state["campaign_context"] = campaign_context

        observed_details = [e.value for e in inv.evidence.values()
                            if e.evidence_type in ("MONIKER_URI", "UNC_PATH", "UNICODE_ANOMALY", "DECEPTIVE_LINK", "ACTIVE_SCRIPT",
                                                   "ATTACHMENT_ANALYSIS", "ATTACHMENT_PE", "AUTHENTICATION")]
        mitre = self.mitre_ingestor.map_indicators_to_mitre(observed_details) if verdict.verdict != "BENIGN" else []

        if verdict.verdict != "BENIGN":
            graph_data = self.graph_repo.upsert_observation(
                email_id=email_dict.get("message_id", "msg-unknown"),
                sender_domain=sender_domain,
                recipient_email=target,
                target_asset_host=target.split("@")[-1],
                cve_id=verdict.cve,
                session_id=None,
                campaign_name=campaign_context.get("campaign_id", f"Campaign-{sender_domain}"),
                threat_actor="Unattributed",
            )
            state["graph_context"] = graph_data.model_dump()

        auth = next((e for e in inv.evidence.values() if e.evidence_type == "AUTHENTICATION"), None)
        auth_result = auth.metadata.get("result") if auth else "UNKNOWN"
        chain: List[Dict[str, str]] = [{
            "stage": "DELIVERY",
            "technique": "SMTP delivery",
            "description": f"Message from {sender_addr} to {target} (sender authentication: {auth_result}).",
        }]
        if verdict.verdict != "BENIGN":
            if "UNICODE_ANOMALY" in types:
                chain.append({"stage": "DEFENSE_EVASION", "technique": "T1027 Obfuscated Files or Information",
                              "description": "Hidden/bidirectional Unicode characters present in the message."})
            if "MONIKER_URI" in types or "UNC_PATH" in types:
                chain.append({"stage": "CREDENTIAL_ACCESS", "technique": "T1187 Forced Authentication",
                              "description": "Message references a moniker or UNC destination that can make the client authenticate to a remote host."})
            if "DECEPTIVE_LINK" in types or any(f.component == "Threat-intel reputation" for f in verdict.factors):
                chain.append({"stage": "INITIAL_ACCESS", "technique": "T1566.002 Spearphishing Link",
                              "description": "Message contains a deceptive or known-malicious link."})
            if any(f.component.startswith(("Attachment", "Mark-of")) for f in verdict.factors):
                chain.append({"stage": "INITIAL_ACCESS", "technique": "T1566.001 Spearphishing Attachment",
                              "description": "Message carries a high-risk attachment."})
            if "ACTIVE_SCRIPT" in types:
                chain.append({"stage": "EXECUTION", "technique": "T1059 Command and Scripting Interpreter",
                              "description": "Script content embedded in the message body."})

        state["incident_report"] = {
            "title": verdict.title,
            "severity": verdict.severity,
            "overall_risk_score": verdict.risk_score,
            "confidence": verdict.confidence,
            "target_identity": target,
            "mail_platform": (state.get("asset_context") or [{}])[0].get("product", "Unknown") if state.get("asset_context") else "Unknown",
            "exposure_status": "Unknown",
            "interaction_required": verdict.interaction_required,
            "cve": verdict.cve,
            "campaign": campaign_context,
            "attack_chain": chain,
            "mitre_techniques": [t.model_dump() for t in mitre],
            "evidence_summary": [f"{f.component}: {f.reason} [{f.evidence_id}]" for f in verdict.factors]
                                or ["No malicious indicators observed."],
        }
        return state
