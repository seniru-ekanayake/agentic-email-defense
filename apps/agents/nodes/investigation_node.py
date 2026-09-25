"""
Agent Node 5: Investigation & Attack Chain Reconstruction Node.
Synthesizes telemetry, correlates attack path, calculates multi-dimensional risk scores,
and generates analyst-readable incident narrative with MITRE ATT&CK mapping.
"""

import logging
from typing import Dict, Any, List

from packages.schemas.python.models import (
    SecurityState,
    InteractionRequirement,
    EmailExploitabilityAssessment,
    EmailAttackRepresentation
)
from packages.attack_surface.src.scoring_engine import AttackSurfaceScoringEngine
from packages.attack_surface.src.models import EmailAsset
from packages.attack_surface.src.campaign_dedup import CampaignAggregator
from packages.threat_intel.src.mitre_attack import MitreAttackIngestor
from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository

logger = logging.getLogger("InvestigationNode")


class InvestigationNode:
    def __init__(self, graph_repo=None, campaign_aggregator=None):
        self.scoring_engine = AttackSurfaceScoringEngine()
        self.mitre_ingestor = MitreAttackIngestor()
        self.graph_repo = graph_repo or InMemoryAttackGraphRepository()
        self.campaign_aggregator = campaign_aggregator or CampaignAggregator.get_instance()

    def execute(self, state: SecurityState) -> SecurityState:
        logger.info("InvestigationNode executing...")

        email_dict = state.get("email_representation", {})
        assets_list = state.get("asset_context", [])
        vuln_list = state.get("vulnerability_context", [])

        # 1. Calculate Multi-Dimensional Scores
        asset_obj = EmailAsset(**assets_list[0]) if assets_list else EmailAsset(
            asset_id="asset-default", tenant_id=state.get("tenant_id", "tenant-1"),
            domain="enterprise-corp.internal", host="mail.enterprise-corp.internal"
        )
        
        assessment_obj = EmailExploitabilityAssessment(**vuln_list[0]) if vuln_list else None
        email_rep_obj = EmailAttackRepresentation(**email_dict) if email_dict else None

        scores_obj = self.scoring_engine.score(
            asset=asset_obj,
            assessment=assessment_obj,
            email_rep=email_rep_obj,
            observed_auth_anomaly=True
        )
        state["scores"] = scores_obj.model_dump()
        state["confidence"] = scores_obj.compromise_confidence

        # 2. Campaign Rollup & Deduplication
        campaign_context = {}
        if email_rep_obj:
            camp_cluster, is_new_camp = self.campaign_aggregator.register_email(
                ear=email_rep_obj,
                risk_score=scores_obj.overall_risk_score,
                severity=scores_obj.severity
            )
            campaign_context = {
                "campaign_id": camp_cluster.campaign_id,
                "is_new_campaign": is_new_camp,
                "total_emails_in_campaign": camp_cluster.total_email_count,
                "unique_recipients_count": len(camp_cluster.recipients_targeted),
                "is_campaign_outbreak": camp_cluster.total_email_count >= 5,
                "target_cve": camp_cluster.target_cve,
            }
            state["campaign_context"] = campaign_context

        # 3. Map Observed Activity to MITRE ATT&CK
        observed_indicators = []
        for ev in state.get("evidence", []):
            if "detail" in ev:
                observed_indicators.append(ev["detail"])
        mitre_techs = self.mitre_ingestor.map_indicators_to_mitre(observed_indicators)

        # 4. Identify Target and Vulnerability
        cve_id = vuln_list[0]["cve"] if vuln_list else "Unknown CVE"
        target_email = email_dict.get("recipients", [{}])[0].get("address", "victim@corp")
        sender_domain = email_dict.get("sender", {}).get("domain", "corporate-updates.net")
        camp_name = campaign_context.get("campaign_id", f"Campaign-{sender_domain}")

        # 5. Build & Upsert Attack Graph
        graph_data = self.graph_repo.upsert_observation(
            email_id=email_dict.get("message_id", "msg-unknown"),
            sender_domain=sender_domain,
            recipient_email=target_email,
            target_asset_host=asset_obj.host,
            cve_id=cve_id if cve_id != "Unknown CVE" else None,
            session_id="active-owa-session",
            campaign_name=camp_name,
            threat_actor="Storm-0978"
        )
        state["graph_context"] = graph_data.model_dump()

        # 6. Reconstruct Probable Attack Chain
        attack_chain = [
            {"stage": "INITIAL_ACCESS", "technique": "T1566 Phishing", "description": f"Attacker delivers crafted email from spoofed sender: {email_dict.get('sender', {}).get('address')}"},
            {"stage": "EMAIL_DELIVERY", "technique": "SMTP Transport", "description": "Email bypasses perimeter filters and lands in victim mailbox."},
            {"stage": "RENDERING_PARSING", "technique": "URI Moniker Parsing", "description": f"Victim previews email in mail client, triggering {cve_id} parser vulnerability."},
            {"stage": "EXPLOITATION", "technique": "T1187 Forced Authentication", "description": "Client automatically attempts outbound SMB/WebDAV authentication leaking NTLM hash."},
            {"stage": "SESSION_IDENTITY", "technique": "Credential Access", "description": f"Identity {target_email} credentials targeted for relay/hijacking."},
            {"stage": "POST_EXPLOITATION", "technique": "T1114 Email Collection", "description": "Potential unauthorized mailbox access and persistent rule creation."}
        ]

        # 7. Generate Incident Report
        incident_report = {
            "title": f"Critical Exploitation Attempt via Email Rendering ({cve_id})",
            "severity": scores_obj.severity,
            "overall_risk_score": scores_obj.overall_risk_score,
            "confidence": scores_obj.compromise_confidence,
            "target_identity": target_email,
            "mail_platform": asset_obj.product,
            "exposure_status": "Internet-Facing",
            "interaction_required": "VIEW",
            "cve": cve_id,
            "campaign": campaign_context,
            "attack_chain": attack_chain,
            "mitre_techniques": [t.model_dump() for t in mitre_techs],
            "evidence_summary": [e.get("detail") or e.get("summary") for e in state.get("evidence", []) if e.get("detail") or e.get("summary")]
        }

        state["incident_report"] = incident_report
        logger.info(f"InvestigationNode completed. Generated incident report with severity: {scores_obj.severity} [Campaign: {camp_name}]")
        return state
