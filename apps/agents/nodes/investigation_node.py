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
        cve_id = vuln_list[0]["cve"] if vuln_list and vuln_list[0].get("cve") else None
        target_email = email_dict.get("recipients", [{}])[0].get("address", "victim@corp")
        sender_addr = email_dict.get("sender", {}).get("address", "unknown@mail")
        sender_domain = email_dict.get("sender", {}).get("domain", "mail.net")
        camp_name = campaign_context.get("campaign_id", f"Campaign-{sender_domain}")
        evidence_items = state.get("evidence", [])

        # Check observed indicators
        auth_failed = any("SPF/DMARC failure" in str(e) or "Sender Spoofing" in str(e) for e in evidence_items)
        has_rtlo = any("RTLO" in str(e) or "UNICODE_RTLO" in str(e) for e in evidence_items)
        has_zero_width = any("ZERO_WIDTH" in str(e) or "zero-width" in str(e) for e in evidence_items)
        has_homoglyphs = any("HOMOGLYPH" in str(e) or "homoglyph" in str(e) for e in evidence_items)
        has_rendering_exploit = any("RENDERING_EXPLOIT" in str(e) or "search-ms" in str(e) or "file:" in str(e) for e in evidence_items)
        has_forced_callout = any("FORCED_CALLOUT" in str(e) or "Forced UNC/SMB" in str(e) for e in evidence_items)
        has_deceptive_url = any("Deceptive link" in str(e) or "Deceptive URL" in str(e) for e in evidence_items)
        has_test_domain = any(".invalid" in str(u.get("url", "")) or ".example" in str(u.get("url", "")) or u.get("reputation") == "inert_test_domain" for u in email_dict.get("urls", []))
        has_active_scripts = any("ACTIVE_SCRIPTING" in str(e) or "<script>" in str(e) for e in evidence_items)

        # 5. Build & Upsert Attack Graph
        threat_actor_attribution = "Storm-0978" if has_rendering_exploit and cve_id else None
        graph_data = self.graph_repo.upsert_observation(
            email_id=email_dict.get("message_id", "msg-unknown"),
            sender_domain=sender_domain,
            recipient_email=target_email,
            target_asset_host=asset_obj.host,
            cve_id=cve_id,
            session_id="active-owa-session" if has_forced_callout else None,
            campaign_name=camp_name,
            threat_actor=threat_actor_attribution or "Unattributed Inbound Delivery"
        )
        state["graph_context"] = graph_data.model_dump()

        # 6. Reconstruct Evidence-Grounded Attack Chain
        attack_chain = []
        
        # Step 1: Ingestion & Delivery
        if auth_failed:
            attack_chain.append({
                "stage": "INITIAL_ACCESS",
                "technique": "T1566 Phishing",
                "description": f"Inbound message from {sender_addr} failed SPF/DMARC sender verification."
            })
        else:
            attack_chain.append({
                "stage": "INITIAL_ACCESS",
                "technique": "T1566 Phishing",
                "description": f"Inbound message delivered from {sender_addr}."
            })

        attack_chain.append({
            "stage": "EMAIL_DELIVERY",
            "technique": "SMTP Transport",
            "description": f"Email delivered to target mailbox {target_email} on {asset_obj.product}."
        })

        # Step 2: Obfuscation / Evasion (if observed)
        if has_rtlo or has_zero_width or has_homoglyphs:
            obf_types = []
            if has_rtlo: obf_types.append("Right-to-Left Override (RTLO)")
            if has_zero_width: obf_types.append("Zero-Width Characters")
            if has_homoglyphs: obf_types.append("Mixed-Script Homoglyphs")
            attack_chain.append({
                "stage": "DEFENSE_EVASION",
                "technique": "T1027 Obfuscated Files or Information",
                "description": f"Sender utilized Unicode obfuscation ({', '.join(obf_types)}) to conceal intent."
            })

        # Step 3: Exploitation / Moniker / Forced Callout (if observed)
        if has_rendering_exploit or cve_id:
            cve_label = cve_id or "Moniker Link Parser Exploit"
            attack_chain.append({
                "stage": "RENDERING_PARSING",
                "technique": "CVE Exploitation",
                "description": f"Client rendering triggers {cve_label} parser vulnerability."
            })
        
        if has_forced_callout:
            attack_chain.append({
                "stage": "EXPLOITATION",
                "technique": "T1187 Forced Authentication",
                "description": "Client forced to attempt outbound SMB/WebDAV NTLM authentication."
            })
            attack_chain.append({
                "stage": "SESSION_IDENTITY",
                "technique": "Credential Access",
                "description": f"Target {target_email} NTLM credentials exposed to remote host."
            })
            attack_chain.append({
                "stage": "POST_EXPLOITATION",
                "technique": "T1114 Email Collection / Lateral Relay",
                "description": "Potential unauthorized session relay and persistent mailbox access."
            })


        # Step 4: URL / Phishing link (if observed)
        if has_deceptive_url:
            attack_chain.append({
                "stage": "CREDENTIAL_ACCESS",
                "technique": "T1204.001 User Execution: Malicious Link",
                "description": "Email contains deceptive link targeting credential harvesting infrastructure."
            })
        elif has_test_domain:
            attack_chain.append({
                "stage": "TEST_FIXTURE",
                "technique": "RFC 2606 Reserved Domain",
                "description": "Email contains inert test destination domain (.invalid per RFC 2606)."
            })

        if has_active_scripts:
            attack_chain.append({
                "stage": "EXECUTION",
                "technique": "T1059 Command and Scripting Interpreter",
                "description": "Embedded active script detected in email body."
            })

        # 7. Generate Precise Incident Title & Severity
        if has_rendering_exploit and cve_id:
            title = f"Critical Exploitation Attempt via Email Rendering ({cve_id})"
        elif has_rendering_exploit:
            title = "Zero-Click Moniker Link Exploitation Attempt"
        elif has_deceptive_url:
            title = "Deceptive Phishing Link Detected"
        elif has_rtlo or has_homoglyphs:
            title = "Suspicious Email with Unicode Obfuscation"
        elif has_test_domain:
            title = "Inbound Test Payload (RFC 2606 .invalid Domain)"
        elif auth_failed:
            title = "Unverified Inbound Email (SPF/DMARC Failure)"
        else:
            title = "Inbound Email Activity - Low Risk"

        # Evidence Summary list
        evidence_summary_list = []
        for e in evidence_items:
            det = e.get("detail") or e.get("summary") or e.get("evidence")
            if det and det not in evidence_summary_list:
                evidence_summary_list.append(det)

        if not evidence_summary_list:
            evidence_summary_list.append("Email processed through deterministic parser. No high-risk exploits detected.")

        incident_report = {
            "title": title,
            "severity": scores_obj.severity,
            "overall_risk_score": scores_obj.overall_risk_score,
            "confidence": scores_obj.compromise_confidence,
            "target_identity": target_email,
            "mail_platform": asset_obj.product,
            "exposure_status": "Internet-Facing",
            "interaction_required": "VIEW" if (has_rendering_exploit or cve_id) else ("CLICK" if has_deceptive_url else "NONE"),
            "cve": cve_id,
            "campaign": campaign_context,
            "attack_chain": attack_chain,
            "mitre_techniques": [t.model_dump() for t in mitre_techs],
            "evidence_summary": evidence_summary_list
        }

        state["incident_report"] = incident_report
        logger.info(f"InvestigationNode completed. Generated incident report with severity: {scores_obj.severity} [Campaign: {camp_name}]")
        return state

