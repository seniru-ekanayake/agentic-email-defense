"""Enterprise SIEM & SOAR Outbound Forwarders.

Formats incident reports and threat telemetry into industry-standard schemas:
- CEF (Common Event Format - ArcSight / QRadar / LogRhythm)
- RFC 5424 Syslog (Enterprise SIEM Log Ingestion)
- Splunk HTTP Event Collector (HEC) JSON
- Microsoft Sentinel Log Analytics Custom Tables
"""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("threat_intel.siem")


class SIEMForwarder:
    """Formats incident representations into enterprise SIEM/SOAR data formats."""

    SEVERITY_MAP_CEF = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFORMATIONAL": 1,
    }

    SEVERITY_MAP_SYSLOG = {
        "CRITICAL": 2,  # Critical
        "HIGH": 3,      # Error
        "MEDIUM": 4,    # Warning
        "LOW": 5,       # Notice
        "INFORMATIONAL": 6,  # Informational
    }

    @classmethod
    def to_cef(cls, incident: Dict[str, Any], device_vendor: str = "AgenticDefense", device_product: str = "EmailExploitPlatform", device_version: str = "1.0") -> str:
        """Format incident into standard ArcSight Common Event Format (CEF)."""
        title = incident.get("title", "Email Exploitation Incident")
        severity_str = incident.get("severity", "HIGH").upper()
        severity_num = cls.SEVERITY_MAP_CEF.get(severity_str, 7)
        sig_id = incident.get("cve") or "EMAIL-EXPLOIT"

        # Extract extension attributes
        target_identity = incident.get("target_identity", "")
        risk_score = incident.get("overall_risk_score", 0.0)
        interaction_req = incident.get("interaction_required", "NONE")
        mail_platform = incident.get("mail_platform", "Exchange")
        campaign_info = incident.get("campaign", {})
        campaign_id = campaign_info.get("campaign_id", "SINGLE_ALERT") if isinstance(campaign_info, dict) else "SINGLE_ALERT"

        ext_parts = [
            f"dst={target_identity}",
            f"cn1={risk_score}",
            f"cn1Label=RiskScore",
            f"cs1={sig_id}",
            f"cs1Label=TargetCVE",
            f"cs2={interaction_req}",
            f"cs2Label=InteractionRequired",
            f"cs3={mail_platform}",
            f"cs3Label=MailPlatform",
            f"cs4={campaign_id}",
            f"cs4Label=CampaignId",
            f"msg={title}"
        ]

        cef_ext = " ".join(ext_parts)
        return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{sig_id}|{title}|{severity_num}|{cef_ext}"

    @classmethod
    def to_syslog_rfc5424(cls, incident: Dict[str, Any], hostname: str = "agentic-defense-engine") -> str:
        """Format incident into structured RFC 5424 Syslog message."""
        severity_str = incident.get("severity", "HIGH").upper()
        prival = 16 * 8 + cls.SEVERITY_MAP_SYSLOG.get(severity_str, 4)  # Facility local0 (16) + severity
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        title = incident.get("title", "Email Exploit Incident")
        cve = incident.get("cve", "NONE")
        score = incident.get("overall_risk_score", 0.0)

        structured_data = f'[incident@41058 severity="{severity_str}" cve="{cve}" score="{score}"]'
        return f"<{prival}>1 {timestamp} {hostname} agentic-defense - - {structured_data} {title}"

    @classmethod
    def to_splunk_hec_json(cls, incident: Dict[str, Any], sourcetype: str = "agentic:email:incident") -> Dict[str, Any]:
        """Format incident for Splunk HTTP Event Collector (HEC)."""
        return {
            "time": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "host": "agentic-defense-gateway",
            "source": "email_exploitation_engine",
            "sourcetype": sourcetype,
            "event": incident
        }

    @classmethod
    def to_sentinel_log_analytics(cls, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Format incident for Microsoft Sentinel Log Analytics custom log ingestion."""
        camp = incident.get("campaign", {})
        camp_id = camp.get("campaign_id") if isinstance(camp, dict) else None

        return {
            "TimeGenerated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "IncidentTitle": incident.get("title"),
            "Severity": incident.get("severity"),
            "OverallRiskScore": incident.get("overall_risk_score"),
            "TargetIdentity": incident.get("target_identity"),
            "TargetCVE": incident.get("cve"),
            "MailPlatform": incident.get("mail_platform"),
            "InteractionRequirement": incident.get("interaction_required"),
            "CampaignId": camp_id,
            "MitreTechniques": [t.get("technique_id") for t in incident.get("mitre_techniques", []) if isinstance(t, dict) and "technique_id" in t],
            "EvidenceCount": len(incident.get("evidence_summary", []))
        }
