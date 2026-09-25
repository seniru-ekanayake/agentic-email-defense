import pytest
from packages.threat_intel.src.siem_forwarder import SIEMForwarder


@pytest.fixture
def sample_incident():
    return {
        "title": "Critical Exploitation Attempt via Email Rendering (CVE-2024-21413)",
        "severity": "CRITICAL",
        "overall_risk_score": 92.5,
        "target_identity": "cfo@victim-corp.com",
        "mail_platform": "Exchange OWA",
        "interaction_required": "VIEW",
        "cve": "CVE-2024-21413",
        "campaign": {
            "campaign_id": "CAMP-E84F10AA",
            "total_emails_in_campaign": 45
        },
        "mitre_techniques": [
            {"technique_id": "T1566", "name": "Phishing"},
            {"technique_id": "T1187", "name": "Forced Authentication"}
        ],
        "evidence_summary": ["Moniker link search-ms: detected", "Forced UNC SMB callout"]
    }


def test_siem_forwarder_to_cef(sample_incident):
    cef_str = SIEMForwarder.to_cef(sample_incident)
    
    assert cef_str.startswith("CEF:0|AgenticDefense|EmailExploitPlatform|1.0|CVE-2024-21413|")
    assert "|10|" in cef_str  # CRITICAL maps to severity 10
    assert "dst=cfo@victim-corp.com" in cef_str
    assert "cn1=92.5" in cef_str
    assert "cs1=CVE-2024-21413" in cef_str
    assert "cs4=CAMP-E84F10AA" in cef_str


def test_siem_forwarder_to_syslog_rfc5424(sample_incident):
    syslog_msg = SIEMForwarder.to_syslog_rfc5424(sample_incident, hostname="soc-gateway-01")
    
    assert syslog_msg.startswith("<130>1 ")  # local0 (128) + 2 (Critical) = 130
    assert "soc-gateway-01 agentic-defense" in syslog_msg
    assert 'severity="CRITICAL"' in syslog_msg
    assert 'cve="CVE-2024-21413"' in syslog_msg


def test_siem_forwarder_to_splunk_hec(sample_incident):
    hec_payload = SIEMForwarder.to_splunk_hec_json(sample_incident)
    
    assert "time" in hec_payload
    assert hec_payload["host"] == "agentic-defense-gateway"
    assert hec_payload["sourcetype"] == "agentic:email:incident"
    assert hec_payload["event"]["target_identity"] == "cfo@victim-corp.com"
    assert hec_payload["event"]["overall_risk_score"] == 92.5


def test_siem_forwarder_to_sentinel(sample_incident):
    sentinel_payload = SIEMForwarder.to_sentinel_log_analytics(sample_incident)
    
    assert sentinel_payload["IncidentTitle"] == "Critical Exploitation Attempt via Email Rendering (CVE-2024-21413)"
    assert sentinel_payload["Severity"] == "CRITICAL"
    assert sentinel_payload["TargetIdentity"] == "cfo@victim-corp.com"
    assert sentinel_payload["CampaignId"] == "CAMP-E84F10AA"
    assert sentinel_payload["MitreTechniques"] == ["T1566", "T1187"]
    assert sentinel_payload["EvidenceCount"] == 2
