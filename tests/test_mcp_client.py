import asyncio
import pytest
from apps.agents.core.mcp_client import MCPManager, MCPProcessServer
from apps.agents.core.mcp_servers.dns_server import handle_spf_dmarc_audit, handle_dns_resolve
from apps.agents.core.mcp_servers.telemetry_server import handle_query_sender_history, handle_record_interaction


@pytest.mark.asyncio
async def test_mcp_manager_discovery_and_tools():
    manager = MCPManager.get_instance()
    tools_by_server = await manager.list_all_tools()
    
    assert "dns_recon" in tools_by_server
    assert "telemetry" in tools_by_server
    
    dns_tool_names = [t["name"] for t in tools_by_server["dns_recon"]]
    assert "dns_resolve" in dns_tool_names
    assert "spf_dmarc_audit" in dns_tool_names
    assert "dkim_selector_check" in dns_tool_names

    telemetry_tool_names = [t["name"] for t in tools_by_server["telemetry"]]
    assert "query_sender_history" in telemetry_tool_names
    assert "record_interaction" in telemetry_tool_names

    await manager.shutdown_all()


def test_dns_server_handlers():
    # Test SPF/DMARC audit handler
    audit_res = handle_spf_dmarc_audit({"domain": "google.com"})
    assert audit_res["domain"] == "google.com"
    assert "has_spf" in audit_res
    assert "has_dmarc" in audit_res

    # Test DNS resolve handler
    resolve_res = handle_dns_resolve({"domain": "google.com", "type": "A"})
    assert resolve_res["status"] == "resolved"
    assert len(resolve_res["records"]) > 0


def test_telemetry_server_handlers():
    # Test baseline query
    hist = handle_query_sender_history({
        "sender_email": "billing@trusted-vendor.com",
        "recipient_email": "finance@victim-corp.com"
    })
    assert hist["sender_domain"] == "trusted-vendor.com"
    assert hist["historical_email_count"] >= 1
    assert hist["is_first_time_sender"] is False

    # Test unknown sender anomaly
    unknown_hist = handle_query_sender_history({
        "sender_email": "attacker@evil-lookalike.xyz",
        "recipient_email": "finance@victim-corp.com"
    })
    assert unknown_hist["is_first_time_sender"] is True
    assert unknown_hist["baseline_reputation"] == "unknown_anomaly"

    # Test recording interaction
    rec = handle_record_interaction({
        "sender_email": "new-user@partner.org",
        "recipient_email": "user@victim-corp.com",
        "auth_status": "PASS"
    })
    assert rec["status"] == "recorded"
