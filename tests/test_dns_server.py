import pytest
from apps.agents.core.mcp_servers.dns_server import handle_spf_dmarc_audit, handle_dns_resolve


@pytest.mark.network
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

