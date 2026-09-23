import pytest
from packages.threat_intel.src.free_feeds import (
    ThreatIntelCache,
    URLhausConnector,
    AbuseIPDBConnector,
    DoHReputationConnector,
    FreeThreatIntelEngine,
)


def test_threat_intel_cache():
    cache = ThreatIntelCache(default_ttl_seconds=10)
    cache.set("key1", {"status": "ok"})
    
    assert cache.get("key1") == {"status": "ok"}
    assert cache.get("non_existent") is None
    
    cache.clear()
    assert cache.get("key1") is None


def test_urlhaus_connector_network_guard():
    connector = URLhausConnector()
    # RFC1918 / localhost destination should be blocked by NetworkGuard
    res = connector.query_url("http://127.0.0.1:8080/payload.exe")
    assert res["query_status"] == "blocked_by_network_guard"
    assert res["is_malicious"] is False


def test_abuseipdb_internal_filtering():
    connector = AbuseIPDBConnector()
    # Internal IP should be recognized and flagged without external API leak
    res = connector.check_ip("192.168.1.50")
    assert res["is_internal_or_restricted"] is True
    assert res["is_malicious"] is False

    # External IP check in free tier
    ext_res = connector.check_ip("8.8.8.8")
    assert ext_res["is_internal_or_restricted"] is False
    assert ext_res["ipAddress"] == "8.8.8.8"


def test_doh_reputation_connector():
    doh = DoHReputationConnector()
    res = doh.check_domain_reputation("google.com")
    assert res["domain"] == "google.com"
    assert res["doh_provider"] == "quad9"
    assert "is_blocked_by_threat_filter" in res


def test_unified_free_threat_intel_engine():
    engine = FreeThreatIntelEngine()
    
    url_res = engine.assess_indicator("url", "http://10.0.0.1/malicious.doc")
    assert url_res["type"] == "url"
    assert url_res["urlhaus"]["query_status"] == "blocked_by_network_guard"

    ip_res = engine.assess_indicator("ip", "10.10.10.10")
    assert ip_res["type"] == "ip"
    assert ip_res["abuseipdb"]["is_internal_or_restricted"] is True
