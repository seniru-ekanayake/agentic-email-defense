import pytest
import os
import sys
import time
import threading
import json
import uvicorn
from fastapi.testclient import TestClient
import requests

sys.path.insert(0, r"c:\Enterprise Agentic Email Exploitation Detection & Response Platform")

# Setup for testing
os.environ["FISHINGMAILS_ENV"] = "test"
os.environ["FISHINGMAILS_AUTH_SECRET"] = "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"
os.environ["FISHINGMAILS_APPROVAL_HMAC_SECRET"] = "test-hmac-secret-key-that-is-long-enough"

from apps.server import app
from apps.agents.core.security_principal import create_principal_token
from apps.agents.core.approval_manager import ApprovalManager

client = TestClient(app)

def get_token(roles):
    return create_principal_token(
        subject_id="test_user",
        tenant_id="tenant-enterprise-prod",
        roles=roles
    )

def test_A_approval_auth_bypass():
    analyst_token = get_token(["SOC_ANALYST"])
    
    am = ApprovalManager.get_instance()
    valid_token = am.create_pending_approval("tenant-enterprise-prod", "CisaKevCorrelator", {})
    parts = valid_token.split("-")
    
    res = client.post("/api/v1/approve/MALFORMED_TOKEN", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 400
    
    forged_token = f"APP-{parts[1]}-00000000"
    res = client.post(f"/api/v1/approve/{forged_token}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 400
    assert "Invalid or unknown approval token" in res.text
    
    wrong_tenant_jwt = create_principal_token("user", "tenant-evil", ["SOC_ANALYST"])
    res = client.post(f"/api/v1/approve/{valid_token}", headers={"Authorization": f"Bearer {wrong_tenant_jwt}"})
    assert res.status_code == 403
    assert "Tenant mismatch" in res.text
    
    # Valid execution
    res = client.post(f"/api/v1/approve/{valid_token}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200, res.text
    
    # Already consumed
    res = client.post(f"/api/v1/approve/{valid_token}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 400

def test_B_approval_race_toctou():
    analyst_token = get_token(["SOC_ANALYST"])
    am = ApprovalManager.get_instance()
    valid_token = am.create_pending_approval("tenant-enterprise-prod", "CisaKevCorrelator", {})
    
    results = []
    
    def fire():
        res = client.post(f"/api/v1/approve/{valid_token}", headers={"Authorization": f"Bearer {analyst_token}"})
        results.append(res.status_code)
        
    threads = []
    for _ in range(50):
        t = threading.Thread(target=fire)
        threads.append(t)
    
    for t in threads: t.start()
    for t in threads: t.join()
    
    success_count = results.count(200)
    fail_count = results.count(400)
    
    assert success_count == 1, f"Expected exactly 1 success, got {success_count} (results: {results})"
    assert fail_count == 49, f"Expected exactly 49 failures, got {fail_count} (results: {results})"
import pytest
import os
import sys
import time
import threading
import json
from fastapi.testclient import TestClient

sys.path.insert(0, r"c:\Enterprise Agentic Email Exploitation Detection & Response Platform")

# Setup for testing
os.environ["FISHINGMAILS_ENV"] = "test"
os.environ["FISHINGMAILS_AUTH_SECRET"] = "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"

from apps.agents.core.tool_registry import ToolRegistry

def test_H_cisa_kev_correlator_dynamic():
    """Verify CisaKevCorrelator genuinely derives results from the dataset."""
    tr = ToolRegistry.get_instance()
    
    # 1. Known KEV entry -> positive
    res1 = tr._cisa_kev_handler({"cve_id": "CVE-2023-35636"})
    assert res1["is_in_kev"] is True
    assert res1["status"] == "VERIFIED"
    assert res1["provenance"]["catalog_version"] == "2024.01.15"
    
    # 2. Random non-KEV IOC -> negative
    res2 = tr._cisa_kev_handler({"cve_id": "CVE-9999-99999"})
    assert res2["is_in_kev"] is False
    assert res2["status"] == "UNKNOWN"
    
    # 3. Modify dataset and verify result changes
    dataset_path = res1["provenance"]["dataset_path"]
    
    # Read original
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Add fake CVE
    data["vulnerabilities"].append({
        "cveID": "CVE-FAKE-123",
        "vendorProject": "Test",
        "product": "Test",
        "vulnerabilityName": "Fake",
        "dateAdded": "2024-01-01",
        "shortDescription": "Fake",
        "requiredAction": "Fake",
        "dueDate": "2024-01-01"
    })
    data["catalogVersion"] = "9999.99.99"
    
    # Write modified
    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
        
    try:
        # Test new fake CVE
        res3 = tr._cisa_kev_handler({"cve_id": "CVE-FAKE-123"})
        assert res3["is_in_kev"] is True
        assert res3["provenance"]["catalog_version"] == "9999.99.99"
    finally:
        # Restore original
        data["vulnerabilities"].pop()
        data["catalogVersion"] = "2024.01.15"
        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

def test_C_sandbox_ssrf_redirect():
    """Verify SSRF redirect tracing with a local HTTP server."""
    import http.server
    import socketserver
    
    class RedirectHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:80")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
                
    # Start server
    httpd = socketserver.TCPServer(("127.0.0.1", 0), RedirectHandler)
    port = httpd.server_address[1]
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    try:
        from apps.sandbox.src.url_sandbox import UrlSandboxRunner
        runner = UrlSandboxRunner()
        url = f"http://127.0.0.1:{port}/"
        
        # We need to monkey-patch NetworkGuard to allow the initial request to the local test server
        # but block the redirect to 127.0.0.1:80
        original_evaluate = runner.network_guard.evaluate_destination
        
        def mock_evaluate(target_url):
            if f":{port}/" in target_url:
                return True, "Allowed", False
            return original_evaluate(target_url)
            
        runner.network_guard.evaluate_destination = mock_evaluate
        
        report = runner.analyze_url(url)
        assert report.network_guard_blocked is True
        assert report.verdict == "BLOCKED_SSRF"
        assert "NetworkGuard blocked dynamic redirect hop 'http://127.0.0.1:80'" in str(report.evidence)
        
    finally:
        httpd.shutdown()
        httpd.server_close()
