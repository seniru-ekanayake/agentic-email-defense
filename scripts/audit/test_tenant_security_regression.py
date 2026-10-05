"""
Tenant Security Regression Suite
Tests A - E covering tenant isolation, cross-tenant 403 enforcement, empty tenant returns [],
and detail isolation with cryptographically authenticated JWT identities.
"""
import os
import urllib.request
import urllib.error
import json
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

# Ensure production secret is set for token signing
SECRET_KEY = os.environ.get(
    "FISHINGMAILS_AUTH_SECRET",
    "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"
)
os.environ["FISHINGMAILS_AUTH_SECRET"] = SECRET_KEY

from apps.agents.core.security_principal import create_principal_token

BASE_URL = "http://127.0.0.1:8000"

def get_headers(token: str):
    return {"Authorization": f"Bearer {token}"}

def run_test(name, fn):
    try:
        fn()
        print(f"[PASS] {name}")
        return True
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        return False

def test_a_empty_tenant_list():
    # Test A: Unseen tenant with zero records returns [] (not fallback incidents_db)
    token = create_principal_token("empty_analyst_1", "tenant-empty-test-999")
    req = urllib.request.Request(f"{BASE_URL}/api/v1/incidents", headers=get_headers(token))
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert data == [], f"Expected empty list [], got {len(data)} items: {data}"

def test_b_empty_tenant_header():
    # Test B: Unseen tenant via matching header returns []
    token = create_principal_token("empty_analyst_2", "tenant-empty-header-888")
    headers = {**get_headers(token), "X-Tenant-ID": "tenant-empty-header-888"}
    req = urllib.request.Request(f"{BASE_URL}/api/v1/incidents", headers=headers)
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert data == [], f"Expected empty list [], got {len(data)} items"

def test_c_existing_tenant_isolation():
    # Test C: Retrieve incidents for primary tenant
    token = create_principal_token("analyst_alpha", "tenant-enterprise-prod")
    req = urllib.request.Request(f"{BASE_URL}/api/v1/incidents", headers=get_headers(token))
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert isinstance(data, list)
        for inc in data:
            assert inc.get("tenant_id") == "tenant-enterprise-prod", f"Cross-tenant record leaked: {inc.get('tenant_id')}"

def test_d_cross_tenant_detail_rejection():
    # Test D: Fetch incident belonging to tenant-enterprise-prod using a rogue tenant token
    token_prod = create_principal_token("analyst_alpha", "tenant-enterprise-prod")
    req = urllib.request.Request(f"{BASE_URL}/api/v1/incidents", headers=get_headers(token_prod))
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    
    if not data:
        print("  (Skipping Test D detail check since no records exist yet)")
        return

    target_id = data[0]["incident_id"]
    # Now attempt access with rogue tenant identity
    token_rogue = create_principal_token("adversary_user", "tenant-rogue-attacker")
    req_rogue = urllib.request.Request(
        f"{BASE_URL}/api/v1/incidents/{target_id}",
        headers=get_headers(token_rogue)
    )
    try:
        urllib.request.urlopen(req_rogue)
        assert False, "Expected 403 Forbidden on cross-tenant detail access, but request succeeded!"
    except urllib.error.HTTPError as he:
        assert he.code == 403, f"Expected 403 Forbidden, got {he.code}"

def test_e_agent_config_active():
    # Test E: Verify AgentConfig defaults to LLM_FIRST with authenticated principal
    token = create_principal_token("analyst_alpha", "tenant-enterprise-prod")
    req = urllib.request.Request(f"{BASE_URL}/api/v1/agent-config", headers=get_headers(token))
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert len(data) > 0, "No agent configs found"
        agent = data[0]
        assert agent.get("hybrid_arbitration_policy") == "LLM_FIRST", f"Policy is {agent.get('hybrid_arbitration_policy')}, expected LLM_FIRST"
        assert agent.get("max_llm_tokens") >= 16000, f"Token limit too low: {agent.get('max_llm_tokens')}"

if __name__ == "__main__":
    results = [
        run_test("Test A: Empty tenant returns []", test_a_empty_tenant_list),
        run_test("Test B: Empty tenant header returns []", test_b_empty_tenant_header),
        run_test("Test C: Existing tenant data isolation", test_c_existing_tenant_isolation),
        run_test("Test D: Cross-tenant detail 403 rejection", test_d_cross_tenant_detail_rejection),
        run_test("Test E: Agent config verification (LLM_FIRST)", test_e_agent_config_active),
    ]
    if all(results):
        print("\nALL TENANT SECURITY REGRESSION TESTS PASSED.")
        sys.exit(0)
    else:
        print("\nSOME TESTS FAILED.")
        sys.exit(1)
