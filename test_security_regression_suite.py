"""
Adversarial Security Regression & Release-Candidate Verification Suite
Tests:
1. Identity-bound tenant authorization (Bearer JWT vs Spoofed headers)
2. Header & Query tenant spoofing rejection (HTTP 403)
3. Cross-tenant incident detail rejection (HTTP 403)
4. Cross-tenant SSE stream access rejection (HTTP 403)
5. Approval token tenant binding & cross-tenant rejection (HTTP 403)
6. Forged approval token rejection (HTTP 400)
7. Approval token replay rejection (HTTP 400)
8. Empty tenant isolation behavior (returns [])
"""

import sys
import json
import time
import requests
from apps.agents.core.security_principal import create_principal_token

BASE_URL = "http://127.0.0.1:8000"

# Generate cryptographically signed JWTs
token_tenant_a = create_principal_token(subject_id="analyst_alpha", tenant_id="tenant-enterprise-prod")
token_tenant_b = create_principal_token(subject_id="adversary_beta", tenant_id="tenant-attacker-adversary")
token_empty_tenant = create_principal_token(subject_id="empty_tenant_user", tenant_id="tenant-clean-empty-99")

auth_a = {"Authorization": f"Bearer {token_tenant_a}"}
auth_b = {"Authorization": f"Bearer {token_tenant_b}"}
auth_empty = {"Authorization": f"Bearer {token_empty_tenant}"}

results = {}

print("=== 1. TESTING IDENTITY-BOUND TENANT AUTHORIZATION ===")

# 1.1 Identity A -> Tenant A
r_a = requests.get(f"{BASE_URL}/api/v1/incidents", headers=auth_a)
print(f"1.1 Identity A -> Tenant A: Status={r_a.status_code}, Count={len(r_a.json())}")
results["identity_a_to_tenant_a"] = "PASS" if r_a.status_code == 200 and len(r_a.json()) > 0 else "FAIL"

# 1.2 Identity A attempting to access Tenant B via header spoof
r_a_spoof_b = requests.get(f"{BASE_URL}/api/v1/incidents", headers={**auth_a, "X-Tenant-ID": "tenant-attacker-adversary"})
print(f"1.2 Identity A -> Header Spoof Tenant B: Status={r_a_spoof_b.status_code}, Body={r_a_spoof_b.text}")
results["identity_a_spoof_header_b"] = "PASS" if r_a_spoof_b.status_code == 403 else "FAIL"

# 1.3 Identity A attempting to access Tenant B via query param spoof
r_a_query_b = requests.get(f"{BASE_URL}/api/v1/incidents?tenant_id=tenant-attacker-adversary", headers=auth_a)
print(f"1.3 Identity A -> Query Spoof Tenant B: Status={r_a_query_b.status_code}, Body={r_a_query_b.text}")
results["identity_a_spoof_query_b"] = "PASS" if r_a_query_b.status_code == 403 else "FAIL"

# 1.4 Identity B -> Tenant B
r_b = requests.get(f"{BASE_URL}/api/v1/incidents", headers=auth_b)
print(f"1.4 Identity B -> Tenant B: Status={r_b.status_code}, Count={len(r_b.json())}")
results["identity_b_to_tenant_b"] = "PASS" if r_b.status_code == 200 else "FAIL"

# 1.5 Empty tenant behavior
r_empty = requests.get(f"{BASE_URL}/api/v1/incidents", headers=auth_empty)
print(f"1.5 Empty Tenant: Status={r_empty.status_code}, Count={len(r_empty.json())}")
results["empty_tenant_returns_empty_list"] = "PASS" if r_empty.status_code == 200 and r_empty.json() == [] else "FAIL"


print("\n=== 2. TESTING CROSS-TENANT INCIDENT DETAIL & SSE ===")

# Get target incident from Tenant A
target_incident_id = "INC-8CAB6A"

# 2.1 Identity A accesses Tenant A incident detail
r_det_a = requests.get(f"{BASE_URL}/api/v1/incidents/{target_incident_id}", headers=auth_a)
print(f"2.1 Identity A -> Tenant A Incident Detail: Status={r_det_a.status_code}")
results["identity_a_detail_tenant_a"] = "PASS" if r_det_a.status_code == 200 else "FAIL"

# 2.2 Identity B attempts to access Tenant A incident detail
r_det_b = requests.get(f"{BASE_URL}/api/v1/incidents/{target_incident_id}", headers=auth_b)
print(f"2.2 Identity B -> Tenant A Incident Detail: Status={r_det_b.status_code}, Body={r_det_b.text}")
results["identity_b_detail_tenant_a_blocked"] = "PASS" if r_det_b.status_code == 403 else "FAIL"

# 2.3 Identity B attempts to subscribe to Tenant A SSE events
r_sse_b = requests.get(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/events", headers=auth_b)
print(f"2.3 Identity B -> Tenant A SSE Stream: Status={r_sse_b.status_code}, Body={r_sse_b.text}")
results["identity_b_sse_tenant_a_blocked"] = "PASS" if r_sse_b.status_code == 403 else "FAIL"


print("\n=== 3. TESTING APPROVAL TOKEN TENANT BINDING & AUTHORIZATION ===")

# Create a fresh pending approval bound to Tenant A using ToolRegistry
from apps.agents.core.tool_registry import ToolRegistry
from packages.schemas.python.models import ToolProposal

registry = ToolRegistry.get_instance()
prop = ToolProposal(
    tool_name="quarantine_email",
    parameters={"message_id": "<test-security-regression@target.com>", "mailbox": "ciso@corp.internal"},
    reasoning="Security regression test quarantine proposal"
)
exec_res = registry.execute_proposal(
    tenant_id="tenant-enterprise-prod",
    proposal=prop,
    autonomy_level=1,
    incident_id="INC-8CAB6A"
)
test_token = exec_res.approval_token
print(f"Created pending approval token for Tenant A: {test_token}")

# 3.1 Forged approval token
r_forged = requests.post(f"{BASE_URL}/api/v1/approve/APP-FORGED-9999", headers=auth_a)
print(f"3.1 Forged token: Status={r_forged.status_code}, Detail={r_forged.text}")
results["forged_token_blocked"] = "PASS" if r_forged.status_code == 400 else "FAIL"

# 3.2 Cross-tenant approval attempt (Identity B attempting to authorize Tenant A token)
r_cross_app = requests.post(f"{BASE_URL}/api/v1/approve/{test_token}", headers=auth_b)
print(f"3.2 Cross-tenant approval attempt: Status={r_cross_app.status_code}, Detail={r_cross_app.text}")
results["cross_tenant_approval_blocked"] = "PASS" if r_cross_app.status_code == 403 else "FAIL"

# 3.3 Cross-tenant rejection attempt (Identity B attempting to reject Tenant A token)
r_cross_rej = requests.post(f"{BASE_URL}/api/v1/reject/{test_token}", headers=auth_b)
print(f"3.3 Cross-tenant rejection attempt: Status={r_cross_rej.status_code}, Detail={r_cross_rej.text}")
results["cross_tenant_rejection_blocked"] = "PASS" if r_cross_rej.status_code == 403 else "FAIL"

# 3.4 Valid approval execution by legitimate Tenant A identity
r_valid_app = requests.post(f"{BASE_URL}/api/v1/approve/{test_token}", headers=auth_a)
print(f"3.4 Valid approval by Tenant A: Status={r_valid_app.status_code}, Resp={r_valid_app.text}")
results["valid_approval_allowed"] = "PASS" if r_valid_app.status_code == 200 else "FAIL"

# 3.5 Replay of the already-approved token by Tenant A
r_replay = requests.post(f"{BASE_URL}/api/v1/approve/{test_token}", headers=auth_a)
print(f"3.5 Token replay: Status={r_replay.status_code}, Detail={r_replay.text}")
results["token_replay_blocked"] = "PASS" if r_replay.status_code == 400 else "FAIL"


print("\n=== SUMMARY OF SECURITY REGRESSION RESULTS ===")
for k, v in results.items():
    print(f" - {k}: {v}")

with open("security_regression_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nAll security regression scenarios complete.")
