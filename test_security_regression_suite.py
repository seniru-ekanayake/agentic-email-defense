"""
Comprehensive Production Authentication & Tenant Security Regression Suite
Verifies:
1. Production Fail-Closed Invariant on ALL protected endpoints:
   - No Authorization header -> HTTP 401
   - Malformed Authorization header -> HTTP 401
   - Random/garbage JWT -> HTTP 401
   - Expired JWT -> HTTP 401
   - Wrong-signature JWT -> HTTP 401
   - Missing required claims (sub, tenant_id) -> HTTP 401
   - Algorithm confusion attempt -> HTTP 401
2. Server-side Tenant Authority:
   - Valid Tenant A JWT -> Authorized (200)
   - Valid Tenant A JWT + X-Tenant-ID Tenant B -> Blocked (403)
   - Valid Tenant A JWT + ?tenant_id=Tenant B -> Blocked (403)
   - Valid Tenant B JWT accessing Tenant A incident detail -> Blocked (403)
   - Valid Tenant B JWT accessing Tenant A investigation control -> Blocked (403)
   - Valid Tenant B JWT accessing Tenant A SSE stream -> Blocked (403, 0 frames)
   - Empty tenant querying incidents -> 200 with []
3. Approval Token Binding & Authorization:
   - Unauthenticated approval/rejection -> 401
   - Forged approval token -> 400
   - Cross-tenant approval attempt -> 403
   - Cross-tenant rejection attempt -> 403
   - Legitimate approval execution -> 200
   - Replay of consumed token -> 400
4. Configuration Boundary & Fallback Invariants:
   - Development + fallback enabled -> local_analyst
   - Development + fallback disabled -> 401
   - Production + fallback requested -> Fail closed (RuntimeError)
   - Production + missing secret -> Fail closed (RuntimeError)
"""

import os
import sys
import time
import json
import requests
import jwt
from fastapi import Request

from apps.agents.core.security_principal import (
    create_principal_token,
    get_jwt_secret_key,
    get_authenticated_principal,
    is_local_auth_fallback_enabled,
    AuthenticatedPrincipal
)

BASE_URL = "http://127.0.0.1:8000"
SECRET_KEY = os.environ.get(
    "FISHINGMAILS_AUTH_SECRET",
    "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"
)
os.environ["FISHINGMAILS_AUTH_SECRET"] = SECRET_KEY

# Tokens
valid_token_a = create_principal_token(subject_id="analyst_alpha", tenant_id="tenant-enterprise-prod")
valid_token_b = create_principal_token(subject_id="adversary_beta", tenant_id="tenant-attacker-adversary")
empty_tenant_token = create_principal_token(subject_id="empty_user", tenant_id="tenant-clean-empty-99")

# Expired token
now = time.time()
expired_token = jwt.encode(
    {"sub": "analyst_alpha", "tenant_id": "tenant-enterprise-prod", "iat": now - 3600, "exp": now - 60},
    SECRET_KEY,
    algorithm="HS256"
)

# Wrong signature token
wrong_sig_token = jwt.encode(
    {"sub": "analyst_alpha", "tenant_id": "tenant-enterprise-prod", "iat": now, "exp": now + 3600},
    "completely-wrong-signing-secret-key-that-does-not-match-at-all",
    algorithm="HS256"
)

# Missing tenant claim token
missing_tenant_token = jwt.encode(
    {"sub": "analyst_alpha", "iat": now, "exp": now + 3600},
    SECRET_KEY,
    algorithm="HS256"
)

# Missing sub claim token
missing_sub_token = jwt.encode(
    {"tenant_id": "tenant-enterprise-prod", "iat": now, "exp": now + 3600},
    SECRET_KEY,
    algorithm="HS256"
)

# Algorithm confusion token (header alg: HS384 signed with HS384)
alg_confusion_token = jwt.encode(
    {"sub": "analyst_alpha", "tenant_id": "tenant-enterprise-prod", "iat": now, "exp": now + 3600},
    SECRET_KEY,
    algorithm="HS384"
)

results = {}

print("======================================================================")
print("1. PRODUCTION FAIL-CLOSED TESTS (UNAUTHENTICATED / MALFORMED)")
print("======================================================================")

target_incident_id = "INC-8CAB6A"

# Protected endpoints inventory to test for fail-closed behavior
protected_endpoints = [
    ("GET", f"/api/v1/incidents"),
    ("GET", f"/api/v1/incidents/{target_incident_id}"),
    ("GET", f"/api/v1/investigations/{target_incident_id}/events"),
    ("POST", f"/api/v1/investigations/{target_incident_id}/pause"),
    ("POST", f"/api/v1/investigations/{target_incident_id}/resume"),
    ("POST", f"/api/v1/investigations/{target_incident_id}/cancel"),
    ("POST", f"/api/v1/investigations/{target_incident_id}/replay"),
    ("GET", f"/api/v1/investigations/compare?id_a={target_incident_id}&id_b={target_incident_id}"),
    ("POST", f"/api/v1/approve/APP-ANY-TEST"),
    ("POST", f"/api/v1/reject/APP-ANY-TEST"),
    ("POST", f"/api/v1/request-info/APP-ANY-TEST"),
    ("GET", f"/api/v1/audit-logs"),
    ("GET", f"/api/v1/trust-score"),
    ("POST", f"/api/v1/mode"),
]

all_no_auth_passed = True
for method, endpoint in protected_endpoints:
    url = f"{BASE_URL}{endpoint}"
    if method == "GET":
        resp = requests.get(url)
    else:
        resp = requests.post(url, json={})
    if resp.status_code != 401:
        print(f"FAILED fail-closed test on {method} {endpoint}: got {resp.status_code}")
        all_no_auth_passed = False
    else:
        print(f"PASS: {method} {endpoint} -> 401 Unauthorized")

results["production_all_protected_endpoints_no_auth_401"] = "PASS" if all_no_auth_passed else "FAIL"

# Test malformed / invalid JWT variants on /api/v1/incidents
r_malformed = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": "Basic admin:password"})
print(f"Malformed auth header (Basic): Status={r_malformed.status_code}")
results["malformed_header_scheme_401"] = "PASS" if r_malformed.status_code == 401 else "FAIL"

r_bearer_empty = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": "Bearer "})
print(f"Empty Bearer token: Status={r_bearer_empty.status_code}")
results["empty_bearer_token_401"] = "PASS" if r_bearer_empty.status_code == 401 else "FAIL"

r_garbage = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": "Bearer not.a.real.jwt.token"})
print(f"Garbage JWT: Status={r_garbage.status_code}")
results["garbage_jwt_401"] = "PASS" if r_garbage.status_code == 401 else "FAIL"

r_expired = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": f"Bearer {expired_token}"})
print(f"Expired JWT: Status={r_expired.status_code}")
results["expired_jwt_401"] = "PASS" if r_expired.status_code == 401 else "FAIL"

r_wrong_sig = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": f"Bearer {wrong_sig_token}"})
print(f"Wrong signature JWT: Status={r_wrong_sig.status_code}")
results["wrong_signature_jwt_401"] = "PASS" if r_wrong_sig.status_code == 401 else "FAIL"

r_missing_sub = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": f"Bearer {missing_sub_token}"})
print(f"Missing 'sub' claim: Status={r_missing_sub.status_code}")
results["missing_sub_claim_401"] = "PASS" if r_missing_sub.status_code == 401 else "FAIL"

r_missing_tenant = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": f"Bearer {missing_tenant_token}"})
print(f"Missing 'tenant_id' claim: Status={r_missing_tenant.status_code}")
results["missing_tenant_claim_401"] = "PASS" if r_missing_tenant.status_code == 401 else "FAIL"

r_alg_conf = requests.get(f"{BASE_URL}/api/v1/incidents", headers={"Authorization": f"Bearer {alg_confusion_token}"})
print(f"Algorithm confusion (HS384): Status={r_alg_conf.status_code}")
results["algorithm_confusion_blocked_401"] = "PASS" if r_alg_conf.status_code == 401 else "FAIL"


print("\n======================================================================")
print("2. SERVER-SIDE TENANT AUTHORITY & SPOOFING RESISTANCE")
print("======================================================================")

auth_a = {"Authorization": f"Bearer {valid_token_a}"}
auth_b = {"Authorization": f"Bearer {valid_token_b}"}
auth_empty = {"Authorization": f"Bearer {empty_tenant_token}"}

# 2.1 Identity A -> Tenant A
r_a = requests.get(f"{BASE_URL}/api/v1/incidents", headers=auth_a)
print(f"2.1 Identity A -> Tenant A incidents: Status={r_a.status_code}, Count={len(r_a.json())}")
results["valid_tenant_a_jwt_success"] = "PASS" if r_a.status_code == 200 and len(r_a.json()) > 0 else "FAIL"

# 2.2 Header spoof attempt
r_a_spoof_h = requests.get(f"{BASE_URL}/api/v1/incidents", headers={**auth_a, "X-Tenant-ID": "tenant-attacker-adversary"})
print(f"2.2 Header spoof (X-Tenant-ID): Status={r_a_spoof_h.status_code}, Detail={r_a_spoof_h.text}")
results["header_spoof_blocked_403"] = "PASS" if r_a_spoof_h.status_code == 403 else "FAIL"

# 2.3 Query spoof attempt
r_a_spoof_q = requests.get(f"{BASE_URL}/api/v1/incidents?tenant_id=tenant-attacker-adversary", headers=auth_a)
print(f"2.3 Query param spoof (?tenant_id): Status={r_a_spoof_q.status_code}, Detail={r_a_spoof_q.text}")
results["query_spoof_blocked_403"] = "PASS" if r_a_spoof_q.status_code == 403 else "FAIL"

# 2.4 Cross-tenant incident detail attempt
r_det_b = requests.get(f"{BASE_URL}/api/v1/incidents/{target_incident_id}", headers=auth_b)
print(f"2.4 Cross-tenant incident detail: Status={r_det_b.status_code}, Detail={r_det_b.text}")
results["cross_tenant_detail_blocked_403"] = "PASS" if r_det_b.status_code == 403 else "FAIL"

# 2.5 Cross-tenant investigation pause attempt
r_pause_b = requests.post(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/pause", headers=auth_b)
print(f"2.5 Cross-tenant pause attempt: Status={r_pause_b.status_code}, Detail={r_pause_b.text}")
results["cross_tenant_pause_blocked_403"] = "PASS" if r_pause_b.status_code == 403 else "FAIL"

# 2.6 Cross-tenant investigation replay attempt
r_replay_b = requests.post(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/replay", headers=auth_b)
print(f"2.6 Cross-tenant replay attempt: Status={r_replay_b.status_code}, Detail={r_replay_b.text}")
results["cross_tenant_replay_blocked_403"] = "PASS" if r_replay_b.status_code == 403 else "FAIL"

# 2.7 Cross-tenant investigation compare attempt
r_comp_b = requests.get(f"{BASE_URL}/api/v1/investigations/compare?id_a={target_incident_id}&id_b={target_incident_id}", headers=auth_b)
print(f"2.7 Cross-tenant compare attempt: Status={r_comp_b.status_code}, Detail={r_comp_b.text}")
results["cross_tenant_compare_blocked_403"] = "PASS" if r_comp_b.status_code == 403 else "FAIL"

# 2.8 Empty tenant returns []
r_empty = requests.get(f"{BASE_URL}/api/v1/incidents", headers=auth_empty)
print(f"2.8 Empty tenant queries: Status={r_empty.status_code}, Records={r_empty.json()}")
results["empty_tenant_returns_empty_list"] = "PASS" if r_empty.status_code == 200 and r_empty.json() == [] else "FAIL"


print("\n======================================================================")
print("3. SSE AUTHORIZATION & LEAKAGE PROOF")
print("======================================================================")

# 3.1 Unauthenticated SSE stream connection
r_sse_unauth = requests.get(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/events", stream=True)
print(f"3.1 Unauthenticated SSE stream: Status={r_sse_unauth.status_code}")
unauth_bytes = r_sse_unauth.raw.read(100)
is_not_unauth_stream = r_sse_unauth.headers.get("content-type") != "text/event-stream" and b"data:" not in unauth_bytes
results["unauthenticated_sse_blocked_401"] = "PASS" if r_sse_unauth.status_code == 401 and is_not_unauth_stream else "FAIL"

# 3.2 Cross-tenant SSE stream connection
r_sse_cross = requests.get(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/events", headers=auth_b, stream=True)
print(f"3.2 Cross-tenant SSE stream: Status={r_sse_cross.status_code}")
cross_bytes = r_sse_cross.raw.read(100)
is_not_cross_stream = r_sse_cross.headers.get("content-type") != "text/event-stream" and b"data:" not in cross_bytes
results["cross_tenant_sse_blocked_403"] = "PASS" if r_sse_cross.status_code == 403 and is_not_cross_stream else "FAIL"

# 3.3 Authorized SSE stream connection
r_sse_auth = requests.get(f"{BASE_URL}/api/v1/investigations/{target_incident_id}/events", headers=auth_a, stream=True)
print(f"3.3 Authorized SSE stream: Status={r_sse_auth.status_code}")
results["authorized_sse_allowed_200"] = "PASS" if r_sse_auth.status_code == 200 else "FAIL"
r_sse_auth.close()


print("\n======================================================================")
print("4. APPROVAL TOKEN BINDING, AUTHORIZATION, AND REPLAY PROOF")
print("======================================================================")

from apps.agents.core.tool_registry import ToolRegistry
from packages.schemas.python.models import ToolProposal

registry = ToolRegistry.get_instance()
prop = ToolProposal(
    tool_name="quarantine_email",
    parameters={"message_id": "<prod-auth-gate-verify@target.com>", "mailbox": "ciso@corp.internal"},
    reasoning="Production authentication gate quarantine proposal"
)
exec_res = registry.execute_proposal(
    tenant_id="tenant-enterprise-prod",
    proposal=prop,
    autonomy_level=1,
    incident_id=target_incident_id
)
approval_token = exec_res.approval_token
print(f"Created real pending approval token: {approval_token}")

# 4.1 Unauthenticated approval attempt
r_app_unauth = requests.post(f"{BASE_URL}/api/v1/approve/{approval_token}")
print(f"4.1 Unauthenticated approval: Status={r_app_unauth.status_code}")
results["unauthenticated_approval_401"] = "PASS" if r_app_unauth.status_code == 401 else "FAIL"

# 4.2 Unauthenticated rejection attempt
r_rej_unauth = requests.post(f"{BASE_URL}/api/v1/reject/{approval_token}")
print(f"4.2 Unauthenticated rejection: Status={r_rej_unauth.status_code}")
results["unauthenticated_rejection_401"] = "PASS" if r_rej_unauth.status_code == 401 else "FAIL"

# 4.3 Forged token attempt
r_app_forged = requests.post(f"{BASE_URL}/api/v1/approve/APP-FORGED-9999", headers=auth_a)
print(f"4.3 Forged approval token: Status={r_app_forged.status_code}")
results["forged_approval_token_400"] = "PASS" if r_app_forged.status_code == 400 else "FAIL"

# 4.4 Cross-tenant approval attempt
r_app_cross = requests.post(f"{BASE_URL}/api/v1/approve/{approval_token}", headers=auth_b)
print(f"4.4 Cross-tenant approval attempt: Status={r_app_cross.status_code}")
results["cross_tenant_approval_blocked_403"] = "PASS" if r_app_cross.status_code == 403 else "FAIL"

# 4.5 Cross-tenant rejection attempt
r_rej_cross = requests.post(f"{BASE_URL}/api/v1/reject/{approval_token}", headers=auth_b)
print(f"4.5 Cross-tenant rejection attempt: Status={r_rej_cross.status_code}")
results["cross_tenant_rejection_blocked_403"] = "PASS" if r_rej_cross.status_code == 403 else "FAIL"

# 4.6 Legitimate Tenant A approval execution
r_app_valid = requests.post(f"{BASE_URL}/api/v1/approve/{approval_token}", headers=auth_a)
print(f"4.6 Legitimate approval: Status={r_app_valid.status_code}, Message={r_app_valid.json().get('message')}")
results["legitimate_approval_success_200"] = "PASS" if r_app_valid.status_code == 200 else "FAIL"

# 4.7 Replay of already executed token
r_app_replay = requests.post(f"{BASE_URL}/api/v1/approve/{approval_token}", headers=auth_a)
print(f"4.7 Approval replay: Status={r_app_replay.status_code}")
results["approval_token_replay_blocked_400"] = "PASS" if r_app_replay.status_code == 400 else "FAIL"


print("\n======================================================================")
print("5. CONFIGURATION BOUNDARY & EXPLICIT DEVELOPMENT FALLBACK INVARIANTS")
print("======================================================================")

# 5.1 Test fallback in development mode with explicit flag
os.environ["FISHINGMAILS_ENV"] = "development"
os.environ["FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK"] = "true"
class DummyRequest:
    def __init__(self, headers=None, query_params=None):
        self.headers = headers or {}
        self.query_params = query_params or {}

dev_principal = get_authenticated_principal(DummyRequest())
print(f"5.1 Dev fallback enabled: Principal={dev_principal.subject_id}, Tenant={dev_principal.tenant_id}")
results["dev_fallback_enabled_resolves_local_analyst"] = (
    "PASS" if dev_principal.subject_id == "local_analyst" and dev_principal.tenant_id == "tenant-enterprise-prod" else "FAIL"
)

# 5.2 Test fallback in development mode with flag disabled
os.environ["FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK"] = "false"
try:
    get_authenticated_principal(DummyRequest())
    results["dev_fallback_disabled_raises_401"] = "FAIL"
except Exception as e:
    is_401 = hasattr(e, "status_code") and e.status_code == 401
    print(f"5.2 Dev fallback disabled: Exception={e}")
    results["dev_fallback_disabled_raises_401"] = "PASS" if is_401 else "FAIL"

# 5.3 Test fallback attempt in production mode (MUST FAIL CLOSED via RuntimeError)
os.environ["FISHINGMAILS_ENV"] = "production"
os.environ["FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK"] = "true"
try:
    is_local_auth_fallback_enabled()
    results["production_fallback_fails_closed_at_startup"] = "FAIL"
except RuntimeError as re:
    print(f"5.3 Production fallback fails closed: {re}")
    results["production_fallback_fails_closed_at_startup"] = "PASS"
except Exception as e:
    results["production_fallback_fails_closed_at_startup"] = "FAIL"

# 5.4 Test missing secret in production mode (MUST FAIL CLOSED via RuntimeError)
os.environ["FISHINGMAILS_AUTH_SECRET"] = ""
try:
    get_jwt_secret_key()
    results["production_missing_secret_fails_closed"] = "FAIL"
except RuntimeError as re:
    print(f"5.4 Production missing secret fails closed: {re}")
    results["production_missing_secret_fails_closed"] = "PASS"
except Exception as e:
    results["production_missing_secret_fails_closed"] = "FAIL"

# Restore production environment settings
os.environ["FISHINGMAILS_ENV"] = "production"
os.environ["FISHINGMAILS_AUTH_SECRET"] = SECRET_KEY
os.environ["FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK"] = "false"


print("\n======================================================================")
print("FINAL AUDIT RESULTS SUMMARY")
print("======================================================================")
total_tests = len(results)
passed_tests = sum(1 for v in results.values() if v == "PASS")
failed_tests = sum(1 for v in results.values() if v == "FAIL")

for test_id, status in results.items():
    print(f"  [{status}] {test_id}")

print(f"\nTotal: {total_tests} | Passed: {passed_tests} | Failed: {failed_tests}")

with open("security_regression_results.json", "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": time.time(),
        "total": total_tests,
        "passed": passed_tests,
        "failed": failed_tests,
        "verdict": "PRODUCTION AUTHENTICATION GATE PASSED" if failed_tests == 0 else "PRODUCTION AUTHENTICATION GATE FAILED",
        "results": results
    }, f, indent=2)

if failed_tests > 0:
    print("\nVERDICT: PRODUCTION AUTHENTICATION GATE FAILED")
    sys.exit(1)
else:
    print("\nVERDICT: PRODUCTION AUTHENTICATION GATE PASSED")
