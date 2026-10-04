import os
import sys
import json
import time
import uuid
import datetime
import requests
import jwt
from typing import Dict, Any

from apps.agents.core.tool_registry import ToolRegistry, ToolProposal, RiskLevel
from apps.agents.core.durable_storage import DurableStorage

def run_enterprise_dispatch_audit():
    print("=" * 80)
    print("FISHINGMAILS — ENTERPRISE INTEGRATION LIVE-DISPATCH READINESS AUDIT")
    print(f"Commit: 9c056d1e664a79f3b5c63cbc139e0fbf3c0ecf21 | Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 80)

    secret = "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"
    base_url = "http://127.0.0.1:8000"

    results = {}

    # -------------------------------------------------------------------------
    # PART 1: LIVE TEST ENVIRONMENT EXPERIMENTS (Microsoft Graph, Okta, Palo Alto)
    # -------------------------------------------------------------------------
    print("\n[PART 1] Executing Real External Endpoint Dispatch Tests...")
    
    # Test 1.1: Microsoft Graph (quarantine_email against live Graph endpoint with test Bearer token)
    os.environ["MAIL_GATEWAY_URL"] = "https://graph.microsoft.com/v1.0/me/messages"
    os.environ["MAIL_GATEWAY_TOKEN"] = "test-graph-token-audit"
    tr = ToolRegistry()
    prop_m365 = ToolProposal(
        tool_name="quarantine_email",
        parameters={"message_id": "MSG-GRAPH-AUDIT-001", "mailbox": "secops-test@enterprise.com"},
        reasoning="Live audit dispatch to Microsoft Graph endpoint"
    )
    res_m365 = tr.execute_proposal("tenant-enterprise-prod", prop_m365, autonomy_level=4)
    print(f"  [+] quarantine_email -> Microsoft Graph (Status: {res_m365.output.get('status')}, HTTP: {res_m365.output.get('http_status')})")
    
    # Test 1.2: Okta IdP (revoke_session against live Okta sandbox URL)
    os.environ["IDP_API_URL"] = "https://dev-123456.okta.com/api/v1/users/user1/sessions"
    os.environ["IDP_API_TOKEN"] = "test-okta-token-audit"
    prop_okta = ToolProposal(
        tool_name="revoke_session",
        parameters={"user_id": "usr_998877", "session_id": "sess_112233"},
        reasoning="Live audit dispatch to Okta user session revocation endpoint"
    )
    res_okta = tr.execute_proposal("tenant-enterprise-prod", prop_okta, autonomy_level=4)
    print(f"  [+] revoke_session -> Okta IdP (Status: {res_okta.output.get('status')}, HTTP: {res_okta.output.get('http_status')})")

    # Test 1.3: Palo Alto / Firewall (block_ioc against live firewall gateway)
    os.environ["FIREWALL_API_URL"] = "https://api.paloaltonetworks.com/ioc/block"
    os.environ["FIREWALL_API_TOKEN"] = "test-fw-token-audit"
    prop_fw = ToolProposal(
        tool_name="block_ioc",
        parameters={"ioc_value": "198.51.100.99", "ioc_type": "ip"},
        reasoning="Live audit dispatch to Palo Alto firewall endpoint"
    )
    res_fw = tr.execute_proposal("tenant-enterprise-prod", prop_fw, autonomy_level=4)
    print(f"  [+] block_ioc -> Palo Alto API (Status: {res_fw.output.get('status')}, HTTP: {res_fw.output.get('http_status')})")

    # -------------------------------------------------------------------------
    # PART 2: UNCONFIGURED ENVIRONMENT SEMANTICS
    # -------------------------------------------------------------------------
    print("\n[PART 2] Auditing Fail-Closed Semantics in Unconfigured State...")
    for v in ["MAIL_GATEWAY_URL", "IDP_API_URL", "FIREWALL_API_URL", "ACTIVE_DIRECTORY_URL", "GATEWAY_BLOCK_URL", "IDP_PASSWORD_RESET_URL"]:
        os.environ.pop(v, None)

    unconf_results = {}
    for tool_name in ["quarantine_email", "revoke_session", "disable_account", "block_sender", "block_ioc", "force_password_reset"]:
        prop = ToolProposal(tool_name=tool_name, parameters={"target": "val"}, reasoning="Unconfigured fail-closed test")
        res = tr.execute_proposal("tenant-enterprise-prod", prop, autonomy_level=4)
        unconf_results[tool_name] = res.output
        print(f"  [+] {tool_name} (Unconfigured) -> status: {res.output.get('status')}, execution_state: {res.output.get('execution_state')}, confirmed: {res.output.get('confirmed')}")

    # -------------------------------------------------------------------------
    # PART 3: CROSS-TENANT APPROVAL AUTHORIZATION
    # -------------------------------------------------------------------------
    print("\n[PART 3] Verifying Cross-Tenant Approval Containment Isolation...")
    # Tenant A generates pending approval
    prop_gated = ToolProposal(tool_name="quarantine_email", parameters={"message_id": "MSG-TENANT-A-ISOLATION"}, reasoning="Policy gated action")
    res_gated = tr.execute_proposal("tenant-A", prop_gated, autonomy_level=1)
    iso_token = res_gated.approval_token

    # Tenant B tries to approve
    now = time.time()
    tok_b = jwt.encode({"sub": "analyst_b", "tenant_id": "tenant-B", "roles": ["SOC_ANALYST"], "iat": now, "exp": now + 3600}, secret, algorithm="HS256")
    resp_cross = requests.post(f"{base_url}/api/v1/approve/{iso_token}", headers={"Authorization": f"Bearer {tok_b}"})
    print(f"  [+] Tenant B approval attempt on Tenant A token: HTTP {resp_cross.status_code} ({resp_cross.text})")
    assert resp_cross.status_code == 403, "Cross-tenant approval must return HTTP 403"

    # Tenant A approves
    tok_a = jwt.encode({"sub": "analyst_a", "tenant_id": "tenant-A", "roles": ["SOC_ANALYST"], "iat": now, "exp": now + 3600}, secret, algorithm="HS256")
    resp_legit = requests.post(f"{base_url}/api/v1/approve/{iso_token}", headers={"Authorization": f"Bearer {tok_a}"})
    print(f"  [+] Tenant A legitimate approval: HTTP {resp_legit.status_code}")
    assert resp_legit.status_code == 200, "Legitimate approval must return HTTP 200"

    # -------------------------------------------------------------------------
    # PART 4: REPLAY PROTECTION
    # -------------------------------------------------------------------------
    print("\n[PART 4] Verifying Approval Token Replay Protection...")
    resp_replay = requests.post(f"{base_url}/api/v1/approve/{iso_token}", headers={"Authorization": f"Bearer {tok_a}"})
    print(f"  [+] Replayed token approval attempt: HTTP {resp_replay.status_code} ({resp_replay.text})")
    assert resp_replay.status_code == 400, "Replayed token must return HTTP 400"

    # -------------------------------------------------------------------------
    # PART 5: EXPIRATION PROTECTION
    # -------------------------------------------------------------------------
    print("\n[PART 5] Verifying Expired Approval Token Protection...")
    exp_token = f"APP-EXP-{uuid.uuid4().hex[:6].upper()}"
    exp_timestamp = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
    DurableStorage.get_instance().save_approval_token({
        "token": exp_token,
        "tenant_id": "tenant-enterprise-prod",
        "incident_id": "INC-AUDIT-EXP",
        "action_name": "disable_account",
        "risk_level": "CRITICAL",
        "status": "PENDING",
        "nonce": uuid.uuid4().hex[:16],
        "expiry_timestamp": exp_timestamp,
        "hmac_signature": "SIG-AUDIT-EXP",
        "parameters": {"user_id": "target_user_exp"},
        "reasoning": "Audit test expired token"
    })
    tok_prod = jwt.encode({"sub": "analyst_1", "tenant_id": "tenant-enterprise-prod", "roles": ["SOC_ANALYST"], "iat": now, "exp": now + 3600}, secret, algorithm="HS256")
    resp_exp = requests.post(f"{base_url}/api/v1/approve/{exp_token}", headers={"Authorization": f"Bearer {tok_prod}"})
    print(f"  [+] Expired token approval attempt: HTTP {resp_exp.status_code} ({resp_exp.text})")
    assert resp_exp.status_code == 400, "Expired token must return HTTP 400"

    # -------------------------------------------------------------------------
    # PART 6: WRITE JSON AUDIT ARTIFACTS
    # -------------------------------------------------------------------------
    live_dispatch_evidence = {
        "metadata": {
            "title": "ENTERPRISE LIVE DISPATCH & CONTAINMENT SECURITY AUDIT",
            "commit": "9c056d1e664a79f3b5c63cbc139e0fbf3c0ecf21",
            "branch": "develop",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        },
        "live_endpoint_tests": {
            "microsoft_graph": {
                "endpoint": "https://graph.microsoft.com/v1.0/me/messages",
                "method": "POST",
                "action": "quarantine_email",
                "auth_tested": "Bearer test-graph-token-audit",
                "http_status": res_m365.output.get("http_status"),
                "status": res_m365.output.get("status"),
                "execution_state": res_m365.output.get("execution_state"),
                "confirmed": res_m365.output.get("confirmed"),
                "raw_detail": res_m365.output.get("detail")
            },
            "okta_idp": {
                "endpoint": "https://dev-123456.okta.com/api/v1/users/user1/sessions",
                "method": "POST",
                "action": "revoke_session",
                "auth_tested": "Bearer test-okta-token-audit",
                "http_status": res_okta.output.get("http_status"),
                "status": res_okta.output.get("status"),
                "execution_state": res_okta.output.get("execution_state"),
                "confirmed": res_okta.output.get("confirmed"),
                "raw_detail": res_okta.output.get("detail")
            },
            "palo_alto_firewall": {
                "endpoint": "https://api.paloaltonetworks.com/ioc/block",
                "method": "POST",
                "action": "block_ioc",
                "auth_tested": "Bearer test-fw-token-audit",
                "http_status": res_fw.output.get("http_status"),
                "status": res_fw.output.get("status"),
                "execution_state": res_fw.output.get("execution_state"),
                "confirmed": res_fw.output.get("confirmed"),
                "raw_detail": res_fw.output.get("detail")
            }
        },
        "unconfigured_fail_closed_tests": unconf_results,
        "cross_tenant_isolation": {
            "token": iso_token,
            "tenant_a": "tenant-A",
            "tenant_b_attempt_status": resp_cross.status_code,
            "tenant_b_response": resp_cross.json(),
            "tenant_a_approval_status": resp_legit.status_code
        },
        "replay_protection": {
            "token": iso_token,
            "first_approval_status": resp_legit.status_code,
            "replay_status": resp_replay.status_code,
            "replay_response": resp_replay.json()
        },
        "expiration_protection": {
            "token": exp_token,
            "status": resp_exp.status_code,
            "response": resp_exp.json()
        }
    }

    with open("enterprise_dispatch_audit_evidence.json", "w", encoding="utf-8") as f:
        json.dump(live_dispatch_evidence, f, indent=2)

    print("\n[+] Saved audit evidence to enterprise_dispatch_audit_evidence.json")
    print("=" * 80)
    print("ALL ENTERPRISE DISPATCH READINESS AUDIT STEPS COMPLETED.")
    print("=" * 80)

if __name__ == "__main__":
    run_enterprise_dispatch_audit()
