"""
Comprehensive Configuration Consistency & Release Forensic Audit Script.
Executes live black-box testing with real FastAPI/uvicorn server instances
under every environment and secret configuration.
"""

import os
import sys
import time
import subprocess
import requests
import jwt
from typing import Dict, Optional, Tuple

VALID_SECRET = "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min"
PYTHON_EXE = sys.executable

def start_server_instance(
    port: int,
    env_vars: Dict[str, str],
    timeout_seconds: float = 6.0
) -> Tuple[Optional[subprocess.Popen], str, bool]:
    """
    Spawns a real uvicorn server process on the specified port with custom environment.
    Returns (process, logs, started_successfully).
    """
    clean_env = os.environ.copy()
    # Strip existing auth/env variables
    for k in [
        "FISHINGMAILS_ENV",
        "ENVIRONMENT",
        "FISHINGMAILS_AUTH_SECRET",
        "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK",
        "DEFAULT_TENANT_ID"
    ]:
        clean_env.pop(k, None)

    # Apply test env vars
    clean_env.update(env_vars)

    cmd = [
        PYTHON_EXE,
        "-m",
        "uvicorn",
        "apps.server:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "info"
    ]

    proc = subprocess.Popen(
        cmd,
        cwd=os.getcwd(),
        env=clean_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    start_time = time.time()
    started = False
    url = f"http://127.0.0.1:{port}/api/v1/mode"

    while time.time() - start_time < timeout_seconds:
        # Check if process terminated prematurely
        ret = proc.poll()
        if ret is not None:
            # Process crashed/failed closed
            logs, _ = proc.communicate()
            return None, logs, False

        # Try connecting to port
        try:
            # Note: /api/v1/mode might require auth or return 401/200; any HTTP response means it started!
            resp = requests.get(url, timeout=0.5)
            started = True
            break
        except (requests.ConnectionError, requests.Timeout):
            time.sleep(0.3)

    if started:
        return proc, "", True
    else:
        # Timed out waiting
        proc.kill()
        logs, _ = proc.communicate()
        return None, logs, False


def stop_server_instance(proc: Optional[subprocess.Popen]):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def mint_jwt(sub: str, tenant_id: str, secret: str = VALID_SECRET, roles=None) -> str:
    now = time.time()
    payload = {
        "sub": sub,
        "tenant_id": tenant_id,
        "roles": roles or ["SOC_ANALYST"],
        "iat": now,
        "exp": now + 3600
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def run_configuration_audit():
    results = []
    print("=" * 70)
    print("FISHINGMAILS — CONFIGURATION CONSISTENCY & SECRET FORENSIC AUDIT")
    print("=" * 70)

    # ------------------------------------------------------------------
    # CONFIG A: No environment selector configured
    # ------------------------------------------------------------------
    print("\n[TEST A] No environment selector configured (Safe Default = Production)")
    port_a = 8021
    proc_a, logs_a, ok_a = start_server_instance(port_a, {"FISHINGMAILS_AUTH_SECRET": VALID_SECRET})
    if not ok_a:
        print(f"  FAIL: Server failed to start: {logs_a[:200]}")
        results.append(("Config A (No Env Selector)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_a}"
            # 1. Unauthenticated incidents -> 401
            r1 = requests.get(f"{base}/api/v1/incidents")
            # 2. Unauthenticated auth/token -> 401
            r2 = requests.post(f"{base}/api/v1/auth/token", json={})
            # 3. Authenticated auth/token -> 403
            tok = mint_jwt("analyst_1", "tenant-enterprise-prod")
            r3 = requests.post(f"{base}/api/v1/auth/token", headers={"Authorization": f"Bearer {tok}"}, json={})
            # 4. Check mode
            r4 = requests.get(f"{base}/api/v1/mode")

            pass_a = (r1.status_code == 401 and r2.status_code == 401 and r3.status_code == 403 and r4.status_code == 200 and r4.json().get("mode") == "PRODUCTION")
            print(f"  Unauth Incidents: {r1.status_code} (Exp 401)")
            print(f"  Unauth Token Mint: {r2.status_code} (Exp 401)")
            print(f"  Auth Token Mint: {r3.status_code} (Exp 403)")
            print(f"  Platform Mode: {r4.json().get('mode')} (Exp PRODUCTION)")
            print(f"  Result: {'PASS' if pass_a else 'FAIL'}")
            results.append(("Config A (No Env Selector -> Prod Default)", "PASS" if pass_a else "FAIL", f"Incidents={r1.status_code}, Mint={r2.status_code}/{r3.status_code}, Mode={r4.json().get('mode')}"))
        finally:
            stop_server_instance(proc_a)

    # ------------------------------------------------------------------
    # CONFIG B: Explicit production configuration
    # ------------------------------------------------------------------
    print("\n[TEST B] Explicit production configuration (ENVIRONMENT=production)")
    port_b = 8022
    proc_b, logs_b, ok_b = start_server_instance(port_b, {"ENVIRONMENT": "production", "FISHINGMAILS_AUTH_SECRET": VALID_SECRET})
    if not ok_b:
        print(f"  FAIL: Server failed to start: {logs_b[:200]}")
        results.append(("Config B (Explicit Production)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_b}"
            r1 = requests.get(f"{base}/api/v1/incidents")
            tok = mint_jwt("analyst_1", "tenant-enterprise-prod")
            r2 = requests.post(f"{base}/api/v1/auth/token", headers={"Authorization": f"Bearer {tok}"}, json={})
            pass_b = (r1.status_code == 401 and r2.status_code == 403)
            print(f"  Unauth Incidents: {r1.status_code} (Exp 401)")
            print(f"  Auth Token Mint: {r2.status_code} (Exp 403)")
            print(f"  Result: {'PASS' if pass_b else 'FAIL'}")
            results.append(("Config B (Explicit Production)", "PASS" if pass_b else "FAIL", f"Incidents={r1.status_code}, Mint={r2.status_code}"))
        finally:
            stop_server_instance(proc_b)

    # ------------------------------------------------------------------
    # CONFIG C: Explicit development configuration
    # ------------------------------------------------------------------
    print("\n[TEST C] Explicit development configuration (FISHINGMAILS_ENV=development)")
    port_c = 8023
    proc_c, logs_c, ok_c = start_server_instance(port_c, {"FISHINGMAILS_ENV": "development", "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK": "false"})
    if not ok_c:
        print(f"  FAIL: Server failed to start: {logs_c[:200]}")
        results.append(("Config C (Explicit Development)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_c}"
            r1 = requests.get(f"{base}/api/v1/incidents")
            r2 = requests.post(f"{base}/api/v1/auth/token", json={"subject_id": "dev_tester", "tenant_id": "tenant-dev", "expires_in": 9999999})
            token_issued = bool(r2.json().get("access_token")) if r2.status_code == 200 else False
            pass_c = (r1.status_code == 401 and r2.status_code == 200 and token_issued)
            print(f"  Unauth Incidents: {r1.status_code} (Exp 401)")
            print(f"  Dev Token Mint: {r2.status_code} (Exp 200, Token issued={token_issued})")
            print(f"  Result: {'PASS' if pass_c else 'FAIL'}")
            results.append(("Config C (Explicit Development)", "PASS" if pass_c else "FAIL", f"Incidents={r1.status_code}, Mint={r2.status_code}"))
        finally:
            stop_server_instance(proc_c)

    # ------------------------------------------------------------------
    # CONFIG D: Production + fallback=true (Fatal Misconfiguration)
    # ------------------------------------------------------------------
    print("\n[TEST D] Production + fallback=true (Expected: Fail-closed startup failure)")
    port_d = 8024
    proc_d, logs_d, ok_d = start_server_instance(
        port_d,
        {"FISHINGMAILS_ENV": "production", "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK": "true", "FISHINGMAILS_AUTH_SECRET": VALID_SECRET}
    )
    pass_d = (not ok_d and ("FATAL SECURITY CONFIGURATION ERROR" in logs_d or "strictly forbidden" in logs_d))
    print(f"  Started: {ok_d} (Exp False)")
    print(f"  Fail closed error logged: {'FATAL SECURITY CONFIGURATION ERROR' in logs_d}")
    print(f"  Result: {'PASS' if pass_d else 'FAIL'}")
    results.append(("Config D (Production + fallback=true)", "PASS" if pass_d else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_d)

    # ------------------------------------------------------------------
    # CONFIG E: Development + fallback=false
    # ------------------------------------------------------------------
    print("\n[TEST E] Development + fallback=false (Expected: 401 on unauthenticated request)")
    port_e = 8025
    proc_e, logs_e, ok_e = start_server_instance(
        port_e,
        {"FISHINGMAILS_ENV": "development", "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK": "false"}
    )
    if not ok_e:
        print(f"  FAIL: Server failed to start: {logs_e[:200]}")
        results.append(("Config E (Dev + fallback=false)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_e}"
            r1 = requests.get(f"{base}/api/v1/incidents")
            pass_e = (r1.status_code == 401)
            print(f"  Unauth Incidents: {r1.status_code} (Exp 401)")
            print(f"  Result: {'PASS' if pass_e else 'FAIL'}")
            results.append(("Config E (Dev + fallback=false)", "PASS" if pass_e else "FAIL", f"Incidents={r1.status_code}"))
        finally:
            stop_server_instance(proc_e)

    # ------------------------------------------------------------------
    # CONFIG F: Development + fallback=true
    # ------------------------------------------------------------------
    print("\n[TEST F] Development + fallback=true (Expected: local fallback active)")
    port_f = 8026
    proc_f, logs_f, ok_f = start_server_instance(
        port_f,
        {"FISHINGMAILS_ENV": "development", "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK": "true"}
    )
    if not ok_f:
        print(f"  FAIL: Server failed to start: {logs_f[:200]}")
        results.append(("Config F (Dev + fallback=true)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_f}"
            r1 = requests.get(f"{base}/api/v1/incidents")
            pass_f = (r1.status_code == 200)
            print(f"  Unauth Incidents with dev fallback: {r1.status_code} (Exp 200)")
            print(f"  Result: {'PASS' if pass_f else 'FAIL'}")
            results.append(("Config F (Dev + fallback=true)", "PASS" if pass_f else "FAIL", f"Incidents={r1.status_code}"))
        finally:
            stop_server_instance(proc_f)

    # ------------------------------------------------------------------
    # CONFIG G1: Conflicting environment configuration
    # ------------------------------------------------------------------
    print("\n[TEST G1] Conflicting environment configuration (FISHINGMAILS_ENV=production vs ENVIRONMENT=development)")
    port_g1 = 8027
    proc_g1, logs_g1, ok_g1 = start_server_instance(
        port_g1,
        {"FISHINGMAILS_ENV": "production", "ENVIRONMENT": "development", "FISHINGMAILS_AUTH_SECRET": VALID_SECRET}
    )
    pass_g1 = (not ok_g1 and "Conflicting environment selectors" in logs_g1)
    print(f"  Started: {ok_g1} (Exp False)")
    print(f"  Conflict error logged: {'Conflicting environment selectors' in logs_g1}")
    print(f"  Result: {'PASS' if pass_g1 else 'FAIL'}")
    results.append(("Config G1 (Conflicting Env Selectors)", "PASS" if pass_g1 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_g1)

    # ------------------------------------------------------------------
    # CONFIG G2: Ambiguous / invalid environment configuration
    # ------------------------------------------------------------------
    print("\n[TEST G2] Ambiguous / invalid environment configuration (ENVIRONMENT=custom_staging_prod)")
    port_g2 = 8028
    proc_g2, logs_g2, ok_g2 = start_server_instance(
        port_g2,
        {"ENVIRONMENT": "custom_staging_prod", "FISHINGMAILS_AUTH_SECRET": VALID_SECRET}
    )
    pass_g2 = (not ok_g2 and "Invalid or ambiguous operating environment" in logs_g2)
    print(f"  Started: {ok_g2} (Exp False)")
    print(f"  Invalid mode error logged: {'Invalid or ambiguous operating environment' in logs_g2}")
    print(f"  Result: {'PASS' if pass_g2 else 'FAIL'}")
    results.append(("Config G2 (Ambiguous/Invalid Env)", "PASS" if pass_g2 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_g2)

    # ------------------------------------------------------------------
    # SECTION 4: SECRET CONFIGURATION AUDIT
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SECTION 4: SECRET CONFIGURATION AUDIT")
    print("=" * 70)

    # S1: Absent secret in production
    print("\n[TEST S1] Production mode with absent FISHINGMAILS_AUTH_SECRET")
    port_s1 = 8029
    proc_s1, logs_s1, ok_s1 = start_server_instance(port_s1, {"FISHINGMAILS_ENV": "production"})
    pass_s1 = (not ok_s1 and "FISHINGMAILS_AUTH_SECRET must be explicitly set" in logs_s1)
    print(f"  Started: {ok_s1} (Exp False)")
    print(f"  Missing secret error logged: {'FISHINGMAILS_AUTH_SECRET must be explicitly set' in logs_s1}")
    print(f"  Result: {'PASS' if pass_s1 else 'FAIL'}")
    results.append(("Secret S1 (Absent in Production)", "PASS" if pass_s1 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_s1)

    # S2: Empty secret in production
    print("\n[TEST S2] Production mode with empty FISHINGMAILS_AUTH_SECRET")
    port_s2 = 8030
    proc_s2, logs_s2, ok_s2 = start_server_instance(port_s2, {"FISHINGMAILS_ENV": "production", "FISHINGMAILS_AUTH_SECRET": ""})
    pass_s2 = (not ok_s2 and "FISHINGMAILS_AUTH_SECRET must be explicitly set" in logs_s2)
    print(f"  Started: {ok_s2} (Exp False)")
    print(f"  Empty secret error logged: {'FISHINGMAILS_AUTH_SECRET must be explicitly set' in logs_s2}")
    print(f"  Result: {'PASS' if pass_s2 else 'FAIL'}")
    results.append(("Secret S2 (Empty in Production)", "PASS" if pass_s2 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_s2)

    # S3: Short secret (< 32 chars) in production
    print("\n[TEST S3] Production mode with short secret (< 32 chars)")
    port_s3 = 8031
    proc_s3, logs_s3, ok_s3 = start_server_instance(port_s3, {"FISHINGMAILS_ENV": "production", "FISHINGMAILS_AUTH_SECRET": "short-secret-16b"})
    pass_s3 = (not ok_s3 and "at least 32 characters" in logs_s3)
    print(f"  Started: {ok_s3} (Exp False)")
    print(f"  Short secret error logged: {'at least 32 characters' in logs_s3}")
    print(f"  Result: {'PASS' if pass_s3 else 'FAIL'}")
    results.append(("Secret S3 (Short Secret <32 chars in Prod)", "PASS" if pass_s3 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_s3)

    # S4: Obvious default secret from .env.example
    print("\n[TEST S4] Production mode with default template secret from .env.example")
    port_s4 = 8032
    proc_s4, logs_s4, ok_s4 = start_server_instance(
        port_s4,
        {"FISHINGMAILS_ENV": "production", "FISHINGMAILS_AUTH_SECRET": "your-secure-32-byte-secret-key-goes-here-change-in-production"}
    )
    pass_s4 = (not ok_s4 and "insecure or missing authentication secret" in logs_s4)
    print(f"  Started: {ok_s4} (Exp False)")
    print(f"  Insecure default error logged: {'insecure or missing authentication secret' in logs_s4}")
    print(f"  Result: {'PASS' if pass_s4 else 'FAIL'}")
    results.append(("Secret S4 (Default .env.example Secret in Prod)", "PASS" if pass_s4 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_s4)

    # S5: Dev fallback secret used in production
    print("\n[TEST S5] Production mode with dev fallback secret")
    port_s5 = 8033
    proc_s5, logs_s5, ok_s5 = start_server_instance(
        port_s5,
        {"FISHINGMAILS_ENV": "production", "FISHINGMAILS_AUTH_SECRET": "fishingmails-dev-test-secret-minimum-32-chars-long-for-local-testing"}
    )
    pass_s5 = (not ok_s5 and "insecure or missing authentication secret" in logs_s5)
    print(f"  Started: {ok_s5} (Exp False)")
    print(f"  Insecure dev secret error logged: {'insecure or missing authentication secret' in logs_s5}")
    print(f"  Result: {'PASS' if pass_s5 else 'FAIL'}")
    results.append(("Secret S5 (Dev Secret in Prod)", "PASS" if pass_s5 else "FAIL", "Startup rejected (fail-closed)"))
    stop_server_instance(proc_s5)

    # S6: Development mode with unset secret (uses dev fallback safely)
    print("\n[TEST S6] Development mode with unset secret (uses dev fallback bounded)")
    port_s6 = 8034
    proc_s6, logs_s6, ok_s6 = start_server_instance(
        port_s6,
        {"FISHINGMAILS_ENV": "development", "FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK": "false"}
    )
    if not ok_s6:
        print(f"  FAIL: Server failed to start: {logs_s6[:200]}")
        results.append(("Secret S6 (Dev Mode Unset Secret)", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_s6}"
            r_mint = requests.post(f"{base}/api/v1/auth/token", json={"subject_id": "dev_analyst", "tenant_id": "tenant-dev"})
            pass_s6 = (r_mint.status_code == 200 and "access_token" in r_mint.json())
            print(f"  Dev token mint: {r_mint.status_code} (Exp 200)")
            print(f"  Result: {'PASS' if pass_s6 else 'FAIL'}")
            results.append(("Secret S6 (Dev Mode Unset Secret)", "PASS" if pass_s6 else "FAIL", f"Mint={r_mint.status_code}"))
        finally:
            stop_server_instance(proc_s6)

    # ------------------------------------------------------------------
    # SECTION 6: PROVE DEFAULT-SECURE PROPERTY
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SECTION 6: PROVE DEFAULT-SECURE PROPERTY")
    print("=" * 70)
    print("Starting server with ZERO auth-related environment variables except a valid key...")
    port_def = 8035
    proc_def, logs_def, ok_def = start_server_instance(port_def, {"FISHINGMAILS_AUTH_SECRET": VALID_SECRET})
    if not ok_def:
        print(f"  FAIL: Server failed to start: {logs_def[:200]}")
        results.append(("Default-Secure Invariant", "FAIL", "Server failed to start"))
    else:
        try:
            base = f"http://127.0.0.1:{port_def}"
            # 1. Which environment does it enter?
            r_mode = requests.get(f"{base}/api/v1/mode")
            mode = r_mode.json().get("mode") if r_mode.status_code == 200 else "UNKNOWN"
            # 2. Does it require JWT?
            r_unauth_inc = requests.get(f"{base}/api/v1/incidents")
            # 3. Can unauthenticated reach local_analyst?
            # If it could reach local_analyst, r_unauth_inc would be 200!
            # 4. Can /api/v1/auth/token mint a credential?
            r_mint_unauth = requests.post(f"{base}/api/v1/auth/token", json={})
            # 5. Can /api/v1/incidents be accessed?
            # Covered by r_unauth_inc (401)
            pass_def = (mode == "PRODUCTION" and r_unauth_inc.status_code == 401 and r_mint_unauth.status_code == 401)
            print(f"  1. Operating Mode Entered: {mode} (Exp PRODUCTION)")
            print(f"  2. Unauthenticated Incidents Status: {r_unauth_inc.status_code} (Exp 401)")
            print(f"  3. Unauthenticated Token Mint Status: {r_mint_unauth.status_code} (Exp 401)")
            print(f"  Result: {'PASS' if pass_def else 'FAIL'}")
            results.append(("Default-Secure Invariant", "PASS" if pass_def else "FAIL", f"Mode={mode}, Incidents={r_unauth_inc.status_code}, Mint={r_mint_unauth.status_code}"))
        finally:
            stop_server_instance(proc_def)

    # ------------------------------------------------------------------
    # FINAL SUMMARY
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("FINAL CONFIGURATION CONSISTENCY AUDIT SUMMARY")
    print("=" * 70)
    passed_count = sum(1 for _, res, _ in results if res == "PASS")
    total_count = len(results)
    for name, res, detail in results:
        print(f"  [{res}] {name}: {detail}")
    print(f"\nTotal: {total_count} | Passed: {passed_count} | Failed: {total_count - passed_count}")

    if passed_count == total_count:
        print("\nVERDICT: CONFIGURATION CONSISTENCY PASSED")
        return 0
    else:
        print("\nVERDICT: CONFIGURATION CONSISTENCY FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(run_configuration_audit())
