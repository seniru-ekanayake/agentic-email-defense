"""
End-to-end scenario through the HTTP API: a forced-authentication phishing email is investigated,
containment is proposed, a responder approves it, and the configured mail-gateway connector
receives the quarantine request. A benign email in the same tenant produces no actions.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

from apps.server import app
from apps.agents.core.security_principal import create_principal_token

SAMPLE = "packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"
BENIGN = "tests/fixtures/benign-control-73922.eml"


def _headers(roles):
    return {"Authorization": "Bearer " + create_principal_token("e2e", "tenant-e2e", roles)}


def test_phishing_to_confirmed_quarantine(monkeypatch):
    received = []

    class MailGateway(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"quarantined_count": 1}')

    gateway = HTTPServer(("127.0.0.1", 0), MailGateway)
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    monkeypatch.setenv("MAIL_GATEWAY_URL", f"http://127.0.0.1:{gateway.server_port}/quarantine")

    client = TestClient(app)
    analyst, responder = _headers(["SOC_ANALYST"]), _headers(["INCIDENT_RESPONDER"])
    try:
        with open(BENIGN, "rb") as f:
            benign = client.post("/api/v1/investigate", headers=analyst, files={"file": ("benign.eml", f.read())}).json()
        assert benign["severity"] == "LOW" and benign["pending_approvals"] == []

        with open(SAMPLE, "rb") as f:
            inc = client.post("/api/v1/investigate", headers=analyst, files={"file": ("phish.eml", f.read())}).json()
        assert inc["severity"] == "CRITICAL"
        assert inc["threat_category"] == "Forced Authentication (Moniker/UNC)"
        assert {p["tool_name"] for p in inc["pending_approvals"]} == {"quarantine_email", "revoke_session"}

        listed = client.get("/api/v1/incidents", headers=analyst).json()
        assert {i["incident_id"] for i in listed} >= {inc["incident_id"], benign["incident_id"]}

        token = next(p["approval_token"] for p in inc["pending_approvals"] if p["tool_name"] == "quarantine_email")
        r = client.post(f"/api/v1/approve/{token}", headers=responder)
        assert r.status_code == 200 and r.json()["status"] == "DISPATCHED"
        assert received == [{"action": "quarantine_email", "parameters": {"message_id": inc["pending_approvals"][0]["parameters"]["message_id"],
                                                                         "mailbox": inc["recipient"]}, "timestamp": received[0]["timestamp"]}]

        audit = client.get("/api/v1/audit-logs", headers=analyst).json()
        assert any(a["action"] == "APPROVAL_ATTEMPT" and a["details"]["success"] for a in audit)
    finally:
        gateway.shutdown()
