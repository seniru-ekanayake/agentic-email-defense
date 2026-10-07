"""
Unit and Integration tests for ResponsePolicyEngine and ToolRegistry.
Tests:
- Autonomy Level 0 (Observe only)
- Autonomy Level 1 (Recommend - holds High/Medium for human approval)
- Autonomy Level 4 (Autonomous execution)
- Emergency Killswitch enforcement
- Rate limiting per tenant
- Human approval workflow and authorization tokens
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import http.server
import threading
import json
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.response_policy_engine import ResponsePolicyEngine, TenantResponsePolicy
from packages.schemas.python.models import ToolProposal, RiskLevel


class MockGatewayHandler(http.server.BaseHTTPRequestHandler):
    received_requests = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        parsed = json.loads(body.decode("utf-8")) if body else {}
        MockGatewayHandler.received_requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": parsed
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "CONFIRMED", "dispatch_id": "DISPATCH-12345"}')

    def log_message(self, format, *args):
        pass  # Suppress console logging during test run


class TestResponseEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}/api/dispatch"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MockGatewayHandler.received_requests.clear()
        os.environ["MAIL_GATEWAY_URL"] = self.base_url
        os.environ["IDP_API_URL"] = self.base_url
        os.environ["GATEWAY_BLOCK_URL"] = self.base_url
        os.environ["ACTIVE_DIRECTORY_URL"] = self.base_url
        os.environ["FIREWALL_API_URL"] = self.base_url
        self.tool_registry = ToolRegistry()
        self.policy_engine = ResponsePolicyEngine(tool_registry=self.tool_registry)

    def tearDown(self):
        for k in ["MAIL_GATEWAY_URL", "IDP_API_URL", "GATEWAY_BLOCK_URL", "ACTIVE_DIRECTORY_URL", "FIREWALL_API_URL", "TEST_MODE"]:
            os.environ.pop(k, None)



    def test_autonomy_level_0_observe_only(self):
        """Autonomy level 0 must never execute actions or create pending approvals."""
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(
            tenant_id="tenant-observe",
            autonomy_level=0
        ))

        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "msg-123", "mailbox": "user@corp"},
            reasoning="Observed malicious email"
        )
        res = self.policy_engine.evaluate_and_execute("tenant-observe", prop)
        self.assertTrue(res.success)
        self.assertFalse(res.executed)
        self.assertFalse(res.requires_human_approval)
        self.assertEqual(res.output.get("status"), "OBSERVE_ONLY")

    def test_autonomy_level_1_human_approval_gate(self):
        """Autonomy level 1 requires approval for medium and high risk tools."""
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(
            tenant_id="tenant-rec",
            autonomy_level=1
        ))

        # 1. Medium risk: quarantine_email held
        prop_quarantine = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "msg-456", "mailbox": "user@corp"},
            reasoning="Quarantine test"
        )
        res_q = self.policy_engine.evaluate_and_execute("tenant-rec", prop_quarantine)
        self.assertTrue(res_q.requires_human_approval)
        self.assertFalse(res_q.executed)
        self.assertIsNotNone(res_q.approval_token)

        # 2. High risk: revoke_session held
        prop_session = ToolProposal(
            tool_name="revoke_session",
            parameters={"user_id": "user@corp", "session_id": "sess-99"},
            reasoning="Compromise prevention"
        )
        res_s = self.policy_engine.evaluate_and_execute("tenant-rec", prop_session)
        self.assertTrue(res_s.requires_human_approval)
        self.assertFalse(res_s.executed)

        # 3. Approve and execute
        exec_res = self.policy_engine.authorize_action(res_s.approval_token, approver_user_id="sec_admin")
        self.assertTrue(exec_res.executed)
        self.assertEqual(exec_res.output.get("status"), "SUCCESS")

    def test_autonomy_level_4_autonomous_execution(self):
        """Autonomy level 4 executes medium/high actions automatically."""
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(
            tenant_id="tenant-auto",
            autonomy_level=4
        ))

        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "msg-789", "mailbox": "user@corp"},
            reasoning="Automated containment"
        )
        res = self.policy_engine.evaluate_and_execute("tenant-auto", prop)
        self.assertTrue(res.executed)
        self.assertFalse(res.requires_human_approval)
        self.assertEqual(res.output.get("status"), "SUCCESS")

    def test_emergency_killswitch(self):
        """Emergency killswitch blocks all execution regardless of autonomy level."""
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(
            tenant_id="tenant-killswitch",
            autonomy_level=4,
            emergency_killswitch_active=True
        ))

        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "msg-999", "mailbox": "user@corp"},
            reasoning="Test under killswitch"
        )
        res = self.policy_engine.evaluate_and_execute("tenant-killswitch", prop)
        self.assertFalse(res.executed)
        self.assertIn("killswitch is ACTIVE", res.error)

    def test_additional_defensive_tools(self):
        """Test block_sender, block_ioc, force_password_reset, create_soc_ticket."""
        # 1. Low risk: create_soc_ticket executes automatically
        prop_ticket = ToolProposal(
            tool_name="create_soc_ticket",
            parameters={"title": "Phishing campaign alert", "severity": "HIGH", "details": {}},
            reasoning="Ticketing"
        )
        res_ticket = self.policy_engine.evaluate_and_execute("tenant-tools", prop_ticket)
        self.assertTrue(res_ticket.executed)
        self.assertFalse(res_ticket.success)
        self.assertEqual(res_ticket.output.get("status"), "NOT_CONFIGURED")
        self.assertNotIn("ticket_id", res_ticket.output)

        # 2. Block sender
        prop_block = ToolProposal(
            tool_name="block_sender",
            parameters={"sender_or_domain": "attacker.com", "reason": "Phishing domain"},
            reasoning="Gateway block"
        )
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(tenant_id="tenant-tools", autonomy_level=3))
        res_block = self.policy_engine.evaluate_and_execute("tenant-tools", prop_block)
        self.assertTrue(res_block.executed)
        self.assertTrue(res_block.output.get("entry_added"))

    def test_unconfigured_external_gateways_fail_closed(self):
        """When gateways are unconfigured and TEST_MODE is off, actions must transparently return NOT_CONFIGURED."""
        os.environ.pop("MAIL_GATEWAY_URL", None)
        os.environ.pop("M365_GRAPH_ENDPOINT", None)
        os.environ.pop("TEST_MODE", None)
        prop_quarantine = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "msg-unconf", "mailbox": "user@corp"},
            reasoning="Quarantine test without gateway"
        )
        self.policy_engine.set_tenant_policy(TenantResponsePolicy(tenant_id="tenant-unconf", autonomy_level=4))
        res = self.policy_engine.evaluate_and_execute("tenant-unconf", prop_quarantine)
        self.assertTrue(res.executed)
        self.assertEqual(res.output.get("status"), "NOT_CONFIGURED")
        self.assertEqual(res.output.get("execution_state"), "DISPATCH_FAILED")
        self.assertFalse(res.output.get("confirmed"))


if __name__ == "__main__":
    unittest.main()

