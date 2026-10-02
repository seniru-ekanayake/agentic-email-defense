"""
Production Remediation Verification Suite.
Validates:
1. Production graph integration with authentic adaptive planner loop.
2. Resolution of URL evidence collision (URL_NORMALIZED vs URL_REPUTATION).
3. Real HTTP dispatch for response tools (zero hardcoded success, real network I/O, error states).
4. Safety gate authorization and autonomy enforcement.
5. Multi-tenancy isolation.
6. Authentic decision trace provenance.
"""

import os
import sys
import time
import json
import socket
import http.server
import threading
import unittest
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.graph import SecurityGraph
from apps.agents.core.tool_registry import ToolRegistry, ToolDefinition, RiskLevel, ApprovalRequirement
from apps.agents.core.investigation_planner import RuleBasedPlanner, HybridPlanner
from apps.agents.core.investigation_state import InvestigationState, Artifact, Evidence
from apps.agents.core.response_policy_engine import ResponsePolicyEngine, TenantResponsePolicy
from apps.agents.investigation_service import InvestigationService
from packages.schemas.python.models import ToolProposal


class MockControlledHttpServer(http.server.BaseHTTPRequestHandler):
    """
    Deterministic local HTTP test server that tracks received requests,
    supports programmable status codes, and optional artificial delay.
    """
    received_requests: List[Dict[str, Any]] = []
    response_status: int = 200
    response_body: str = '{"status": "SUCCESS", "message": "Dispatched"}'
    delay_seconds: float = 0.0

    def do_POST(self):
        try:
            if MockControlledHttpServer.delay_seconds > 0:
                time.sleep(MockControlledHttpServer.delay_seconds)

            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            parsed_body = {}
            try:
                parsed_body = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                parsed_body = {"raw": body_bytes.decode("utf-8", errors="replace")}

            normalized_headers = {k.lower(): v for k, v in self.headers.items()}
            MockControlledHttpServer.received_requests.append({
                "path": self.path,
                "headers": normalized_headers,
                "body": parsed_body
            })

            self.send_response(MockControlledHttpServer.response_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(MockControlledHttpServer.response_body.encode("utf-8"))
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError, OSError):
            pass

    def log_message(self, format, *args):
        pass  # Suppress console logging


class TestProductionRemediationSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start local controlled HTTP test server on ephemeral port
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockControlledHttpServer)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}/gateway/dispatch"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MockControlledHttpServer.received_requests.clear()
        MockControlledHttpServer.response_status = 200
        MockControlledHttpServer.response_body = '{"status": "SUCCESS", "message": "Dispatched"}'
        MockControlledHttpServer.delay_seconds = 0.0

        # Clean environment variables
        for key in ["MAIL_GATEWAY_URL", "IDP_API_URL", "ACTIVE_DIRECTORY_URL", "GATEWAY_BLOCK_URL", "FIREWALL_API_URL", "TEST_MODE"]:
            os.environ.pop(key, None)

    def tearDown(self):
        for key in ["MAIL_GATEWAY_URL", "IDP_API_URL", "ACTIVE_DIRECTORY_URL", "GATEWAY_BLOCK_URL", "FIREWALL_API_URL", "TEST_MODE"]:
            os.environ.pop(key, None)

    # -------------------------------------------------------------------------
    # TEST 1: Production Counterfactual (Malicious vs Unknown)
    # -------------------------------------------------------------------------
    def test_production_counterfactual_malicious_vs_unknown(self):
        """
        Enters through the REAL production SecurityGraph.run() path.
        Identical raw EML containing URL_NORMALIZED in baseline.
        Run A: ThreatIntelFeeds returns MALICIOUS -> Q-03 resolved -> STOP (UrlSandboxRunner NEVER executes).
        Run B: ThreatIntelFeeds returns UNKNOWN -> Q-03 unresolved -> UrlSandboxRunner executes.
        """
        raw_eml = (
            b"From: billing@vendor-corp.com\r\n"
            b"To: finance@enterprise.internal\r\n"
            b"Subject: Overdue Invoice Notification\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please download your invoice immediately: http://invoice-portal-update.org/pay\r\n"
        )

        # Run A: ThreatIntelFeeds returns MALICIOUS
        tr_a = ToolRegistry()
        tr_a._handlers["ThreatIntelFeeds"] = lambda p: {"is_malicious": True, "details": "URLhaus flagged phishing domain"}
        graph_a = SecurityGraph(planner=RuleBasedPlanner(), tool_registry=tr_a)
        res_a = graph_a.run({
            "tenant_id": "tenant-counterfactual",
            "autonomy_level": 1,
            "raw_eml": raw_eml,
            "workflow_id": "wf-cf-run-a"
        })
        inv_a = res_a["investigation_state"]
        tools_a = [t.tool_name for t in inv_a.executed_tools]

        # Run B: ThreatIntelFeeds returns UNKNOWN / CLEAN
        tr_b = ToolRegistry()
        tr_b._handlers["ThreatIntelFeeds"] = lambda p: {"is_malicious": False, "details": "Zero reputation records"}
        graph_b = SecurityGraph(planner=RuleBasedPlanner(), tool_registry=tr_b)
        res_b = graph_b.run({
            "tenant_id": "tenant-counterfactual",
            "autonomy_level": 1,
            "raw_eml": raw_eml,
            "workflow_id": "wf-cf-run-b"
        })
        inv_b = res_b["investigation_state"]
        tools_b = [t.tool_name for t in inv_b.executed_tools]

        # Verification of strictly divergent trajectories
        self.assertIn("ThreatIntelFeeds", tools_a)
        self.assertNotIn("UrlSandboxRunner", tools_a, "UrlSandboxRunner must NOT run when ThreatIntel confirms MALICIOUS")
        self.assertEqual(inv_a.stop_reason, "SUFFICIENT_EVIDENCE")

        self.assertIn("ThreatIntelFeeds", tools_b)
        self.assertIn("UrlSandboxRunner", tools_b, "UrlSandboxRunner MUST run when ThreatIntel returns UNKNOWN")
        self.assertNotEqual(tools_a, tools_b)

    # -------------------------------------------------------------------------
    # TEST 2: Production Evidence Semantics
    # -------------------------------------------------------------------------
    def test_production_evidence_semantics(self):
        """
        Verifies that URL_NORMALIZED and URL_REPUTATION are distinct semantic types.
        URL_NORMALIZED must NEVER resolve Q-03.
        get_latest_evidence() must correctly scope by evidence_type and subject.
        """
        state = InvestigationState(
            incident_id="INC-SEMANTICS",
            tenant_id="tenant-semantics",
            remaining_budget_steps=5
        )
        url1 = "http://legit-site.com/home"
        url2 = "http://phish-site.cc/login"

        state.artifacts.append(Artifact(artifact_type="URL_STRING", raw_data=url1, location="BODY"))

        # Add URL_NORMALIZED
        state.evidence["E-1"] = Evidence(
            id="E-1",
            evidence_type="URL_NORMALIZED",
            value=url1,
            subject=url1,
            source="HTMLAnalyzer"
        )

        planner = RuleBasedPlanner()
        planner._update_questions_and_hypotheses(state)

        # Q-03 must remain UNRESOLVED after normalization
        self.assertEqual(state.questions["Q-03"].status, "UNRESOLVED")

        # Adding URL_REPUTATION for url2 must NOT resolve Q-03 for url1
        state.evidence["E-2"] = Evidence(
            id="E-2",
            evidence_type="URL_REPUTATION",
            value="Threat intel reputation: MALICIOUS",
            subject=url2,
            source="ThreatIntelFeeds",
            metadata={"is_malicious": True, "reputation": "MALICIOUS", "url": url2}
        )
        planner._update_questions_and_hypotheses(state)
        # Because target_url is url1, E-2 (for url2) does NOT resolve url1's Q-03
        self.assertEqual(state.questions["Q-03"].status, "UNRESOLVED")

        # Adding URL_REPUTATION matching target_url url1 resolves Q-03
        state.evidence["E-3"] = Evidence(
            id="E-3",
            evidence_type="URL_REPUTATION",
            value="Threat intel reputation: MALICIOUS",
            subject=url1,
            source="ThreatIntelFeeds",
            metadata={"is_malicious": True, "reputation": "MALICIOUS", "url": url1}
        )
        planner._update_questions_and_hypotheses(state)
        self.assertEqual(state.questions["Q-03"].status, "RESOLVED")
        self.assertEqual(state.questions["Q-03"].resolution_evidence_id, "E-3")

        # Verify strongly typed helper
        ev = state.get_latest_evidence("URL_REPUTATION", subject=url1)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.id, "E-3")

    # -------------------------------------------------------------------------
    # TEST 3: Early Stop After Malicious Reputation
    # -------------------------------------------------------------------------
    def test_production_early_stop_after_malicious_reputation(self):
        """
        Verifies that when threat intel returns MALICIOUS, the planner immediately
        stops rather than wasting budget or executing unnecessary sandboxing.
        """
        raw_eml = b"From: attacker@evil.org\r\nTo: victim@corp.com\r\nSubject: Invoice\r\n\r\nLink: http://evil.org/mal"
        tr = ToolRegistry()
        tr._handlers["ThreatIntelFeeds"] = lambda p: {"is_malicious": True, "details": "Known malware hosting"}
        graph = SecurityGraph(planner=RuleBasedPlanner(), tool_registry=tr)

        res = graph.run({"tenant_id": "tenant-test", "autonomy_level": 1, "raw_eml": raw_eml})
        inv = res["investigation_state"]

        self.assertTrue(inv.is_complete)
        self.assertEqual(inv.stop_reason, "SUFFICIENT_EVIDENCE")
        executed_tools = [t.tool_name for t in inv.executed_tools]
        self.assertNotIn("UrlSandboxRunner", executed_tools)

    # -------------------------------------------------------------------------
    # TEST 4: Unknown Reputation Continues to Sandbox
    # -------------------------------------------------------------------------
    def test_production_unknown_reputation_continues_to_sandbox(self):
        """
        Verifies that when threat intel returns UNKNOWN, the planner continues to
        UrlSandboxRunner to perform behavioral DOM analysis.
        """
        raw_eml = b"From: user@service.net\r\nTo: admin@corp.com\r\nSubject: Note\r\n\r\nLink: http://newly-registered-domain.xyz"
        tr = ToolRegistry()
        tr._handlers["ThreatIntelFeeds"] = lambda p: {"is_malicious": False, "details": "No records in feed"}
        graph = SecurityGraph(planner=RuleBasedPlanner(), tool_registry=tr)

        res = graph.run({"tenant_id": "tenant-test", "autonomy_level": 1, "raw_eml": raw_eml})
        inv = res["investigation_state"]

        executed_tools = [t.tool_name for t in inv.executed_tools]
        self.assertIn("ThreatIntelFeeds", executed_tools)
        self.assertIn("UrlSandboxRunner", executed_tools)

    # -------------------------------------------------------------------------
    # TEST 5: Response Tool Not Configured
    # -------------------------------------------------------------------------
    def test_response_not_configured(self):
        """
        Verifies that when gateway URLs are absent from the environment,
        calling response tools returns NOT_CONFIGURED and DISPATCH_FAILED.
        """
        tr = ToolRegistry()
        for tool_name in ["quarantine_email", "revoke_session", "disable_account", "block_sender", "block_ioc"]:
            prop = ToolProposal(
                tool_name=tool_name,
                parameters={"target": "val"},
                reasoning="Testing unconfigured dispatch"
            )
            res = tr.execute_proposal("tenant-unconf", prop, autonomy_level=4)
            self.assertEqual(res.output.get("status"), "NOT_CONFIGURED")
            self.assertEqual(res.output.get("execution_state"), "DISPATCH_FAILED")
            self.assertFalse(res.output.get("confirmed"))

    # -------------------------------------------------------------------------
    # TEST 6: Real HTTP Dispatch Success
    # -------------------------------------------------------------------------
    def test_response_real_http_success(self):
        """
        Verifies that configuring the gateway URL actually performs a real HTTP POST,
        the local server observes the payload, and SUCCESS is returned.
        """
        os.environ["MAIL_GATEWAY_URL"] = self.base_url
        os.environ["MAIL_GATEWAY_TOKEN"] = "token-secret-123"

        tr = ToolRegistry()
        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-9999", "mailbox": "victim@enterprise.com"},
            reasoning="Dispatched quarantine for active incident"
        )
        res = tr.execute_proposal("tenant-dispatch", prop, autonomy_level=4)

        # 1. Assert real network request was received by the server
        self.assertEqual(len(MockControlledHttpServer.received_requests), 1)
        req = MockControlledHttpServer.received_requests[0]
        self.assertEqual(req["body"]["action"], "quarantine_email")
        self.assertEqual(req["body"]["parameters"]["message_id"], "MSG-9999")
        self.assertEqual(req["headers"]["authorization"], "Bearer token-secret-123")

        # 2. Assert tool output reflects real dispatch success
        self.assertEqual(res.output.get("status"), "SUCCESS")
        self.assertEqual(res.output.get("execution_state"), "DISPATCHED")
        self.assertTrue(res.output.get("confirmed"))
        self.assertEqual(res.output.get("http_status"), 200)

    # -------------------------------------------------------------------------
    # TEST 7: Response HTTP Failure (500 and 401)
    # -------------------------------------------------------------------------
    def test_response_http_failure(self):
        """
        Verifies that remote HTTP 500 produces DISPATCH_FAILED and
        remote HTTP 401 produces AUTH_FAILED.
        """
        os.environ["MAIL_GATEWAY_URL"] = self.base_url
        tr = ToolRegistry()

        # Case 1: Server returns HTTP 500
        MockControlledHttpServer.response_status = 500
        MockControlledHttpServer.response_body = '{"error": "Internal Gateway Error"}'
        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-500"},
            reasoning="Testing 500 error dispatch"
        )
        res500 = tr.execute_proposal("tenant-err", prop, autonomy_level=4)
        self.assertEqual(res500.output.get("status"), "DISPATCH_FAILED")
        self.assertEqual(res500.output.get("http_status"), 500)
        self.assertFalse(res500.output.get("confirmed"))

        # Case 2: Server returns HTTP 401
        MockControlledHttpServer.response_status = 401
        MockControlledHttpServer.response_body = '{"error": "Unauthorized"}'
        prop2 = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-401"},
            reasoning="Testing 401 error dispatch"
        )
        res401 = tr.execute_proposal("tenant-err", prop2, autonomy_level=4)
        self.assertEqual(res401.output.get("status"), "AUTH_FAILED")
        self.assertEqual(res401.output.get("http_status"), 401)
        self.assertFalse(res401.output.get("confirmed"))

    # -------------------------------------------------------------------------
    # TEST 8: Response Timeout
    # -------------------------------------------------------------------------
    def test_response_timeout(self):
        """
        Verifies that when the external gateway times out, the tool catches the timeout
        and returns status: TIMEOUT without crashing or reporting success.
        """
        os.environ["MAIL_GATEWAY_URL"] = self.base_url
        # Artificial delay longer than timeout
        MockControlledHttpServer.delay_seconds = 3.5

        tr = ToolRegistry()
        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-TIMEOUT"},
            reasoning="Testing timeout error dispatch"
        )
        res = tr.execute_proposal("tenant-timeout", prop, autonomy_level=4)

        self.assertEqual(res.output.get("status"), "TIMEOUT")
        self.assertEqual(res.output.get("execution_state"), "DISPATCH_FAILED")
        self.assertFalse(res.output.get("confirmed"))

    # -------------------------------------------------------------------------
    # TEST 9: Response Never Reports Success Without Real Dispatch
    # -------------------------------------------------------------------------
    def test_response_never_reports_success_without_dispatch(self):
        """
        Asserts that if no request actually reaches an endpoint, SUCCESS is impossible.
        """
        # Unconfigured endpoint
        os.environ.pop("MAIL_GATEWAY_URL", None)
        tr = ToolRegistry()
        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-FAKE"},
            reasoning="Testing unconfigured failure"
        )
        res = tr.execute_proposal("tenant-test", prop, autonomy_level=4)

        self.assertNotEqual(res.output.get("status"), "SUCCESS")
        self.assertFalse(res.output.get("confirmed"))

    # -------------------------------------------------------------------------
    # TEST 10: Safety Gate Still Blocks Unauthorized Response
    # -------------------------------------------------------------------------
    def test_safety_gate_still_blocks_unauthorized_response(self):
        """
        Verifies that at Autonomy Level 1, quarantine_email requires human approval
        and will NOT execute even if the endpoint is configured.
        """
        os.environ["MAIL_GATEWAY_URL"] = self.base_url
        tr = ToolRegistry()
        policy_engine = ResponsePolicyEngine(tool_registry=tr)
        policy_engine.set_tenant_policy(TenantResponsePolicy(tenant_id="tenant-gate", autonomy_level=1))

        prop = ToolProposal(
            tool_name="quarantine_email",
            parameters={"message_id": "MSG-GATED"},
            reasoning="Testing safety gate authorization"
        )
        res = policy_engine.evaluate_and_execute("tenant-gate", prop)

        self.assertTrue(res.requires_human_approval)
        self.assertFalse(res.executed)
        self.assertIsNotNone(res.approval_token)
        # Server should have received 0 requests because the gate held the action
        self.assertEqual(len(MockControlledHttpServer.received_requests), 0)

    # -------------------------------------------------------------------------
    # TEST 11: Tenant Isolation
    # -------------------------------------------------------------------------
    def test_tenant_isolation_after_remediation(self):
        """
        Verifies that cross-tenant incident retrieval raises PermissionError.
        """
        svc = InvestigationService()
        raw_eml = b"From: test@corp.com\r\nTo: user@corp.com\r\nSubject: Test\r\n\r\nContent"

        incident = svc.run_investigation(tenant_id="tenant-alpha", raw_eml=raw_eml)
        inc_id = incident.incident_id

        # Access with correct tenant succeeds
        inc_ok = svc.get_incident(inc_id, tenant_id="tenant-alpha")
        self.assertEqual(inc_ok.incident_id, inc_id)

        # Access with mismatched tenant raises PermissionError
        with self.assertRaises(PermissionError):
            svc.get_incident(inc_id, tenant_id="tenant-beta")

    # -------------------------------------------------------------------------
    # TEST 12: Decision Trace Matches Real Runtime Events
    # -------------------------------------------------------------------------
    def test_decision_trace_matches_real_runtime_events(self):
        """
        Verifies that the API/service decision trace faithfully reflects real runtime planner
        decisions and tool executions with authentic measured wall-clock latencies.
        """
        raw_eml = b"From: alert@phish.net\r\nTo: target@corp.internal\r\nSubject: Security Alert\r\n\r\nVerify: http://malicious-portal.org/login"

        tr = ToolRegistry()
        tr._handlers["ThreatIntelFeeds"] = lambda p: {"is_malicious": False, "details": "Unknown"}

        svc = InvestigationService()
        svc.security_graph = SecurityGraph(planner=RuleBasedPlanner(), tool_registry=tr)
        incident = svc.run_investigation(tenant_id="tenant-trace", raw_eml=raw_eml)

        decision_trace = incident.decision_trace
        tool_executions = incident.tool_executions

        self.assertTrue(len(decision_trace) >= 2)
        self.assertTrue(len(tool_executions) >= 2)

        # Verify decisions match executed tools
        trace_tools = [d.action for d in decision_trace if not d.action.startswith("STOP")]
        exec_tools = [t.tool_name for t in tool_executions]

        for tt in trace_tools:
            self.assertIn(tt, exec_tools)

        # Verify durations are positive and authentic
        for t in tool_executions:
            self.assertGreater(t.duration_ms, 0.0)


if __name__ == "__main__":
    unittest.main()
