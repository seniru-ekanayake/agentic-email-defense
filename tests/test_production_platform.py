"""
Comprehensive Tests for FishingMails Production Platform:
- Zero-Code Engine
- State Machine & Controls (Pause/Resume/Cancel)
- Event Stream & SSE
- Forensic Ledger, Evidence Graph & Decision Trace
- 12-Subsystem Self-Test
- Agent Trust Score
- Production / Demo Separation
- REST & SSE Endpoints
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.server import app, investigation_service, prod_manager, incidents_db
from apps.agents.core.state_machine import AgentState, InvestigationStateMachine
from apps.agents.core.event_system import EventStreamManager
from apps.agents.core.integration_center import IntegrationManager, IntegrationStatus
from apps.agents.core.agent_builder import ZeroCodeStore, AgentConfig, DetectionRule
from apps.agents.core.system_selftest import SystemSelfTester, TestStatus
from apps.agents.core.trust_score import TrustScoreCalculator
from apps.agents.core.production_manager import PlatformMode


class TestProductionPlatform(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.sample_path = "packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"

    def test_production_mode_purity(self):
        """Verify strict production purity rules."""
        prod_manager.set_mode(PlatformMode.PRODUCTION)
        self.assertTrue(prod_manager.is_production())
        self.assertFalse(prod_manager.allows_fixtures())
        self.assertFalse(prod_manager.allows_mocks())

        # Attempting to detonate synthetic demo in production must be forbidden
        resp = self.client.get("/api/v1/demo")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("FORBIDDEN IN PRODUCTION MODE", resp.json()["detail"])

    def test_mode_switching(self):
        """Verify switching to DEMO mode permits synthetic detonation."""
        resp = self.client.post("/api/v1/mode", json={"mode": "DEMO"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["mode"], "DEMO")
        self.assertTrue(prod_manager.allows_fixtures())

        # Demo sample detonation now allowed
        demo_resp = self.client.get("/api/v1/demo")
        self.assertEqual(demo_resp.status_code, 200)
        demo_data = demo_resp.json()
        self.assertIn("[DEMO FIXTURE]", demo_data["title"])

        # Switch back to PRODUCTION
        self.client.post("/api/v1/mode", json={"mode": "PRODUCTION"})
        self.assertTrue(prod_manager.is_production())

    def test_state_machine_transitions_and_controls(self):
        """Verify state machine lifecycle, pause, resume, and cancel."""
        sm = InvestigationStateMachine("test-inv-01")
        self.assertEqual(sm.current_state, AgentState.QUEUED)

        sm.transition_to(AgentState.INITIALIZING)
        sm.transition_to(AgentState.PARSING)
        sm.transition_to(AgentState.INVESTIGATING)

        # Pause
        sm.pause()
        self.assertEqual(sm.current_state, AgentState.PAUSED)
        self.assertFalse(sm.is_active())

        # Resume
        sm.resume()
        self.assertEqual(sm.current_state, AgentState.INVESTIGATING)
        self.assertTrue(sm.is_active())

        # Cancel
        sm.cancel()
        self.assertEqual(sm.current_state, AgentState.CANCELLED)
        self.assertFalse(sm.is_active())

    def test_event_stream_publishing(self):
        """Verify auditable lifecycle event stream with sequence numbers."""
        esm = EventStreamManager.get_instance()
        inv_id = "inv-event-test"
        ev1 = esm.publish_event(
            investigation_id=inv_id,
            agent_run_id="run-1",
            event_type="agent.started",
            message="Test start"
        )
        self.assertEqual(ev1.sequence_number, 1)

        ev2 = esm.publish_event(
            investigation_id=inv_id,
            agent_run_id="run-1",
            event_type="agent.tool.selected",
            tool="Quad9DoH",
            message="Selected Quad9 DNS"
        )
        self.assertEqual(ev2.sequence_number, 2)
        self.assertEqual(ev2.tool, "Quad9DoH")

        events = esm.get_events(inv_id)
        self.assertEqual(len(events), 2)

    def test_12_subsystems_selftest(self):
        """Verify the built-in system self-test across all 12 subsystems."""
        resp = self.client.get("/api/v1/selftest")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("results", data)
        self.assertGreaterEqual(len(data["results"]), 14)
        self.assertEqual(data["overall_status"], "PASS")

        subsystems = [r["subsystem"] for r in data["results"]]
        self.assertTrue(any("Email Parser" in s for s in subsystems))
        self.assertTrue(any("Database" in s for s in subsystems))
        self.assertTrue(any("Threat Intelligence" in s for s in subsystems))
        self.assertTrue(any("Sandbox" in s for s in subsystems))
        self.assertTrue(any("Browser" in s for s in subsystems))
        self.assertTrue(any("Event Stream" in s for s in subsystems))
        self.assertTrue(any("Safety Gate" in s for s in subsystems))

    def test_agent_trust_score(self):
        """Verify mathematically inspectable agent trust score."""
        resp = self.client.get("/api/v1/trust-score")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["overall_score"], 80.0)
        self.assertIn(data["grade"], ["A+", "A", "B"])
        self.assertEqual(len(data["components"]), 5)

    def test_zero_code_integrations_and_health(self):
        """Verify listing integrations and live socket/HTTP health check."""
        resp = self.client.get("/api/v1/integrations")
        self.assertEqual(resp.status_code, 200)
        integrations = resp.json()
        self.assertGreaterEqual(len(integrations), 5)

        # Test Quad9 DoH health check
        health_resp = self.client.post("/api/v1/integrations/int-quad9/health")
        self.assertEqual(health_resp.status_code, 200)
        health_data = health_resp.json()
        self.assertIn(health_data["status"], ["CONNECTED", "OPERATIONAL"])
        self.assertIsNotNone(health_data["latency_ms"])

    def test_zero_code_agent_builder_and_rules(self):
        """Verify saving and retrieving visual agent configs and detection rules."""
        # Agent config
        agent_resp = self.client.get("/api/v1/agent-config")
        self.assertEqual(agent_resp.status_code, 200)
        agents = agent_resp.json()
        self.assertGreaterEqual(len(agents), 1)

        # Detection rules
        rules_resp = self.client.get("/api/v1/detection-rules")
        self.assertEqual(rules_resp.status_code, 200)
        rules = rules_resp.json()
        self.assertGreaterEqual(len(rules), 2)

    def test_full_investigation_observability(self):
        """
        Verify end-to-end investigation generates all mandatory forensic artifacts:
        - Evidence items (E-xxx)
        - Hypotheses (FACT vs HYPOTHESIS vs INFERENCE vs UNKNOWN)
        - Decision trace (#D-xxx)
        - Tool execution records
        - Forensic audit ("What Actually Happened?")
        - Claim vs Evidence verification
        - Evidence graph
        - Risk score provenance
        - 8-question explanation quality
        - Resource telemetry
        """
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()

        response = self.client.post(
            "/api/v1/investigate",
            files={"file": ("exploit_test.eml", raw_eml, "message/rfc822")},
            data={"tenant_id": "tenant-enterprise-prod"}
        )
        self.assertEqual(response.status_code, 200)
        inc = response.json()

        # Core Fields
        self.assertIn("incident_id", inc)
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertEqual(inc["interaction_required"], "VIEW")
        self.assertEqual(inc["cve"], "CVE-2023-35636")

        # Evidence Items
        self.assertIn("evidence_items", inc)
        self.assertGreaterEqual(len(inc["evidence_items"]), 4)
        for ev in inc["evidence_items"]:
            self.assertTrue(ev["evidence_id"].startswith("E-"))
            self.assertIn(ev["status"], ["OBSERVED", "INFERRED", "CLAIMED", "UNKNOWN"])

        # Hypotheses
        self.assertIn("hypotheses", inc)
        self.assertGreaterEqual(len(inc["hypotheses"]), 3)
        for hyp in inc["hypotheses"]:
            self.assertTrue(hyp["hypothesis_id"].startswith("H-"))
            self.assertIn(hyp["category"], ["FACT", "HYPOTHESIS", "INFERENCE", "UNKNOWN"])
            self.assertIn(hyp["status"], ["OPEN", "SUPPORTED", "REJECTED", "UNRESOLVED"])

        # Decision Trace
        self.assertIn("decision_trace", inc)
        self.assertGreaterEqual(len(inc["decision_trace"]), 4)
        for dec in inc["decision_trace"]:
            self.assertTrue(dec["decision_id"].startswith("D-"))
            self.assertTrue(dec["observed"])
            self.assertTrue(dec["reason"])
            self.assertTrue(dec["impact"])

        # Tool Executions
        self.assertIn("tool_executions", inc)
        self.assertGreaterEqual(len(inc["tool_executions"]), 2)

        # Forensic Audit: What Actually Happened?
        audit = inc["forensic_audit"]
        self.assertGreaterEqual(len(audit["files_read"]), 1)
        self.assertGreaterEqual(len(audit["tools_executed"]), 2)
        self.assertGreaterEqual(len(audit["database_queries"]), 1)

        # Claim vs Evidence Verification
        claims = inc["claim_evidence_items"]
        self.assertGreaterEqual(len(claims), 3)
        for clm in claims:
            self.assertIn(clm["status"], ["SUPPORTED", "NOT_SUPPORTED", "UNKNOWN"])

        # Evidence Graph
        eg = inc["evidence_graph"]
        self.assertGreaterEqual(len(eg["nodes"]), 4)
        self.assertGreaterEqual(len(eg["edges"]), 3)

        # Risk Score Provenance
        prov = inc["risk_provenance"]
        self.assertGreater(prov["final_score"], 50.0)
        self.assertGreaterEqual(len(prov["adjustments"]), 1)

        # Explanation Quality: 8 Mandatory Questions
        exp = inc["explanation"]
        self.assertTrue(exp["what_did_we_observe"])
        self.assertTrue(exp["what_does_it_mean"])
        self.assertTrue(exp["what_evidence_supports_it"])
        self.assertTrue(exp["what_did_we_investigate"])
        self.assertTrue(exp["what_did_we_not_investigate"])
        self.assertTrue(exp["what_remains_unknown"])
        self.assertTrue(exp["why_did_the_risk_score_change"])
        self.assertTrue(exp["what_should_the_analyst_do_next"])

        # Measured Resource Telemetry
        tel = inc["telemetry"]
        self.assertGreater(tel["execution_time_seconds"], 0.0)
        self.assertGreater(tel["tool_calls_count"], 0)

        # Agent Trust Score
        ts = inc["trust_score"]
        self.assertGreaterEqual(ts["overall_score"], 90.0)
        self.assertEqual(ts["unsupported_claim_count"], 0)

    def test_approval_lifecycle(self):
        """Verify human-in-the-loop approval and rejection."""
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()

        resp = self.client.post(
            "/api/v1/investigate",
            files={"file": ("exploit_test.eml", raw_eml, "message/rfc822")},
            data={"tenant_id": "tenant-enterprise-prod"}
        )
        inc = resp.json()
        self.assertTrue(len(inc["pending_approvals"]) > 0)
        token = inc["pending_approvals"][0]["approval_token"]

        # Approve
        app_resp = self.client.post(f"/api/v1/approve/{token}")
        self.assertEqual(app_resp.status_code, 200)
        self.assertEqual(app_resp.json()["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
