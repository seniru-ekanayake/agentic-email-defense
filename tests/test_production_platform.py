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

# Ensure test auth secret and env are configured
os.environ.setdefault("FISHINGMAILS_ENV", "test")
os.environ.setdefault("FISHINGMAILS_AUTH_SECRET", "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min")
os.environ.setdefault("FISHINGMAILS_APPROVAL_HMAC_SECRET", "test-hmac-secret-key-that-is-long-enough")

from apps.server import app, investigation_service, prod_manager
from apps.agents.core.state_machine import AgentState, InvestigationStateMachine
from apps.agents.core.event_system import EventStreamManager
from apps.agents.core.trust_score import TrustScoreCalculator
from apps.agents.core.production_manager import PlatformMode


class TestProductionPlatform(unittest.TestCase):

    def setUp(self):
        from apps.agents.core.security_principal import create_principal_token
        token = create_principal_token(
            subject_id="test_analyst",
            tenant_id="tenant-enterprise-prod",
            roles=["SOC_ANALYST", "INCIDENT_RESPONDER", "ADMIN"]
        )
        self.client = TestClient(app, headers={"Authorization": f"Bearer {token}"})
        admin = create_principal_token(subject_id="admin", tenant_id="tenant-enterprise-prod", roles=["SOC_ADMIN"])
        self.admin_headers = {"Authorization": f"Bearer {admin}"}
        self.sample_path = "packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"

    def test_production_mode_purity(self):
        """Verify strict production purity rules."""
        prod_manager.set_mode(PlatformMode.PRODUCTION)
        self.assertTrue(prod_manager.is_production())
        self.assertFalse(prod_manager.allows_fixtures())
        self.assertFalse(prod_manager.allows_mocks())

        # Attempting to detonate synthetic demo in production must be forbidden
        resp = self.client.post("/api/v1/demo")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("only available in DEMO or TEST mode", resp.json()["detail"])

    def test_mode_switching(self):
        """Verify switching to DEMO mode permits synthetic detonation."""
        prod_manager.set_mode(PlatformMode.TEST)
        resp = self.client.post("/api/v1/mode", json={"mode": "DEMO"}, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["mode"], "DEMO")
        self.assertTrue(prod_manager.allows_fixtures())

        # Demo sample detonation now allowed
        demo_resp = self.client.post("/api/v1/demo")
        self.assertEqual(demo_resp.status_code, 200)
        self.assertEqual(demo_resp.json()["severity"], "CRITICAL")

        # PRODUCTION is chosen by FISHINGMAILS_ENV, never at runtime
        resp = self.client.post("/api/v1/mode", json={"mode": "PRODUCTION"}, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)
        prod_manager.set_mode(PlatformMode.TEST)

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

    def test_agent_trust_score(self):
        """Verify mathematically inspectable agent trust score."""
        resp = self.client.get("/api/v1/trust-score")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["overall_score"], 0.0)
        self.assertLessEqual(data["overall_score"], 100.0)
        self.assertEqual(len(data["components"]), 5)

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
        # search-ms/UNC links are not attributed to a CVE that the evidence does not support
        self.assertIsNone(inc["cve"])

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
        self.assertGreaterEqual(len(inc["decision_trace"]), 2)
        for dec in inc["decision_trace"]:
            self.assertTrue(dec["decision_id"].startswith("D-"))
            self.assertTrue(dec["observed"])
            self.assertTrue(dec["reason"])
            self.assertTrue(dec["impact"])

        # Tool Executions
        self.assertIn("tool_executions", inc)
        self.assertGreaterEqual(len(inc["tool_executions"]), 1)

        # Forensic Audit: What Actually Happened?
        audit = inc["forensic_audit"]
        self.assertGreaterEqual(len(audit["files_read"]), 1)
        self.assertEqual(len(audit["tools_executed"]), len(inc["tool_executions"]))
        self.assertEqual(audit["llm_calls"], [])  # no LLM configured in tests, and none is claimed

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
        evidence_ids = {e["evidence_id"] for e in inc["evidence_items"]}
        for adj in prov["adjustments"]:
            self.assertIn(adj["evidence_id"], evidence_ids)

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

        # No mail gateway configured: the approval is consumed but the dispatch is reported as failed
        app_resp = self.client.post(f"/api/v1/approve/{token}")
        self.assertEqual(app_resp.status_code, 502)
        self.assertEqual(app_resp.json()["detail"]["output"]["status"], "NOT_CONFIGURED")
        self.assertEqual(self.client.post(f"/api/v1/approve/{token}").status_code, 400)


if __name__ == "__main__":
    unittest.main()
