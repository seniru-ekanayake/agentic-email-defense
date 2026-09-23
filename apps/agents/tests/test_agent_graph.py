"""
Integration tests for the complete LangGraph Agent Workflow.
Verifies end-to-end execution from raw EML ingestion to investigation,
attack chain reconstruction, explainable scoring, and response gating.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from apps.agents.graph import SecurityGraph
from packages.schemas.python.models import SecurityState


class TestAgentGraph(unittest.TestCase):

    def setUp(self):
        self.graph = SecurityGraph()
        self.sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"))

    def test_end_to_end_agent_workflow(self):
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()

        initial_state: SecurityState = {
            "tenant_id": "tenant-enterprise-demo",
            "workflow_id": "wf-test-001",
            "autonomy_level": 1,  # Level 1: Recommend (Requires human approval for High/Medium)
            "raw_eml": raw_eml
        }

        final_state = self.graph.run(initial_state)

        # 1. Verify Ingestion & Classification
        self.assertEqual(final_state.get("data_classification"), "CONFIDENTIAL")
        self.assertIsNotNone(final_state.get("email_representation"))

        # 2. Verify Sandbox Behavioral Telemetry
        sandbox = final_state.get("sandbox_telemetry")
        self.assertIsNotNone(sandbox)
        self.assertFalse(sandbox["is_benign"])
        self.assertGreater(len(sandbox["rendering_anomalies"]), 0)

        # 3. Verify Vulnerability Research
        vuln_ctx = final_state.get("vulnerability_context", [])
        self.assertGreater(len(vuln_ctx), 0)
        cve_ids = [v["cve"] for v in vuln_ctx]
        self.assertIn("CVE-2023-35636", cve_ids)
        self.assertEqual(vuln_ctx[0]["interaction_required"], "VIEW")

        # 4. Verify Exposed Asset Context
        asset_ctx = final_state.get("asset_context", [])
        self.assertGreater(len(asset_ctx), 0)
        self.assertEqual(asset_ctx[0]["product"], "Microsoft Exchange / Outlook Web Access (OWA)")

        # 5. Verify Investigation & Attack Chain
        incident = final_state.get("incident_report")
        self.assertIsNotNone(incident)
        self.assertEqual(incident["interaction_required"], "VIEW")
        self.assertIn(incident["severity"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(incident["confidence"], 0.85)
        
        # Check Attack Chain Stages
        attack_chain_stages = [s["stage"] for s in incident["attack_chain"]]
        self.assertEqual(attack_chain_stages, [
            "INITIAL_ACCESS",
            "EMAIL_DELIVERY",
            "RENDERING_PARSING",
            "EXPLOITATION",
            "SESSION_IDENTITY",
            "POST_EXPLOITATION"
        ])

        # Check MITRE mapping
        mitre_tech_ids = [t["technique_id"] for t in incident["mitre_techniques"]]
        self.assertIn("T1187", mitre_tech_ids)  # Forced Authentication

        # 6. Verify Response Planning & Policy Gating
        pending_approvals = final_state.get("pending_approvals", [])
        self.assertGreater(len(pending_approvals), 0)
        
        approval_tokens = [p["approval_token"] for p in pending_approvals]
        self.assertTrue(all(tok.startswith("APP-") for tok in approval_tokens))

        # Test approving one of the actions
        approved_result = self.graph.response_node.tool_registry.approve_and_execute(
            approval_token=approval_tokens[0],
            approver_user_id="analyst_bob"
        )
        self.assertTrue(approved_result.executed)
        self.assertEqual(approved_result.output["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
