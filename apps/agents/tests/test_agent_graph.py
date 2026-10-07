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

        # 2. Verify evidence-based verdict (forced-authentication URIs observed by the parser)
        verdict = final_state["verdict"]
        inv = final_state["investigation_state"]
        evidence_types = {e.evidence_type for e in inv.evidence.values()}
        self.assertTrue(evidence_types & {"MONIKER_URI", "UNC_PATH"})
        self.assertTrue(verdict.forced_authentication)
        self.assertEqual(verdict.verdict, "MALICIOUS")
        self.assertTrue(all(f.evidence_id in inv.evidence for f in verdict.factors))

        # 3. No CVE is invented: search-ms/UNC links are not attributed to a specific CVE
        self.assertIsNone(verdict.cve)
        self.assertEqual(final_state.get("vulnerability_context", []), [])

        # 4. The recipient domain is recorded without fabricated fingerprinting
        asset_ctx = final_state.get("asset_context", [])
        self.assertEqual(len(asset_ctx), 1)
        self.assertEqual(asset_ctx[0]["product"], "Unknown (not fingerprinted)")
        self.assertEqual(asset_ctx[0]["associated_cves"], [])

        # 5. Report and attack chain reflect observed evidence only
        incident = final_state.get("incident_report")
        self.assertEqual(incident["interaction_required"], "VIEW")
        self.assertIn(incident["severity"], ["HIGH", "CRITICAL"])
        stages = [s["stage"] for s in incident["attack_chain"]]
        self.assertIn("DELIVERY", stages)
        self.assertIn("CREDENTIAL_ACCESS", stages)

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
        self.assertIn(approved_result.output["status"], ["NOT_CONFIGURED", "SUCCESS"])


if __name__ == "__main__":
    unittest.main()
