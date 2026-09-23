"""
End-to-End Test for the Master Demo Scenario:
Synthetic EML -> Deterministic Parser -> Static Analysis -> Simulated Webmail Exposure ->
Simulated Vulnerability (CVE-2023-35636) -> Safe Sandbox Behavior -> Synthetic Identity Event ->
Attack Graph -> LangGraph Investigation -> Incident Creation -> Evidence-based Explanation ->
Response Proposal & Human-in-the-Loop Approval.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from apps.agents.investigation_service import InvestigationService


class TestDemoScenario(unittest.TestCase):

    def setUp(self):
        self.service = InvestigationService()
        self.sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"))

    def test_full_synthetic_demo_scenario(self):
        tenant_id = "tenant-enterprise-demo"

        # 1. Step 1: Simulate Exposed Asset
        asset_rec = self.service.simulate_asset(tenant_id, {
            "host": "owa.enterprise-corp.internal",
            "product": "Microsoft Exchange / Outlook Web Access (OWA)",
            "version": "15.1.2507.17"
        })
        self.assertEqual(asset_rec["host"], "owa.enterprise-corp.internal")

        # 2. Step 2: Ingest Synthetic Rendering Exploit Email
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()

        incident = self.service.simulate_email(tenant_id, raw_eml)

        # 3. Step 3: Simulate Post-Exploitation Identity Telemetry
        identity_event = self.service.simulate_identity_event(tenant_id, {
            "user_id": incident.target_identity,
            "source_ip": "198.51.100.42",
            "event_type": "ANOMALOUS_NTLM_RELAY_AUTHENTICATION"
        })
        self.assertEqual(identity_event["status"], "LOGGED")

        # 4. Step 4: Verify Incident Properties & Exact Demo Requirements
        self.assertIn(incident.severity, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(incident.confidence, 0.90)
        self.assertEqual(incident.target_identity, "cfo@enterprise-corp.internal")
        self.assertEqual(incident.mail_platform, "Microsoft Exchange / Outlook Web Access (OWA)")
        self.assertEqual(incident.exposure_status, "Internet-Facing")
        self.assertEqual(incident.cve, "CVE-2023-35636")
        
        # Mandatory Check: Interaction Required is strictly VIEW
        self.assertEqual(incident.interaction_required, "VIEW")

        # 5. Step 5: Verify Reconstructed Attack Chain
        self.assertEqual(len(incident.attack_chain), 6)
        chain_stages = [s["stage"] for s in incident.attack_chain]
        self.assertEqual(chain_stages, [
            "INITIAL_ACCESS",
            "EMAIL_DELIVERY",
            "RENDERING_PARSING",
            "EXPLOITATION",
            "SESSION_IDENTITY",
            "POST_EXPLOITATION"
        ])

        # 6. Step 6: Verify Attack Graph
        graph_data = self.service.get_attack_graph(incident.incident_id)
        node_labels = [n.label for n in graph_data.nodes]
        self.assertIn("ThreatActor", node_labels)
        self.assertIn("Campaign", node_labels)
        self.assertIn("Email", node_labels)
        self.assertIn("CVE", node_labels)
        self.assertIn("Asset", node_labels)
        self.assertIn("Identity", node_labels)
        self.assertIn("Session", node_labels)

        # 7. Step 7: Verify Recommended Actions & Human Approval Gate
        self.assertGreater(len(incident.pending_approvals), 0)
        approval_token = incident.pending_approvals[0]["approval_token"]
        self.assertTrue(approval_token.startswith("APP-"))

        # 8. Step 8: Execute Human-in-the-Loop Response
        exec_result = self.service.security_graph.response_node.tool_registry.approve_and_execute(
            approval_token=approval_token,
            approver_user_id="lead_soc_analyst"
        )
        self.assertTrue(exec_result.executed)
        self.assertEqual(exec_result.output["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
