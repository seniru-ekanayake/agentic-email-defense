"""
Unit tests for Foundation Components:
1. LLMGateway runtime validation & fallback
2. DataClassificationEngine privacy boundary & audit
3. ToolRegistry policy gates & human authorization
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from apps.agents.core.llm_gateway import LLMGateway, OpenRouterProvider, LocalOllamaProvider
from apps.agents.core.data_classification import DataClassificationEngine
from apps.agents.core.tool_registry import ToolRegistry
from packages.schemas.python.models import (
    DataClassification,
    ToolProposal,
    RiskLevel
)


class TestFoundation(unittest.TestCase):

    def test_llm_gateway_validation(self):
        """Test that LLMGateway validates capabilities and falls back to safe mock in test mode."""
        gateway = LLMGateway()
        provider = gateway.get_provider(is_confidential=False)
        self.assertIsInstance(provider, OpenRouterProvider)
        
        # Test generation in test/mock mode
        resp = provider.generate(
            system_prompt="You are a security reasoning agent.",
            user_prompt="Evaluate CVE-2023-35636",
            response_schema={"type": "object"}
        )
        self.assertIsNotNone(resp.structured_json)
        self.assertEqual(resp.structured_json.get("interaction_required"), "VIEW")
        self.assertEqual(resp.structured_json.get("cve"), "CVE-2023-35636")

    def test_data_classification_privacy_boundary(self):
        """Test that confidential/restricted data is strictly routed away from external LLMs."""
        engine = DataClassificationEngine()
        
        # Test internal payload
        internal_payload = {
            "headers": {"Subject": "Quarterly Project Review"},
            "body": {"text_plain": "Please review the attached slide deck."}
        }
        cls1 = engine.classify_payload(internal_payload)
        self.assertEqual(cls1, DataClassification.INTERNAL)
        decision1 = engine.evaluate_privacy_policy("tenant-123", cls1)
        self.assertIn("OpenRouterProvider", decision1.allowed_providers)
        self.assertEqual(decision1.selected_provider, "OpenRouterProvider")

        # Test confidential payload
        confidential_payload = {
            "headers": {"Subject": "Confidential Salary Report"},
            "body": {"text_plain": "Here is the confidential salary sheet and private key token."}
        }
        cls2 = engine.classify_payload(confidential_payload)
        self.assertIn(cls2, [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED])
        decision2 = engine.evaluate_privacy_policy("tenant-123", cls2)
        self.assertNotIn("OpenRouterProvider", decision2.allowed_providers)
        self.assertEqual(decision2.selected_provider, "LocalOllamaProvider")
        self.assertIn("local", decision2.policy_reason.lower())

    def test_tool_registry_policy_and_human_approval(self):
        """Test that High and Critical tools cannot execute without authorization when autonomy < 3."""
        registry = ToolRegistry()
        
        # 1. Low risk tool executes automatically
        low_proposal = ToolProposal(
            tool_name="search_mailbox_history",
            parameters={"query": "attacker.com", "days_back": 7},
            reasoning="Searching for related campaign emails"
        )
        res_low = registry.execute_proposal("tenant-123", low_proposal, autonomy_level=1)
        self.assertTrue(res_low.success)
        self.assertTrue(res_low.executed)
        self.assertFalse(res_low.requires_human_approval)

        # 2. High risk tool (revoke_session) held for human approval at autonomy level 1
        high_proposal = ToolProposal(
            tool_name="revoke_session",
            parameters={"user_id": "user@example.com", "session_id": "sess-xyz"},
            reasoning="Potential account takeover detected"
        )
        res_high = registry.execute_proposal("tenant-123", high_proposal, autonomy_level=1)
        self.assertTrue(res_high.success)
        self.assertFalse(res_high.executed)
        self.assertTrue(res_high.requires_human_approval)
        self.assertIsNotNone(res_high.approval_token)

        # 3. Explicit human approval triggers execution
        res_approved = registry.approve_and_execute(res_high.approval_token, approver_user_id="analyst_alice")
        self.assertTrue(res_approved.executed)
        self.assertEqual(res_approved.output["status"], "SUCCESS")

        # 4. Critical risk tool (disable_account) held for human approval
        crit_proposal = ToolProposal(
            tool_name="disable_account",
            parameters={"user_id": "user@example.com", "reason": "Compromise confirmed"},
            reasoning="Prevent data exfiltration"
        )
        res_crit = registry.execute_proposal("tenant-123", crit_proposal, autonomy_level=2)
        self.assertTrue(res_crit.requires_human_approval)
        self.assertFalse(res_crit.executed)


if __name__ == "__main__":
    unittest.main()
