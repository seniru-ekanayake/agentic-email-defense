"""
Counterfactual Agenticity Verification Test.
Demonstrates that the InvestigationPlanner dynamically alters its trajectory based on evidence:
- Identical Email + Threat Intel = MALICIOUS -> Stops early with SUFFICIENT_EVIDENCE.
- Identical Email + Threat Intel = UNKNOWN -> Dynamically branches to secondary tool (UrlSandboxRunner).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.core.investigation_state import (
    InvestigationState,
    Artifact,
    Evidence,
    ToolExecution
)
from apps.agents.core.investigation_planner import RuleBasedPlanner, HybridPlanner
from apps.agents.core.tool_registry import ToolRegistry


class TestCounterfactualAgenticity(unittest.TestCase):

    def setUp(self):
        self.planner = RuleBasedPlanner()
        self.tool_registry = ToolRegistry.get_instance()
        self.available_tools = self.tool_registry.get_tool_definitions()
        self.permissions = ["email.parse", "threat_intel.query", "attachment.inspect", "sandbox.browser_execute", "network.dns_lookup", "telemetry.query"]

    def _build_base_state(self) -> InvestigationState:
        state = InvestigationState(
            incident_id="INC-COUNTERFACTUAL-TEST",
            tenant_id="tenant-counterfactual",
            autonomy_level=1,
            remaining_budget_steps=10
        )
        state.artifacts.append(Artifact(artifact_type="EML_RAW", raw_data=1024, location="RAW_EML"))
        state.artifacts.append(Artifact(artifact_type="MIME_HEADER", raw_data={"subject": "Account Alert"}, location="HEADERS"))
        state.artifacts.append(Artifact(artifact_type="BODY_PLAIN", raw_data="Click here to verify login.", location="BODY"))
        state.artifacts.append(Artifact(artifact_type="URL_STRING", raw_data="http://suspicious-login-portal.cc/auth", location="BODY_URL"))

        # Base evidence
        state.evidence["E-101"] = Evidence(
            id="E-101",
            evidence_type="MIME_HEADER",
            value="From: security@service.net | To: user@corp.com",
            source="DeterministicMimeParser"
        )
        state.evidence["E-102"] = Evidence(
            id="E-102",
            evidence_type="AUTHENTICATION",
            value="SPF: Pass / DMARC: Aligned",
            source="MimeParser.HeaderAnalyzer"
        )
        # Baseline reconnaissance already completed
        state.executed_tools.append(ToolExecution(
            tool_name="UnicodeAnalyzer",
            status="COMPLETED",
            duration_ms=1.5,
            output_summary="No RTLO or zero-width tags detected."
        ))
        state.executed_tools.append(ToolExecution(
            tool_name="dns_spf_dmarc_recon",
            status="COMPLETED",
            duration_ms=3.2,
            output_summary="DNS records aligned."
        ))
        return state

    def test_counterfactual_branching(self):
        # 1. Base run: Both scenarios start with identical email and state
        state_malicious = self._build_base_state()
        state_unknown = self._build_base_state()

        # Step 1: Both propose ThreatIntelFeeds first to resolve Q-03
        dec1_mal = self.planner.propose_next_action(state_malicious, self.available_tools, self.permissions)
        dec1_unk = self.planner.propose_next_action(state_unknown, self.available_tools, self.permissions)

        self.assertEqual(dec1_mal.action, "RUN_TOOL")
        self.assertEqual(dec1_mal.tool_name, "ThreatIntelFeeds")
        self.assertEqual(dec1_unk.action, "RUN_TOOL")
        self.assertEqual(dec1_unk.tool_name, "ThreatIntelFeeds")

        # Record tool execution in both states
        # Scenario A: Threat intel feed confirms MALICIOUS reputation
        state_malicious.executed_tools.append(ToolExecution(
            tool_name="ThreatIntelFeeds",
            status="COMPLETED",
            duration_ms=12.4,
            output_summary="Matched URLhaus malware registry: MALICIOUS"
        ))
        state_malicious.evidence["E-103"] = Evidence(
            id="E-103",
            evidence_type="URL_REPUTATION",
            value="MALICIOUS (URLhaus verified payload URL)",
            source="ThreatIntelFeeds"
        )

        # Scenario B: Threat intel feed returns UNKNOWN / NO_RECORDS
        state_unknown.executed_tools.append(ToolExecution(
            tool_name="ThreatIntelFeeds",
            status="COMPLETED",
            duration_ms=11.8,
            output_summary="Zero reputation records: UNKNOWN / CLEAN"
        ))
        state_unknown.evidence["E-103"] = Evidence(
            id="E-103",
            evidence_type="URL_REPUTATION",
            value="UNKNOWN / CLEAN (No records in Quad9 or URLhaus)",
            source="ThreatIntelFeeds"
        )

        # Step 2: Next planner decision under divergent evidence!
        dec2_mal = self.planner.propose_next_action(state_malicious, self.available_tools, self.permissions)
        dec2_unk = self.planner.propose_next_action(state_unknown, self.available_tools, self.permissions)

        print(f"\n[COUNTERFACTUAL TEST] Scenario A (TI=MALICIOUS) Action: {dec2_mal.action} | Stop Reason: {dec2_mal.stop_reason} | Rationale: {dec2_mal.rationale[:60]}")
        print(f"[COUNTERFACTUAL TEST] Scenario B (TI=UNKNOWN) Action: {dec2_unk.action} | Tool: {dec2_unk.tool_name} | Rationale: {dec2_unk.rationale[:60]}")

        # Verification:
        # Scenario A concluded early because evidence was conclusive (STOP)
        self.assertEqual(dec2_mal.action, "STOP")
        self.assertEqual(dec2_mal.stop_reason, "SUFFICIENT_EVIDENCE")

        # Scenario B dynamically branched to UrlSandboxRunner for secondary behavioural analysis
        self.assertEqual(dec2_unk.action, "RUN_TOOL")
        self.assertEqual(dec2_unk.tool_name, "UrlSandboxRunner")

        # The trajectories are strictly divergent based solely on observed tool evidence!
        self.assertNotEqual(dec2_mal.action, dec2_unk.action)


if __name__ == "__main__":
    unittest.main()
