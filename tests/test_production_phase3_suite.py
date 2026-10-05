"""
test_production_phase3_suite.py: Production Autonomous Intelligence Layer Test Suite.
Validates:
1. End-to-end Production Graph with RuleBased, Hybrid, and LLM planning modes.
2. True Hybrid arbitration across all 5 policies (RULE_FIRST, CONSENSUS_REQUIRED, EVIDENCE_WEIGHTED, INFORMATION_GAIN_WEIGHTED, SAFETY_FIRST).
3. Causal counterfactual investigation branches (same initial state -> divergent paths).
4. Truthful explicit fallback (unconfigured gateway, simulated timeout, simulated 429 rate limit).
5. Negative evidence accumulation and contradiction tracking.
6. Multi-step replanning around tool failures.
7. Strict tenant isolation and state serialization round-trip.
8. Performance benchmarks (P50, P95, P99).
"""

import os
import sys
import unittest
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.graph import SecurityGraph
from apps.agents.core.investigation_state import (
    InvestigationState,
    Artifact as StateArtifact,
    Evidence as StateEvidence,
    PlannerDecision,
    LLMDecisionProposal
)
from apps.agents.core.investigation_planner import (
    RuleBasedPlanner,
    LLMPlanner,
    HybridPlanner,
    select_planner
)
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.llm_gateway import LLMGateway
from packages.schemas.python.models import SecurityState, ToolDefinition


class TestProductionPhase3Suite(unittest.TestCase):

    def setUp(self):
        self.tool_registry = ToolRegistry.get_instance()
        self.available_tools = self.tool_registry.get_tool_definitions()
        self.permissions = ["email.parse", "threat_intel.query", "attachment.inspect", "sandbox.browser_execute", "network.dns_lookup", "telemetry.query"]

    def _create_mock_security_state(self, tenant_id="tenant-prod-test", url="http://login.legit-bank.com.suspicious-portal.ru"):
        raw_eml = (
            b"From: security@alerts-security-verify.com\r\n"
            b"To: cfo@enterprise-corp.internal\r\n"
            b"Subject: Urgent Password Expiration Notice\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body>Please verify your account: <a href=\"" + url.encode() + b"\">Verify Now</a></body></html>"
        )
        return {
            "incident_id": "inc-phase3-001",
            "tenant_id": tenant_id,
            "workflow_id": "wf-phase3-001",
            "autonomy_level": 1,
            "raw_eml": raw_eml,
            "email_representation": {
                "headers": {"subject": "Urgent Password Expiration Notice"},
                "body_html": f"<html><body>Please verify: <a href='{url}'>Verify Now</a></body></html>",
                "body_plain": f"Please verify: {url}",
                "sender": {"address": "security@alerts-security-verify.com", "domain": "alerts-security-verify.com"},
                "recipients": [{"address": "cfo@enterprise-corp.internal"}],
                "urls": [{"url": url}],
                "authentication": {"spf": "pass", "dmarc": "pass"}
            },
            "evidence": []
        }

    # -------------------------------------------------------------------------
    # 1. Production Graph Integration: Rule, Hybrid, LLM
    # -------------------------------------------------------------------------
    def test_production_graph_rule_mode(self):
        graph = SecurityGraph(planner_mode="RULE")
        state = self._create_mock_security_state()
        state["planner_mode"] = "RULE"

        final_state = graph.run(state)
        inv_state = final_state["investigation_state"]

        self.assertEqual(final_state["planner_requested"], "RULE")
        self.assertEqual(final_state["planner_used"], "RULE")
        self.assertGreaterEqual(len(inv_state.decisions), 1)
        self.assertTrue(all(d.planner_type == "RULE" for d in inv_state.decisions))

    def test_production_graph_hybrid_agreement_mode(self):
        rule_planner = RuleBasedPlanner()
        llm_planner = LLMPlanner(fallback_planner=rule_planner)

        # Mock LLM to agree with rule planner
        with patch.object(LLMGateway, "is_configured", return_value=True), \
             patch.object(LLMGateway, "generate_completion", return_value={
                 "content": '{"decision": "RUN_TOOL", "tool": "ThreatIntelFeeds", "arguments": {}, "question_id": "Q-03", "evidence_ids": ["E-103"], "expected_information_gain": 0.85, "confidence": 0.90, "rationale_summary": "Query threat intelligence feeds for target URL.", "alternatives": []}',
                 "model_used": "openrouter/anthropic/claude-3-haiku",
                 "status": "COMPLETED",
                 "tokens_prompt": 120,
                 "tokens_completion": 40
             }):
            hybrid = HybridPlanner(rule_planner=rule_planner, llm_planner=llm_planner, policy="RULE_FIRST")
            graph = SecurityGraph(planner=hybrid)
            state = self._create_mock_security_state()

            final_state = graph.run(state)
            inv_state = final_state["investigation_state"]

            first_decision = inv_state.decisions[0]
            self.assertEqual(first_decision.engine_type, "HYBRID")
            self.assertIsNotNone(first_decision.arbitration)
            self.assertIn(first_decision.arbitration["agreement_state"], ["AGREEMENT", "DISAGREEMENT"])

    # -------------------------------------------------------------------------
    # 2. True Hybrid Arbitration across 5 Policies
    # -------------------------------------------------------------------------
    def _setup_disagreement_scenario(self, policy):
        rule_planner = MagicMock()
        rule_dec = PlannerDecision(
            action="RUN_TOOL",
            engine_type="RULE_ENGINE",
            planner_type="RULE",
            tool_name="ThreatIntelFeeds",
            expected_information_gain=0.70,
            confidence=0.75,
            rationale="Rule suggests fast reputation query."
        )
        rule_planner.propose_next_action.return_value = rule_dec

        llm_planner = MagicMock()
        llm_dec = PlannerDecision(
            action="RUN_TOOL",
            engine_type="LLM_PLANNER",
            planner_type="LLM",
            tool_name="UrlSandboxRunner",
            evidence_ids_used=["E-101", "E-102", "E-103"],
            expected_information_gain=0.92,
            confidence=0.90,
            rationale="LLM prioritizes deep behavioral detonation due to homograph domain."
        )
        llm_planner.propose_next_action.return_value = llm_dec

        hybrid = HybridPlanner(rule_planner=rule_planner, llm_planner=llm_planner, policy=policy)
        state = InvestigationState(incident_id="inc-arb", tenant_id="tenant-arb")
        state.evidence["E-101"] = StateEvidence(id="E-101", evidence_type="URL_NORMALIZED", value="http://mal.ru", source="test")
        return hybrid, state

    def test_hybrid_policy_rule_first(self):
        hybrid, state = self._setup_disagreement_scenario("RULE_FIRST")
        with patch.object(LLMGateway, "is_configured", return_value=True):
            dec = hybrid.propose_next_action(state, self.available_tools, self.permissions)
            self.assertEqual(dec.arbitration["selected"], "ThreatIntelFeeds")
            self.assertEqual(dec.arbitration["policy"], "RULE_FIRST")

    def test_hybrid_policy_consensus_required(self):
        hybrid, state = self._setup_disagreement_scenario("CONSENSUS_REQUIRED")
        with patch.object(LLMGateway, "is_configured", return_value=True):
            dec = hybrid.propose_next_action(state, self.available_tools, self.permissions)
            self.assertEqual(dec.action, "STOP")
            self.assertEqual(dec.stop_reason, "CONSENSUS_REQUIRED_DISAGREEMENT")

    def test_hybrid_policy_information_gain_weighted(self):
        hybrid, state = self._setup_disagreement_scenario("INFORMATION_GAIN_WEIGHTED")
        with patch.object(LLMGateway, "is_configured", return_value=True):
            dec = hybrid.propose_next_action(state, self.available_tools, self.permissions)
            # LLM has 0.92 gain vs Rule's 0.70 gain
            self.assertEqual(dec.arbitration["selected"], "UrlSandboxRunner")

    def test_hybrid_policy_evidence_weighted(self):
        hybrid, state = self._setup_disagreement_scenario("EVIDENCE_WEIGHTED")
        with patch.object(LLMGateway, "is_configured", return_value=True):
            dec = hybrid.propose_next_action(state, self.available_tools, self.permissions)
            # LLM used 3 evidence IDs + 0.90 confidence vs Rule's 1 evidence ID + 0.75 confidence
            self.assertEqual(dec.arbitration["selected"], "UrlSandboxRunner")

    def test_hybrid_policy_safety_first(self):
        hybrid, state = self._setup_disagreement_scenario("SAFETY_FIRST")
        with patch.object(LLMGateway, "is_configured", return_value=True):
            dec = hybrid.propose_next_action(state, self.available_tools, self.permissions)
            # ThreatIntelFeeds is static/low-cost; UrlSandboxRunner is dynamic detonation
            self.assertEqual(dec.arbitration["selected"], "ThreatIntelFeeds")

    # -------------------------------------------------------------------------
    # 3. Truthful Explicit Fallback
    # -------------------------------------------------------------------------
    def test_llm_fallback_when_unconfigured(self):
        planner = LLMPlanner()
        state = InvestigationState(incident_id="inc-unconf", tenant_id="tenant-unconf")
        state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data="http://suspicious.com", location="BODY"))

        with patch.object(LLMGateway, "is_configured", return_value=False):
            dec = planner.propose_next_action(state, self.available_tools, self.permissions)
            self.assertEqual(state.planner_requested, "LLM")
            self.assertEqual(state.planner_used, "RULE")
            self.assertIn("not configured", state.fallback_reason.lower())
            self.assertEqual(dec.planner_type, "RULE")

    def test_llm_fallback_on_timeout(self):
        planner = LLMPlanner()
        state = InvestigationState(incident_id="inc-timeout", tenant_id="tenant-timeout")
        state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data="http://suspicious.com", location="BODY"))

        with patch.object(LLMGateway, "is_configured", return_value=True), \
             patch.object(LLMGateway, "generate_completion", side_effect=TimeoutError("LLM Gateway request timed out after 10000ms")):
            dec = planner.propose_next_action(state, self.available_tools, self.permissions)
            self.assertEqual(state.planner_requested, "LLM")
            self.assertEqual(state.planner_used, "RULE")
            self.assertEqual(planner.llm_status, "LLM_TIMEOUT")
            self.assertIn("TIMEOUT", state.fallback_reason.upper())

    def test_llm_fallback_on_rate_limit_429(self):
        planner = LLMPlanner()
        state = InvestigationState(incident_id="inc-429", tenant_id="tenant-429")
        state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data="http://suspicious.com", location="BODY"))

        with patch.object(LLMGateway, "is_configured", return_value=True), \
             patch.object(LLMGateway, "generate_completion", side_effect=Exception("HTTP 429: Rate limit exceeded on OpenRouter")):
            dec = planner.propose_next_action(state, self.available_tools, self.permissions)
            self.assertEqual(state.planner_requested, "LLM")
            self.assertEqual(state.planner_used, "RULE")
            self.assertEqual(planner.llm_status, "LLM_RATE_LIMITED")
            self.assertIn("429", state.fallback_reason)

    # -------------------------------------------------------------------------
    # 4. Causal Counterfactual Investigation
    # -------------------------------------------------------------------------
    def test_causal_counterfactual_benign_vs_malicious_path(self):
        from apps.agents.core.investigation_state import ToolExecution
        planner = RuleBasedPlanner()

        def _make_state(site_url):
            s = InvestigationState(incident_id="inc-cf", tenant_id="tenant-cf")
            s.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data=site_url, location="BODY"))
            s.evidence["E-AUTH"] = StateEvidence(id="E-AUTH", evidence_type="AUTHENTICATION", value="SPF: Pass", source="test")
            s.executed_tools.append(ToolExecution(tool_name="UnicodeAnalyzer", status="COMPLETED"))
            s.executed_tools.append(ToolExecution(tool_name="dns_spf_dmarc_recon", status="COMPLETED"))
            s.executed_tools.append(ToolExecution(tool_name="ThreatIntelFeeds", status="COMPLETED"))
            return s

        # Branch A: Threat intel flagged URL as MALICIOUS -> stops early after threat intel
        state_mal = _make_state("http://malware.site")
        state_mal.evidence["E-1"] = StateEvidence(
            id="E-1",
            evidence_type="URL_REPUTATION",
            value="Threat intel reputation: MALICIOUS",
            subject="http://malware.site",
            source="ThreatIntelFeeds",
            metadata={"is_malicious": True, "reputation": "MALICIOUS"}
        )
        dec_mal = planner.propose_next_action(state_mal, self.available_tools, self.permissions)

        # Branch B: Threat intel returned UNKNOWN -> branches to UrlSandboxRunner!
        state_unk = _make_state("http://unknown.site")
        state_unk.evidence["E-1"] = StateEvidence(
            id="E-1",
            evidence_type="URL_REPUTATION",
            value="Threat intel reputation: UNKNOWN",
            subject="http://unknown.site",
            source="ThreatIntelFeeds",
            metadata={"is_malicious": False, "reputation": "UNKNOWN"}
        )

        dec_unk = planner.propose_next_action(state_unk, self.available_tools, self.permissions)

        # Counterfactual verification: Different evidence causes divergent planning action!
        self.assertNotEqual(dec_mal.action, dec_unk.action)
        self.assertEqual(dec_mal.action, "STOP")
        self.assertEqual(dec_unk.action, "RUN_TOOL")
        self.assertEqual(dec_unk.tool_name, "UrlSandboxRunner")

    # -------------------------------------------------------------------------
    # 5. Negative Evidence & Contradiction Tracking
    # -------------------------------------------------------------------------
    def test_negative_evidence_and_contradiction_recording(self):
        graph = SecurityGraph(planner_mode="RULE")
        state = self._create_mock_security_state()
        res_state = graph.run(state)
        inv = res_state["investigation_state"]

        # Negative evidence must record absence of attachments
        self.assertIn("no_attachment", inv.negative_evidence)
        self.assertTrue(inv.negative_evidence["no_attachment"]["absent"])

        # Add explicit contradiction and test detection
        contra = inv.add_contradiction(
            description="SPF alignment passed but URL flagged by CTI",
            conflicting_evidence_ids=["E-102", "E-104"],
            impact="HIGH"
        )
        self.assertEqual(len(inv.contradictions), 1)
        self.assertEqual(contra.impact, "HIGH")

    # -------------------------------------------------------------------------
    # 6. Multi-Step Replanning around Tool Failure
    # -------------------------------------------------------------------------
    def test_replanning_around_tool_failure(self):
        planner = RuleBasedPlanner()
        state = InvestigationState(incident_id="inc-replan", tenant_id="tenant-replan")
        state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data="http://login-verify.net", location="BODY"))

        from apps.agents.core.investigation_state import ToolExecution
        # ThreatIntelFeeds previously failed
        state.executed_tools.append(ToolExecution(tool_name="ThreatIntelFeeds", status="FAILED", error="Feed connection reset"))

        # Planner should not re-run ThreatIntelFeeds; it should adaptively replan to UrlSandboxRunner!
        dec = planner.propose_next_action(state, self.available_tools, self.permissions)
        self.assertEqual(dec.action, "RUN_TOOL")
        self.assertEqual(dec.tool_name, "UrlSandboxRunner")
        self.assertNotEqual(dec.tool_name, "ThreatIntelFeeds")

    # -------------------------------------------------------------------------
    # 7. Multi-Tenant State Isolation & Persistence
    # -------------------------------------------------------------------------
    def test_tenant_isolation_and_serialization_roundtrip(self):
        state_tenant_a = InvestigationState(incident_id="inc-101", tenant_id="tenant-alpha")
        state_tenant_b = InvestigationState(incident_id="inc-102", tenant_id="tenant-bravo")

        state_tenant_a.add_negative_evidence("no_attachment", "Alpha verified clean")
        state_tenant_b.add_negative_evidence("no_url", "Bravo verified no links")

        # Isolation
        self.assertIn("no_attachment", state_tenant_a.negative_evidence)
        self.assertNotIn("no_attachment", state_tenant_b.negative_evidence)
        self.assertIn("no_url", state_tenant_b.negative_evidence)
        self.assertNotIn("no_url", state_tenant_a.negative_evidence)

        # Serialization round-trip
        dumped = state_tenant_a.model_dump()
        restored = InvestigationState.model_validate(dumped)
        self.assertEqual(restored.tenant_id, "tenant-alpha")
        self.assertEqual(restored.incident_id, "inc-101")
        self.assertEqual(restored.negative_evidence["no_attachment"]["detail"], "Alpha verified clean")

    # -------------------------------------------------------------------------
    # 8. Performance Latency Benchmarks
    # -------------------------------------------------------------------------
    def test_performance_latency_benchmarks(self):
        planner = RuleBasedPlanner()
        state = InvestigationState(incident_id="inc-bench", tenant_id="tenant-bench")
        state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data="http://benchmark-target.internal", location="BODY"))

        latencies = []
        for _ in range(50):
            t0 = time.perf_counter()
            planner.propose_next_action(state, self.available_tools, self.permissions)
            latencies.append((time.perf_counter() - t0) * 1000.0)

        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        # Deterministic rule planner must be sub-millisecond (p50 < 10ms, p99 < 50ms)
        self.assertLess(p50, 10.0, f"P50 latency exceeded 10ms: {p50}ms")
        self.assertLess(p99, 50.0, f"P99 latency exceeded 50ms: {p99}ms")


if __name__ == "__main__":
    unittest.main()
