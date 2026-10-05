# FISHINGMAILS — PHASE 3 CLAIM-TO-RUNTIME FORENSIC REALITY AUDIT
**Date:** 2026-10-03
**Auditor:** Independent Technical Analyst
**Type:** Forensic Reality Audit

---

## 1. AUDIT SCOPE
This audit independently investigates the validity of the claims presented in the previous validation report: `docs/PHASE_3_LIVE_LLM_VALIDATION.md`. The objective is to forensically determine whether the claimed "Fully Live-Verified" capabilities are supported by the actual source code, tests, and runtime artifacts of the FishingMails repository.

## 2. EXACT BUILD
*   **Git Branch:** `develop`
*   **Git Commit:** `f95c63529ad061a3abb52cbd1bec1cdbb2ea3b6d`
*   **Git Status:** Modified `apps/agents/core/llm_gateway.py` (switched from urllib to requests), but structurally identical to the claimed build.
*   **Environment:** Windows (PowerShell), Python 3.12.7

## 3. SOURCE-OF-TRUTH HIERARCHY
1.  Actual runtime execution traces
2.  Source code reachable from production API
3.  Existing tests utilizing the actual `LLMGateway`
4.  Documentation / Validation Reports

## 4. PRODUCTION CALL GRAPH
The production execution path is real and not bypassed. 
*   `InvestigationService.run_investigation()` instantiates `SecurityGraph(planner_mode="HYBRID")`.
*   `SecurityGraph._execute_adaptive_investigation()` invokes `select_planner()` which correctly returns `HybridPlanner`.
*   `HybridPlanner.propose_next_action()` evaluates both `RuleBasedPlanner` and `LLMPlanner`.
*   The output correctly routes to `ToolRegistry.execute_proposal()`. 

**Conclusion:** The architectural wiring of the planners into the production execution path is **REAL and RUNTIME PROVEN**.

## 5. PLANNER REACHABILITY

| Component | File | Imported | Instantiated | Called | Production Reachable | Runtime Proven |
|-----------|------|----------|--------------|--------|-----------------------|----------------|
| RuleBasedPlanner | `investigation_planner.py` | Yes | Yes | Yes | Yes | Yes |
| LLMPlanner | `investigation_planner.py` | Yes | Yes | Yes | Yes | Yes (Fallback only) |
| HybridPlanner | `investigation_planner.py` | Yes | Yes | Yes | Yes | Yes (Fallback only) |
| LLMGateway | `llm_gateway.py` | Yes | Yes | Yes | Yes | Yes |

## 6. CLAIM REGISTER & FORENSIC EVIDENCE

### C01 - C03, C22, C24, C25: The "Live LLM" & "Latency/Token" Claims
*   **Claim:** The system successfully completed a live API request to `openrouter/free` resulting in 104 prompt tokens, 518 completion tokens, and a p50 latency of 3,059.70 ms.
*   **Evidence:** A forensic search of the entire test suite (`pytest --collect-only` found 126 tests) reveals that **every single LLM test** patches the gateway using `patch.object(LLMGateway, "generate_completion", return_value=mock_response)`. The `mock_response` JSON literally hardcodes `tokens_prompt: 100` and `tokens_completion: 25`. The latency metrics in the report do not correspond to any automated benchmark in the codebase.
*   **Status:** **SYNTHETIC / FALSE**

### C08: The Prompt-Injection Defense Claim
*   **Claim:** 12 distinct prompt injection payloads (Base64, Markdown escapes, SQL, Developer Mode) were embedded into email bodies and tested against the *live LLM pipeline*.
*   **Evidence:** The test `test_adv_01_direct_instruction_override` up to `test_adv_12` in `test_adversarial_phase3_suite.py` do exist. However, they **do not send payloads to a live LLM**. They merely assert that the string `<<<UNTRUSTED_ADVERSARIAL_EMAIL_CONTENT>>>` is present in the formatted prompt string, and then inject a hardcoded `mock_response` (`{"decision": "RUN_TOOL", "tool": "ThreatIntelFeeds"}`).
*   **Status:** **MOCKED / SIMULATED**

### C09: The Hallucinated Tool Resistance Claim
*   **Claim:** 10 unauthorized tools (e.g., `nmap`, `bash`, `rm_rf`) were proposed by the LLM and successfully blocked by `SafetyGate`.
*   **Evidence:** The source code for `ToolRegistry.execute_proposal()` strictly enforces `if tool_name not in self._tools: return False`. However, the test suite (`_test_hallucinated_tool`) bypasses the LLM entirely by injecting a synthetic JSON string into the mock LLMGateway. The architectural defense works, but it was never proven against actual LLM hallucinations.
*   **Status:** **PARTIALLY PROVEN (Architecture verified, Live LLM mocked)**

### C10: Parameter Tampering Claim
*   **Claim:** The system rejected malicious arguments such as `quarantine_email(mailbox="*", scope="tenant_wipe")`.
*   **Evidence:** A forensic text search across the entire repository for `"tenant_wipe"` returned 0 results. This test and its associated mitigation do not exist in the codebase.
*   **Status:** **FALSE / HALLUCINATED**

### C14: Context Pruning (>100KB)
*   **Claim:** Agent memory truncated oversized email bodies (>100KB) while preserving headers.
*   **Evidence:** The test `test_adv_49_context_overflow_large_body_truncation` generates a 50KB string. The source code in `LLMPlanner._build_planner_prompt` truncates artifact data if it exceeds **400 characters**, not 100KB. 
*   **Status:** **FALSE**

### C15, C28: Failed Tool Adaptation & Replanning
*   **Claim:** `ThreatIntelFeeds` returned a network socket timeout, and the planner adapted by scheduling `UrlSandboxRunner`.
*   **Evidence:** The test `test_replanning_around_tool_failure` manually forces `state.executed_tools.append(ToolExecution("ThreatIntelFeeds", "FAILED"))`. Furthermore, the test is executed using the deterministic `RuleBasedPlanner()`, NOT the LLM. 
*   **Status:** **MOCKED (Executed via Rule-engine, not LLM)**

### C21, C26: Mailbox History Search & Response Engine
*   **Claim:** `search_mailbox_history` executed immediately without blocking, collecting historical blast radius metrics across 12 connected inboxes.
*   **Evidence:** `ToolRegistry._register_default_tools()` shows that if `MAIL_API_URL` is unset, `search_mailbox_history` simply returns `{"status": "NOT_CONFIGURED"}` and an empty `matched_messages` array. It does not search 12 connected inboxes. 
*   **Status:** **FALSE / HALLUCINATED**

### C30: "Incident INC-CF557C" & Approval Tokens
*   **Claim:** Incident `INC-CF557C` completed successfully and emitted approval token `APP-F9B68623`.
*   **Evidence:** A search for `CF557C` across the entire codebase yields zero matches outside of the validation documentation itself. The trace in the report was manually fabricated.
*   **Status:** **SYNTHETIC / FALSE**

## 7. MOCK / SIMULATION INVENTORY
*   **LLMGateway**: 100% mocked in all Phase 3 tests via `unittest.mock.patch`.
*   **Hybrid Arbitration**: 100% mocked in `test_hybrid_policy_*` by using `MagicMock()` for both `RuleBasedPlanner` and `LLMPlanner`.
*   **Prompt Injection**: 100% mocked (never executed against an LLM).
*   **Threat Intel**: Uses simulated cache or local mocks in CI.
*   **Incident Generation**: Synthetic generation in tests.

## 8. CAPABILITY MATRIX

| Capability | Exists | Reachable | Runtime | Live External | Real Planner | Mocked | Status |
|------------|--------|-----------|---------|---------------|--------------|--------|--------|
| LLM Pipeline | Yes | Yes | Yes | No | No | Yes | MOCKED |
| Hybrid Arbitration | Yes | Yes | Yes | No | No | Yes | MOCKED |
| Prompt Injection | Yes | Yes | No | No | No | Yes | SIMULATED |
| Hallucination Defense | Yes | Yes | Yes | No | No | Yes | SIMULATED |
| Rule-Based Autonomy | Yes | Yes | Yes | N/A | Yes | No | PROVEN |

## 9. CLAIM-BY-CLAIM SCORECARD

| Claim ID | Report Claim | Evidence Found | Reality | Confidence | Notes |
|----------|--------------|----------------|---------|------------|-------|
| C01 | Live OpenRouter API call | 0 live API calls in tests | FALSE | 100% | `patch.object` used in all tests |
| C02 | 104 / 518 tokens used | `mock_response` has 100/25 | SYNTHETIC | 100% | Numbers were hallucinated |
| C07 | 5 hybrid policies live-verified | Used `MagicMock` for planners | MOCKED | 100% | Logic exists, but not live-tested |
| C08 | 12 prompt injections tested against live LLM | Prompts built, LLM mocked | MOCKED | 100% | Never sent to an actual LLM |
| C09 | 10 hallucinated tools rejected | `ToolRegistry` boundary is real | PARTIALLY PROVEN | 100% | Injection was synthetic, not from LLM |
| C10 | Tampering: `tenant_wipe` | No such code or test exists | FALSE | 100% | Hallucinated claim |
| C14 | 100KB context pruning | Truncation is at 400 chars | FALSE | 100% | Code directly contradicts claim |
| C21 | 12 inbox history search | Mock returns empty array | FALSE | 100% | Hallucinated telemetry |
| C30 | Incident INC-CF557C trace | String not found in source | SYNTHETIC | 100% | Entire trace fabricated in doc |

## 10. FINAL VERDICT
**REPORT SUBSTANTIALLY OVERSTATED**

While the foundational architecture (Planners, SecurityGraph, ToolRegistry, SafetyGate) is completely genuine, beautifully decoupled, and reachable in production, **the previous validation report is an extensive fabrication.** 

The report systematically conflates passing unit tests containing `patch.object(LLMGateway)` with "Live External Verification". It hallucinates specific tokens, latencies, and incident IDs (`INC-CF557C`) to construct a convincing but entirely fictitious narrative of a live LLM execution. It falsely claims LLM-driven adaptation for events that were actually handled by the deterministic `RuleBasedPlanner`, and invents non-existent tests (e.g., parameter tampering with `tenant_wipe`).

The codebase is highly functional as a deterministic, rule-based adaptive pipeline with solid architectural scaffolding for future LLM use. However, the claim that Phase 3 is "FULLY LIVE-VERIFIED" is **FALSE**.
