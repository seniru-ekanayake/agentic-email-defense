# FISHINGMAILS — FINAL CYCLE-BY-CYCLE LLM CAUSALITY FORENSIC AUDIT
===============================================================

## VERDICT:
**`LIVE LLM EXECUTION PROVEN — AGENTIC CAUSAL LOOP NOT PROVEN`**

---

## EXECUTIVE SUMMARY TABLE

```
REAL PROVIDER CALLS:                    3
REAL LLM-CONTROLLED CYCLES:             3
REAL TOOL EXECUTIONS CAUSED BY LLM:     1 (threat_intel_lookup: COMPLETED; query_sender_history: FAILED)
REAL EVIDENCE PROPAGATION EVENTS:       1 (Cycle 1 -> Cycle 2 prompt)
REAL LLM REPLANNING EVENTS:             1 (Cycle 2 diverged to query_sender_history)
RULE FALLBACK CYCLES:                   0
HARNESS STATE WRITES:                   0
MOCKED LLM CALLS:                       0
```

---

## STRONGEST DIRECT EVIDENCE BY CYCLE

### Cycle 1
- **Live Provider Call:** VERIFIED. OpenRouter API invoked via `LLMGateway.generate()` during `POST /api/v1/investigate`.
- **Model Used:** `meta-llama/llama-3.3-70b-instruct:free` (aliased as `openrouter/free`).
- **Proposal:** `RUN_TOOL` on `threat_intel_lookup`.
- **Live LLM Rationale:**
  > *"The URL in the email mimics a Microsoft 365 verification portal (m365-verify-portal.auth-service-login.cc) and is highly suspicious for credential harvesting. Querying free threat intelligence feeds (URLhaus, AbuseIPDB, Quad9) will immediately reveal if this URL or its domain is known malicious, providing high-value context at zero cost."*
- **Tool Execution:** `exec-bcc6a19e` executed by `ToolRegistry.threat_intel_lookup` in 1812.32 ms, status: `COMPLETED`.
- **Result:** `is_malicious: False`, URLhaus `no_results` (UNKNOWN/CLEAN).
- **State Mutation:** Negative evidence recorded in `InvestigationState` (`no_known_malicious_reputation`).

### Cycle 2
- **Live Provider Call:** VERIFIED. Second distinct OpenRouter request executed.
- **Context Received:** Received Cycle 1 tool execution history (`threat_intel_lookup | Status: COMPLETED`) and negative evidence.
- **Proposal:** `RUN_TOOL` on `query_sender_history` (Causal divergence from Cycle 1).
- **Live LLM Rationale:**
  > *"The email comes from security-admin@microsoft-identity-verification.net, a domain that is not microsoft.com but passed SPF/DMARC, suggesting possible domain spoofing. To assess whether this sender has any legitimate prior communication with the finance director, querying the sender‑recipient history will provide interaction frequency, first‑seen timestamps, and baseline anomaly scores, which are essential for determining legitimacy."*
- **Tool Execution:** **FAILED (`exec-6e5f52b6`)**. Dispatched to `ToolRegistry.query_sender_history`, but crashed in 0.19 ms with error:
  `"SQLite objects created in a thread can only be used in that same thread. The object was created in thread id 14764 and this is thread id 1460."`
- **Result & State Mutation:** **BROKEN LINK**. Zero telemetry returned, zero evidence created (`evidence_created: []`), and no sender baseline evidence was recorded in `InvestigationState`.

### Cycle 3
- **Live Provider Call:** VERIFIED. Third distinct OpenRouter request executed.
- **Context Received:** Saw `threat_intel_lookup` (COMPLETED) and `query_sender_history` (FAILED).
- **Proposal:** `STOP (SUFFICIENT_EVIDENCE)`.
- **Live LLM Rationale:**
  > *"Sufficient evidence exists; no further action needed."*
- **Stop Causality:** The LLM terminated the investigation on generic grounds without consuming any Cycle 2 sender baseline evidence (since the tool crashed).

---

## 1. RUN IDENTIFICATION & BUILD INTEGRITY

- **Claimed Incident ID:** `INC-562F20`
- **Claimed Run ID:** `run-prod-live-73185648`
- **Database Location:** `data/fishingmails.db` (Table: `incidents`, Record: `INC-562F20`)
- **Git Commit:** `f95c63529ad061a3abb52cbd1bec1cdbb2ea3b6d`
- **Git Branch:** `develop`
- **Build Status:** **DIRTY WORKING-TREE CODE**.
  The historical investigation ran against uncommitted working-tree modifications across:
  - `apps/agents/core/investigation_planner.py`
  - `apps/agents/core/llm_gateway.py`
  - `apps/agents/core/mcp_servers/telemetry_server.py`
  - `apps/agents/graph.py`
  - `apps/agents/nodes/vuln_research_node.py`

### File SHA-256 Hashes
| File Path | SHA-256 Hash |
|---|---|
| `apps/server.py` | `738da3e13c8de94e0935fd1e001c71491c504d872068a24cfb946d7c8e7b28e2` |
| `apps/agents/graph.py` | `accfcc7bddec1691d40be75683692da4f7f4ed3ba90be43652e2da3e926773f2` |
| `apps/agents/investigation_service.py` | `cb3431ab91ef96b43cb3fd3678c5cdb9765ac8fd64a05d60357c3e48dc7ff26f` |
| `apps/agents/core/investigation_planner.py` | `5356f9c460cbcac846813402eb9031209b838f4bc80696eee949c67817f02151` |
| `apps/agents/core/llm_gateway.py` | `0ab73740da17ba775ca1c2a1e357ce58b26993f2aa464c97ffe3bdabb475c03a` |
| `apps/agents/core/tool_registry.py` | `1bb91ead3f61e5004fdce44909bd41f1623d39f8712104f33739f7d18c1ad53a` |
| `apps/agents/core/investigation_state.py` | `a0487830f81777dbb509ec3ee5036accb1b658acaeccca2eba373b26dbf3c939` |

---

## 2. ARTIFACT INVENTORY

1. `docs/LIVE_LLM_AGENTIC_LOOP_PROOF.json` (Summary proof JSON claiming multi-cycle agentic verification)
2. `docs/LIVE_LLM_AGENTIC_LOOP_PROOF.md` (Summary markdown report)
3. `data/fishingmails.db` (Durable SQLite storage containing raw incident record `INC-562F20`)
4. `.system_generated/tasks/task-3919.log` (Raw execution log from task 3919 that executed `POST /api/v1/investigate`)
5. `.system_generated/logs/transcript.jsonl` and `transcript_full.jsonl` (Antigravity framework execution trace)

---

## 3. CYCLE 1 FORENSICS (VERIFIED)

- **Entrypoint:** `POST /api/v1/investigate` with raw RFC822 EML bytes.
- **Provider Request:** HTTP POST to `https://openrouter.ai/api/v1/chat/completions`.
- **Model:** `openrouter/free` (`meta-llama/llama-3.3-70b-instruct:free`).
- **Response Received:** Valid JSON proposal parsed into `LLMDecisionProposal`.
- **Proposed Action:** `RUN_TOOL`, tool: `threat_intel_lookup`.
- **RuleBasedPlanner Counterfactual Check:**
  On the identical initial state, `RuleBasedPlanner` selects `UnicodeAnalyzer` (addressing `Q-02` with 0.85 information gain). The decision to select `threat_intel_lookup` originated strictly from the LLM.
- **SafetyGate:** PASSED.
- **Tool Execution Record (`tool_executions` in DB):**
  - Execution ID: `exec-bcc6a19e`
  - Tool: `threat_intel_lookup`
  - Status: `COMPLETED`
  - Duration: 1812.32 ms
  - Output: `is_malicious: False`, query status: `no_results`.
- **State Mutation:** `InvestigationState.negative_evidence` updated with key `no_known_malicious_reputation`.

---

## 4. CYCLE 2 FORENSICS (TOOL EXECUTION FAILED — CRITICAL FINDING)

- **Provider Request:** Second distinct HTTP POST to OpenRouter API.
- **Context Propagation:**
  `InvestigationPlanner._build_planner_prompt()` dynamically populated:
  - `--- TOOL EXECUTION HISTORY ---` with `threat_intel_lookup | Status: COMPLETED`
  - `--- NEGATIVE EVIDENCE ---` with `no_known_malicious_reputation`
  The LLM was aware that threat intel had run and returned clean/unknown.
- **LLM Proposal:**
  The LLM shifted focus to the sender domain `microsoft-identity-verification.net` and proposed `query_sender_history`.
- **RuleBasedPlanner Counterfactual Check:**
  `RuleBasedPlanner` would have selected `UrlSandboxRunner` (0.88 information gain addressing `Q-03`). The selection of `query_sender_history` was 100% LLM-driven.
- **SafetyGate:** PASSED.
- **Tool Execution Reality (`tool_executions` in DB):**
  - Execution ID: `exec-6e5f52b6`
  - Tool: `query_sender_history`
  - Status: **`FAILED`**
  - Duration: 0.19 ms
  - Error:
    ```
    SQLite objects created in a thread can only be used in that same thread.
    The object was created in thread id 14764 and this is thread id 1460.
    ```
  - Result Summary: `{}`
  - Evidence Created: `[]` (EMPTY)
- **Root Cause:**
  `apps/agents/core/mcp_servers/telemetry_server.py` instantiated `sqlite3.connect(":memory:")` without `check_same_thread=False` at the time of execution. When invoked in the async worker thread, SQLite raised a thread binding exception.

---

## 5. CYCLE 3 FORENSICS (STOP CAUSALITY)

- **Provider Request:** Third distinct HTTP POST to OpenRouter API.
- **Context Received:**
  - `threat_intel_lookup`: `COMPLETED`
  - `query_sender_history`: `FAILED`
  - Unresolved question: `Q-03` (URL behavioral detonation) was still open!
- **LLM Proposal:** `STOP (SUFFICIENT_EVIDENCE)`.
- **Live LLM Rationale:** *"Sufficient evidence exists; no further action needed."*
- **Causality Evaluation:**
  Because `query_sender_history` failed, no sender baseline evidence was available. The model concluded the investigation without resolving `Q-03` and without receiving sender history telemetry. The termination was not caused by newly acquired sender evidence.

---

## 6. COMPLETE CAUSAL CHAIN TABLE

| Stage | Required Evidence | Found | Source | Status |
|---|---|---|---|:---:|
| Raw EML | Actual MIME RFC822 payload | YES | `task-3919.log`, `data/fishingmails.db` | **PASS** |
| Cycle 1 provider request | Distinct OpenRouter HTTP call | YES | `task-3919.log`, runtime latency (165s total) | **PASS** |
| Cycle 1 LLM response | Real model output | YES | `D-548325` in `decision_trace` | **PASS** |
| Cycle 1 decision | LLM Proposal -> PlannerDecision | YES | `D-548325`, `Engine: LLM_PLANNER` | **PASS** |
| Cycle 1 tool execution | ToolRegistry execution | YES | `exec-bcc6a19e` in DB | **PASS** |
| Cycle 1 tool result | Real URLhaus response | YES | `result_summary`, 1812.32 ms | **PASS** |
| State update | Negative evidence updated | YES | `no_known_malicious_reputation` | **PASS** |
| Cycle 2 provider request | Second distinct HTTP call | YES | `task-3919.log`, `D-017489` | **PASS** |
| Cycle 2 context | Includes Cycle 1 result | YES | Prompt built with Cycle 1 history | **PASS** |
| Cycle 2 LLM response | Real model output | YES | `D-017489` (`query_sender_history`) | **PASS** |
| Cycle 2 decision | LLM Proposal -> PlannerDecision | YES | `D-017489`, `Engine: LLM_PLANNER` | **PASS** |
| Cycle 2 tool execution | ToolRegistry execution | **NO** | `exec-6e5f52b6` **FAILED** (SQLite thread error) | **FAIL** |
| Cycle 2 tool result | Real sender telemetry | **NO** | Output was empty `{}`, 0.19 ms duration | **FAIL** |
| Cycle 2 state update | Sender baseline evidence | **NO** | `evidence_created: []` | **FAIL** |
| Cycle 3 provider request | Third distinct HTTP call | YES | `task-3919.log`, `D-3D25C0` | **PASS** |
| Cycle 3 context | Prior execution state | YES | Saw Tool 1 COMPLETED, Tool 2 FAILED | **PASS** |
| Cycle 3 LLM response | Real model output | YES | `D-3D25C0` (`STOP`) | **PASS** |
| Cycle 3 STOP | Evidence-based stopping | **NO** | Generic STOP without Cycle 2 evidence | **FAIL** |

---

## 7. HARNESS INJECTION & MOCK AUDIT

- **Mock Calls Detected:** `0` (Zero mocked LLM calls in `task-3919`).
- **Harness State Injection:** `0` (Zero synthetic state injected; run executed directly through `client.post("/api/v1/investigate")`).
- **Proof Generation Misrepresentation:**
  While the investigation itself ran against the real production API without mocks, the verification script `tools/generate_proof_report.py` produced summary claims in `docs/LIVE_LLM_AGENTIC_LOOP_PROOF.json` and `docs/LIVE_LLM_AGENTIC_LOOP_PROOF.md` stating:
  - `"real_tool_registry_executed": true`
  - `"real_evidence_state_updated": true`
  - `"cycle_1_evidence_consumed_by_cycle_2": true`
  - *"InvestigationState: Sender baseline queried and updated"*
  These claims were **inaccurate** because they overlooked `exec-6e5f52b6`'s failure log:
  `ERROR:ToolRegistry:[TOOL ERROR] Error executing 'query_sender_history': SQLite objects created in a thread can only be used in that same thread.`

---

## 8. CVE & STATIC EVIDENCE PROVENANCE

In `data/fishingmails.db`, the incident record `INC-562F20` lists 4 evidence items:
1. `E-101`: `From: security-admin@microsoft-identity-verification.net...` (Source: `DeterministicMimeParser`)
2. `E-102`: `SPF: Pass / DMARC: Aligned` (Source: `MimeParser.HeaderAnalyzer`)
3. `E-103`: `http://m365-verify-portal.auth-service-login.cc/login` (Source: `HTMLAnalyzer`)
4. `E-104`: `CVE-2023-35636: Known exploitation in mail client rendering engine` (Source: `CisaKevIngestor + NvdIngestor`)

**Finding:** `CVE-2023-35636` was generated entirely by the static deterministic `VulnResearchNode` pipeline stage. It was **not** discovered, researched, or proposed by the LLM Planner.

---

## 9. SELF-CLAIM VERIFICATION AUDIT

| Field Claimed | Actual Reality | Verified? |
|---|---|:---:|
| `zero_synthetic_data: true` | Real SQLite database records and genuine MIME payload | **YES** |
| `zero_mocked_llm_calls: true` | Real OpenRouter network traffic across 3 distinct calls | **YES** |
| `real_openrouter_cycle_1_proposal: true` | Real proposal: `threat_intel_lookup` | **YES** |
| `real_openrouter_cycle_2_replanning: true` | Real replanning proposal: `query_sender_history` | **YES** |
| `causally_divergent_tool_selected: true` | Cycle 1 (`threat_intel_lookup`) != Cycle 2 (`query_sender_history`) | **YES** |
| `cycle_1_evidence_consumed_by_cycle_2: true` | Negative evidence and Tool 1 summary included in Cycle 2 prompt | **YES** |
| `real_tool_registry_executed: true` (Cycle 2) | Tool crashed in `telemetry_server.py` with SQLite threading error | **NO (CRASHED)** |
| `real_evidence_state_updated: true` (Cycle 2) | No evidence created from `query_sender_history` (`[]`) | **NO** |

---

## 10. FINAL CLASSIFICATION & CONCLUSION

**Required Classification:**
### **`LIVE LLM EXECUTION PROVEN — AGENTIC CAUSAL LOOP NOT PROVEN`**

### Summary of Findings:
1. **Live LLM Execution Proven:** The system indisputably made three consecutive, authentic live HTTP API calls to OpenRouter's Llama-3.3-70B model via FastAPI's `POST /api/v1/investigate`. The LLM was the sole decision maker for all three cycles (0 rule fallbacks).
2. **Causal Replanning Proven:** In Cycle 2, the LLM received the execution history of Cycle 1 and autonomously pivoted to inspect the sender domain with `query_sender_history`.
3. **Agentic Causal Loop Broken at Cycle 2 Execution:** Because `query_sender_history` failed with an unhandled SQLite cross-thread exception (`thread id 14764 vs 1460`), no tool result was generated, no evidence was updated in `InvestigationState`, and Cycle 3 stopped without consuming the planned sender telemetry.
4. **Documentation Discrepancy:** The generated summary reports claimed the full multi-cycle tool execution and evidence update loop succeeded, which was contradicted by the underlying database record `tool_executions[1].status = 'FAILED'`.
