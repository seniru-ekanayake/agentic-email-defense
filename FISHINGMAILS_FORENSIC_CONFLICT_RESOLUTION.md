# Executive Finding
The contradictions between the previous validation reports and the latest reality audit stem from two primary causes: 
1. The previous validation reports were testing an isolated, uncommitted set of files (e.g., `investigation_planner.py`) in isolated test scripts, rather than the integrated production path. 
2. The latest audit correctly observed the current state of the working directory, where critical components (like `investigation_planner.py`) are detached from the production graph, and other components (like `AbuseIPDBConnector`) have been deliberately stubbed out with mocks in uncommitted modifications.

The production `SecurityGraph` fundamentally does NOT use any agentic replanning loop, whether Rule-Based or LLM-Based. It is a linear, hardcoded pipeline that relies on `investigation_node.py` and `investigation_service.py` to statically assemble a synthetic UI trace mimicking agentic behavior. 

# 1. Exact Build Audited
*   **Commit:** `0a6a7f09d49799fe7a1f96f69dc8c4ed69fb041b`
*   **Branch:** `develop`
*   **Working Directory State:** Dirty, with numerous modified and untracked files.

**BUILD_COMPONENT_MAP**
| Component | File | Commit Introduced | Currently Imported? | Currently Reachable? |
| :--- | :--- | :--- | :--- | :--- |
| InvestigationPlanner | `apps/agents/core/investigation_planner.py` | Untracked File | Imported in `investigation_service.py` | NO (Dead code) |
| RuleBasedPlanner | `apps/agents/core/investigation_planner.py` | Untracked File | Imported in `investigation_service.py` | NO (Dead code) |
| LLMPlanner | `apps/agents/core/investigation_planner.py` | Untracked File | No | NO |
| HybridPlanner | `apps/agents/core/investigation_planner.py` | Untracked File | Instantiated in `investigation_service.py` | NO (Instantiated but never called) |
| LLMGateway | `apps/agents/core/llm_gateway.py` | `3a62e6e` | Yes | NO (Only by unreachable planners) |
| ToolRegistry | `apps/agents/core/tool_registry.py` | `3a62e6e` | Yes | YES (But heavily mocked) |
| URL sandbox | `apps/sandbox/src/url_sandbox.py` | `3a62e6e` | Yes | YES |
| Threat intelligence | `packages/threat_intel/src/free_feeds.py` | `3a62e6e` | Yes | YES (But AbuseIPDB is mocked in working tree) |
| InvestigationState | `apps/agents/core/investigation_state.py` | Untracked File | No | NO |

# 2. Runtime Entry Points
*   **Main Pipeline Entry:** `apps/agents/investigation_service.py` -> `process_triage()`
*   **Graph Orchestrator:** `apps/agents/graph.py` -> `SecurityGraph.run()`

# 3. Actual Architecture
The production execution path is a rigid, linear sequence of nodes:
`IngestionNode` -> `EmailAnalysisNode` -> `ExposureNode` -> `VulnResearchNode` -> `InvestigationNode` -> `ResponseNode`.
The system does not utilize an agentic loop or a planner.

# 4. RuleBasedPlanner Verification
*   **Finding:** The claim "Rule Planning = HARDCODED" is correct because the RuleBasedPlanner is entirely bypassed in production.
*   **Trace:** In `apps/agents/investigation_service.py`, `self.planner = HybridPlanner()` is instantiated on line 64, but it is **never called**. Instead, `final_state = self.security_graph.run(initial_state)` is executed. 
*   **Static Trace Formatter:** `investigation_node.py` builds the `attack_chain` list (lines 124-205) using static string heuristics on evidence. `investigation_service.py` builds the `decision_trace` manually (lines 417-595). The UI visualizes this static output; it does NOT visualize the decisions of a planner.

# 5. LLMPlanner Verification
*   **Finding:** The claim "LLM planning is bypassed" correctly describes the production environment, because the LLMPlanner is completely unreachable (Category B: LLMPlanner exists but is unreachable). It only exists in an untracked file and is never invoked by `SecurityGraph` or `investigation_service.py`.

# 6. HybridPlanner Verification
*   **Finding:** HybridPlanner is unreachable in production. It acts merely as a wrapper that falls back to RuleBasedPlanner if the LLMGateway is unconfigured. 

# 7. Agentic Loop Verification
*   **Finding:** There is no agentic loop.
*   **Evidence:** `apps/agents/graph.py` executes a predetermined list of nodes. Tool output cannot change the next planner decision because the planner is never consulted for the next action.

# 8. URL/Sandbox Verification
*   **Finding:** MOCKED / STATIC HEURISTICS.
*   **Breakdown:**
    *   URL extraction: IMPLEMENTED (via MIME parser)
    *   URL normalization: IMPLEMENTED (via urllib)
    *   DOM parsing: MOCKED (Regex `.lower()` on manually passed `simulated_landing_html`)
    *   Network request: NOT IMPLEMENTED
    *   Browser rendering: UNAVAILABLE IN CURRENT ENVIRONMENT (Playwright not installed/used)
    *   JavaScript execution: NOT IMPLEMENTED
*   **Evidence:** `apps/sandbox/src/url_sandbox.py` (lines 144-177). If `simulated_landing_html` is not provided in tests, it defaults to an empty string and fails to fetch real HTML.

# 9. Threat Intelligence Verification
*   **AbuseIPDB:** MOCKED. In the current working tree, uncommitted modifications replaced the actual `requests.get` call with a mock returning static values (`packages/threat_intel/src/free_feeds.py`).
*   **Quad9 DoH:** LIVE. It makes real `session.get` calls to `https://dns.quad9.net/dns-query`.
*   **URLhaus:** LIVE. It makes real `session.get` calls.
*   **CISA KEV:** HARDCODED. Relies primarily on an offline snapshot of exactly 4 CVEs (`packages/threat_intel/src/cisa_kev.py`).

# 10. Response Execution Verification
*   **Finding:** MOCKED / RETURNS STATIC SUCCESS.
*   **Evidence:** `apps/agents/core/tool_registry.py` lines 304-357 explicitly mock actions like `block_sender`, `block_ioc`, and `force_password_reset` with lambdas returning immediate static SUCCESS (`lambda p: {"status": "SUCCESS", "entry_added": True, "target": p.get("sender_or_domain")}`). No external APIs are called.

# 11. Mailbox Ingestion Verification
*   **Finding:** PARTIALLY IMPLEMENTED.
*   **Evidence:** `apps/agents/ingestion/m365_adapter.py` and `gmail_adapter.py` contain logic to parse webhook notification structures and decode base64 bytes, but lack the authentication logic to actually connect to the Graph API or Gmail APIs to fetch emails.

# 12. Persistence Verification
*   **Finding:** PARTIALLY VERIFIED. SQLite WAL persistence exists for the attack graph (`packages/attack_graph/src/sqlite_repository.py` untracked file), but durable state storage for the entire investigation context across a distributed multi-tenant environment is not fully wired in.

# 13. Multi-Tenant Verification
*   **Finding:** IMPLEMENTED BUT NOT VERIFIED. Relies entirely on basic `tenant_id` string matching in requests without cryptographic separation or robust access controls.

# 14. Frontend/Backend Verification
*   The UI "Decision Trace" visualizes the `decision_trace` array built deterministically by `investigation_service.py`. It is a presentation of a hardcoded narrative, not the visualization of real runtime decisions.

# 15. Test Integrity
*   Tests such as `test_free_threat_feeds.py` test mocked internal logic, while `test_production_platform.py` relies on a synthetic demo fixture to pass its assertions.

# 16. Previous Report Reconciliation
| Previous Claim | Latest Audit Claim | Current Code Evidence | Actual Conclusion |
| :--- | :--- | :--- | :--- |
| RuleBasedPlanner verified | HARDCODED | Planner is unreachable dead code | The UI trace is formatted statically. Planners were only tested in isolated scripts. |
| LLMPlanner live verified | Bypassed | Unreachable in production | Isolated test scripts used the untracked file, but it is not part of the actual app. |
| Hybrid runtime verified | Fallback only | Unreachable in production | Untracked file wrapper falling back to rules. |
| Agentic replanning | No agentic loop | `graph.py` is linear | System uses a static processing pipeline. |

# 17. Latest Audit Errors
*   The latest audit correctly identified the mocked/hardcoded nature of the system, but incorrectly stated that the `RuleBasedPlanner` was driving the execution. The `RuleBasedPlanner` is completely orphaned and uncalled; the logic is even simpler—a linear sequence of nodes and static trace string formatting.

# 18. Confirmed Gaps
*   **No Agentic Loop:** The system is a fixed linear pipeline, not an adaptive planner.
*   **Mocked Execution:** The URL sandbox, automated responses, and AbuseIPDB are completely stubbed out.

# 19. Capability Matrix
### VERIFIED
*   MIME Parsing
*   Static Attachment Analysis
*   DNS-over-HTTPS (DoH)

### PARTIALLY VERIFIED
*   URLhaus Intelligence
*   SQLite Persistence

### IMPLEMENTED BUT NOT VERIFIED
*   LLM Gateway Configuration
*   Multi-tenant ID tagging

### MOCKED / SIMULATED
*   Response Actions (`block_sender`, etc.)
*   URL Sandbox (Playwright absent)
*   AbuseIPDB
*   Decision Trace Generation (Static formatter)

### BROKEN
*   Local Ollama fallback (explicitly returns NOT_CONFIGURED)

### NOT IMPLEMENTED
*   Agentic Adaptive Planning (Production Path)

### UNAVAILABLE IN CURRENT ENVIRONMENT
*   Live Mailbox Ingestion (Lacks auth fetching logic)

# 20. Final Defensible Product Description
FishingMails is a deterministic, linear email parser and static analysis engine that dynamically formats its output to mimic an autonomous AI agent's decision trace. While it possesses functional components for MIME extraction, DNS querying, and static attachment inspection, its core agentic capabilities (adaptive planning, browser sandboxing, live automated response) are completely disconnected, mocked, or absent from the production execution path.
