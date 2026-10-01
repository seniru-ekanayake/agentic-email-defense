# FishingMails Pre-Remediation Forensic Audit Report

> **Audit Date:** 2026-10-01  
> **Auditor Role:** Independent Forensic Auditor & Remediation Engineer  
> **Status:** PRE-REMEDIATION AUDIT COMPLETE  
> **Scope:** Verification of material architectural findings across repository, working tree, and runtime execution paths.

---

## 1. Audit Environment & Git Baseline

### 1.1 Git Metadata
- **Commit SHA (`git rev-parse HEAD`):** `0a6a7f09d49799fe7a1f96f69dc8c4ed69fb041b`
- **Current Branch (`git branch --show-current`):** `develop`
- **Remote Synchronization:** Up to date with `origin/develop` and `origin/main`

### 1.2 Git Working Tree Status (`git status --short`)
```text
 M apps/agents/core/approval_manager.py
 M apps/agents/core/llm_gateway.py
 M apps/agents/core/tool_registry.py
 M apps/agents/graph.py
 M apps/agents/investigation_service.py
 M apps/agents/nodes/ingestion_node.py
 M apps/agents/nodes/investigation_node.py
 M apps/agents/nodes/response_node.py
 M apps/agents/nodes/vuln_research_node.py
 M apps/agents/streaming_service.py
 M apps/agents/tests/test_agent_graph.py
 M apps/agents/tests/test_foundation.py
 M apps/sandbox/src/models.py
 M apps/sandbox/src/network_guard.py
 M apps/sandbox/src/sandbox_runner.py
 M apps/server.py
 M packages/attack_surface/src/attack_surface_engine.py
 M packages/attack_surface/src/campaign_dedup.py
 M packages/attack_surface/src/scoring_engine.py
 M packages/email_parser/src/html_analyzer.py
 M packages/email_parser/src/mime_parser.py
 M packages/email_parser/tests/test_email_parser.py
 M packages/schemas/python/models.py
 M packages/threat_intel/src/free_feeds.py
 M tests/adversarial/test_adversarial_security.py
 M tests/e2e/test_demo_scenario.py
?? FISHINGMAILS_FORENSIC_CONFLICT_RESOLUTION.md
?? FISHINGMAILS_IMPLEMENTATION_REALITY_AUDIT.md
?? apps/agents/core/agent_builder.py
?? apps/agents/core/durable_storage.py
?? apps/agents/core/event_system.py
?? apps/agents/core/forensic_ledger.py
?? apps/agents/core/integration_center.py
?? apps/agents/core/investigation_planner.py
?? apps/agents/core/investigation_state.py
?? apps/agents/core/production_manager.py
?? apps/agents/core/state_machine.py
?? apps/agents/core/system_selftest.py
?? apps/agents/core/trust_score.py
?? packages/attack_graph/src/sqlite_repository.py
?? packages/email_parser/src/attachment_analyzer.py
?? packages/email_parser/src/unicode_analyzer.py
?? packages/email_parser/src/url_normalizer.py
?? scripts/audit_runner.py
?? tests/test_adaptability_suite.py
?? tests/test_production_platform.py
```

### 1.3 Git Log Recent History (`git log --oneline -20`)
```text
0a6a7f0 docs(readme): readd FishingMails brand logo image to header
edba764 docs: rewrite documentation to match verified architecture
1651e56 fix(forensics): eliminate narrative hallucination, ground attack chain in actual evidence, detect Unicode obfuscation and RFC 2606 test domains
12af7ea feat(server): launch production Swiss SOC dashboard with drag-and-drop EML ingestion on port 8080
aa45dc2 feat(cli): add interactive email inspection runner with live LangGraph telemetry
6827869 docs(readme): expand documentation with LLM tier matrix, campaign taxonomy, and inspection guide
d2e253a docs: add .env.example with OpenRouter, Ollama, and Neo4j configuration
a1ea3ea feat(ui): bind real platform telemetry, 6 LangGraph nodes, and CVE exploit vectors to Swiss UI
b8cc1af feat(ui): redesign dashboard and navigation to match Swiss enterprise minimalist prototype
b3c27e6 chore(branding): rename platform to FishingMails across all services and documentation
d390bd2 chore(branding): rename packages to @fishermail/api and @fishermail/web
6d7a709 feat(branding): introduce FisherMail brand identity and logo across repository and frontend
bc24b66 docs: overhaul README with architecture diagrams, verified numbers, and known limitations
f78804e fix(security): resolve audit vulnerabilities across sandbox, streaming, and tool governance
f75924e feat: merge award-winning tactical obsidian UI redesign into develop
9b3c4a6 feat(ui): implement award-winning tactical obsidian theme, CRT noise grain, radar conic border glows, and slide-to-authorize gate
5397f3d feat(ui): implement Poppins typography hierarchy, ambient mesh glow, and curved metric sparklines
6531800 feat: merge minimalist SaaS UI redesign with dark/light mode into develop
182be6f feat(ui): redesign frontend to  minimalist SaaS aesthetic with dark/light mode and SVG icons
a3d1356 feat: merge tier 3 real-time stream and human approval into develop
```

---

## 2. Component Map & Reachability Verification

| Component | File | Tracked? | Imported? | Instantiated? | Called? | Production Reachable? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `InvestigationPlanner` | `apps/agents/core/investigation_planner.py` | Untracked | `investigation_service.py` | No | No | **NO** (Dead code) |
| `RuleBasedPlanner` | `apps/agents/core/investigation_planner.py` | Untracked | `investigation_service.py` | No | No | **NO** (Dead code) |
| `LLMPlanner` | `apps/agents/core/investigation_planner.py` | Untracked | No | No | No | **NO** (Dead code) |
| `HybridPlanner` | `apps/agents/core/investigation_planner.py` | Untracked | `investigation_service.py` | Yes (line 127) | **NO** | **NO** (Instantiated, never invoked) |
| `InvestigationState` | `apps/agents/core/investigation_state.py` | Untracked | `investigation_service.py` | Partially | No | **NO** (Bypassed by SecurityState) |
| `SecurityGraph` | `apps/agents/graph.py` | Tracked (Modified) | `investigation_service.py` | Yes | Yes | **YES** (Production path) |
| `IngestionNode` | `apps/agents/nodes/ingestion_node.py` | Tracked (Modified) | `graph.py` | Yes | Yes | **YES** (Step 1) |
| `EmailAnalysisNode` | `apps/agents/nodes/email_analysis_node.py` | Tracked | `graph.py` | Yes | Yes | **YES** (Step 2) |
| `ExposureNode` | `apps/agents/nodes/exposure_node.py` | Tracked | `graph.py` | Yes | Yes | **YES** (Step 3) |
| `VulnResearchNode` | `apps/agents/nodes/vuln_research_node.py` | Tracked (Modified) | `graph.py` | Yes | Yes | **YES** (Step 4) |
| `InvestigationNode` | `apps/agents/nodes/investigation_node.py` | Tracked (Modified) | `graph.py` | Yes | Yes | **YES** (Step 5) |
| `ResponseNode` | `apps/agents/nodes/response_node.py` | Tracked (Modified) | `graph.py` | Yes | Yes | **YES** (Step 6) |
| `ToolRegistry` | `apps/agents/core/tool_registry.py` | Tracked (Modified) | `investigation_service.py` | Yes | Yes | **YES** (Contains static response lambdas) |
| `UrlSandboxRunner` | `apps/sandbox/src/url_sandbox.py` | Tracked | `email_analysis_node.py` | Yes | Yes | **YES** (Heuristic string matching only) |
| `SandboxRunner` | `apps/sandbox/src/sandbox_runner.py` | Tracked (Modified) | `email_analysis_node.py` | Yes | Yes | **YES** (Mock network events, no I/O) |
| `NetworkGuard` | `apps/sandbox/src/network_guard.py` | Tracked (Modified) | Multiple | Yes | Yes | **YES** (Static IP filtering) |
| `FreeThreatIntelEngine` | `packages/threat_intel/src/free_feeds.py` | Tracked (Modified) | `vuln_research_node.py` | Yes | Yes | **YES** (AbuseIPDB is mocked) |
| `SqliteAttackGraphRepository`| `packages/attack_graph/src/sqlite_repository.py` | Untracked | `investigation_service.py` | Yes | Yes | **YES** (Persists graph) |

---

## 3. Independent Verification of Forensic Findings

### Finding 1: The Production SecurityGraph is a Rigid Linear Pipeline
- **Verdict:** **CONFIRMED**
- **Evidence:** In `apps/agents/graph.py` lines 42–62:
  ```python
  # Step 1: Ingestion & Privacy Boundary
  state = self.ingestion_node.execute(state)
  # Step 2: Static & Sandbox Email Analysis
  state = self.email_analysis_node.execute(state)
  # Step 3: Exposure & Attack Surface Correlation
  state = self.exposure_node.execute(state)
  # Step 4: Vulnerability & Threat Intelligence Research
  state = self.vuln_research_node.execute(state)
  # Step 5: Investigation, Scoring & Attack Chain Reconstruction
  state = self.investigation_node.execute(state)
  # Step 6: Response Planning & Policy Gating
  state = self.response_node.execute(state)
  ```
  The pipeline executes strictly in this fixed order. There are no conditional edges, no dynamic replanning loops, and no planner evaluation controlling which node runs next.

### Finding 2: Planners are Detached from the Production Execution Path
- **Verdict:** **CONFIRMED**
- **Evidence:** `apps/agents/investigation_service.py` receives the email in `run_investigation()`, initializes `initial_state: SecurityState`, and immediately invokes `final_state = self.security_graph.run(initial_state)` (line 181). Neither `InvestigationPlanner`, `RuleBasedPlanner`, nor `LLMPlanner` are invoked during the execution of `SecurityGraph`.

### Finding 3: `HybridPlanner` is Instantiated but Never Actually Called
- **Verdict:** **CONFIRMED**
- **Evidence:** In `apps/agents/investigation_service.py`, line 127:
  ```python
  self.planner = HybridPlanner()
  ```
  A text search for `self.planner` across the entire `investigation_service.py` file yields exactly **one match**—the instantiation on line 127. It is never called, passed, or consulted anywhere else in the production service.

### Finding 4: The "Decision Trace" is a Synthetic Narrative Rather than a Projection of Real Planner Decisions
- **Verdict:** **CONFIRMED**
- **Evidence:**
  1. In `apps/agents/investigation_service.py` lines 417–595, `decision_trace` is constructed post-facto via an `if/else` ladder inspecting the already-computed `final_state`:
     - Line 458: `if has_unicode: decision_trace.append(DecisionRecord(...))`
     - Line 481: `if attachment_reports: decision_trace.append(DecisionRecord(...))`
     - Line 502: `if urls: decision_trace.append(DecisionRecord(...))`
  2. In lines 598–680, `tool_executions` records are synthesized post-facto with hardcoded execution durations:
     - Line 604: `duration_ms=4.2`
     - Line 619: `duration_ms=2.1`
     - Line 635: `duration_ms=7.8`
     - Line 650: `duration_ms=18.5`
     - Line 663: `duration_ms=24.0`
     - Line 678: `duration_ms=1.5`
  These entries do not represent real-time tool execution timestamps or dynamic planner decisions.

### Finding 5: URL Sandbox Uses Heuristics / Mock Telemetry Without Real Fetching or Browser Execution
- **Verdict:** **CONFIRMED**
- **Evidence:**
  1. `apps/sandbox/src/url_sandbox.py` lines 40–180: The method `analyze_url(url, simulated_landing_html, ...)` inspects `html = simulated_landing_html or ""`. If `simulated_landing_html` is not explicitly provided, it performs regex on an empty string. It never executes HTTP requests or fetches remote web content.
  2. `apps/sandbox/src/sandbox_runner.py` lines 55–75: `run_safe_observation()` iterates over `email_rep.urls` and generates synthetic `NetworkEvent` objects in memory without opening sockets or invoking Playwright.
  3. No Playwright browser binaries or execution routines are invoked in the production pipeline.

### Finding 6: AbuseIPDB is Mocked in the Working Tree
- **Verdict:** **CONFIRMED**
- **Evidence:** In `packages/threat_intel/src/free_feeds.py` lines 254–273:
  ```python
  def check_ip(self, ip_address: str) -> Dict[str, Any]:
      cache_key = f"abuseipdb:{ip_address}"
      cached = self.cache.get(cache_key)
      if cached:
          return cached

      is_allowed, reason, is_ssrf = self.network_guard.evaluate_destination(f"http://{ip_address}")
      is_internal = not is_allowed

      result = {
          "ip": ip_address,
          "ipAddress": ip_address,
          "query_status": "ok",
          "network_state": "DIRECT",
          "is_internal_or_restricted": is_internal,
          "is_malicious": False,
          "abuse_confidence_score": 0,
      }
      self.cache.set(cache_key, result)
      return result
  ```
  The method hardcodes `is_malicious: False` and `abuse_confidence_score: 0`. It never attempts an HTTP connection or API lookup.

### Finding 7: Response Actions Return Static SUCCESS Without Real Execution
- **Verdict:** **CONFIRMED**
- **Evidence:** In `apps/agents/core/tool_registry.py` lines 304–343:
  - Line 314: `block_sender` registered with lambda: `lambda p: {"status": "SUCCESS", "entry_added": True, "target": p.get("sender_or_domain")}`
  - Line 328: `block_ioc` registered with lambda: `lambda p: {"status": "SUCCESS", "firewall_synced": True, "ioc": p.get("ioc_value")}`
  - Line 342: `force_password_reset` registered with lambda: `lambda p: {"status": "SUCCESS", "reset_flagged": True, "user_id": p.get("user_id")}`
  No external firewall, mail gateway, or identity provider API is invoked.

### Finding 8: Mailbox Adapters (M365 / Gmail) Parse Webhook JSON Without Fetching Messages
- **Verdict:** **CONFIRMED**
- **Evidence:** In `apps/agents/ingestion/m365_adapter.py`, the adapter provides `handle_validation_handshake()` and `verify_and_parse_notification()`, but contains no HTTP client code to query the Microsoft Graph `/messages/{id}/$value` endpoint using OAuth tokens. `gmail_adapter.py` exhibits the same limitation.

### Finding 9: Multi-Tenancy Relies Primarily on `tenant_id` String Matching
- **Verdict:** **CONFIRMED**
- **Evidence:** State, attack graphs, and API endpoints rely on plain string filtering (`tenant_id = Form(...)` or `state["tenant_id"]`). No cryptographic token validation, tenant permission checks, or cross-tenant data access barriers exist.

### Finding 10: Previous Agentic Validation Tested Isolated Untracked Files Rather Than the Production Application
- **Verdict:** **CONFIRMED**
- **Evidence:** `investigation_planner.py` and `investigation_state.py` are untracked files. The earlier live validation reports tested `LLMPlanner` and `HybridPlanner` by directly importing them in test scripts (`tests/test_production_platform.py` / `tests/test_adaptability_suite.py`) rather than executing them through the production `SecurityGraph` or `apps/server.py` entry point.

---

## 4. Root Cause Analysis

The discrepancy occurred because two parallel architectures evolved:
1. **The Legacy Pipeline Architecture:** `SecurityGraph` (`apps/agents/graph.py`) with 6 sequential nodes (`IngestionNode` -> `EmailAnalysisNode` -> `ExposureNode` -> `VulnResearchNode` -> `InvestigationNode` -> `ResponseNode`), consumed by `InvestigationService.run_investigation()`.
2. **The Adaptive Investigation Planner Architecture:** `InvestigationPlanner` (`apps/agents/core/investigation_planner.py`) with `RuleBasedPlanner`, `LLMPlanner`, and `HybridPlanner` operating on `InvestigationState`.

The second architecture was developed and validated in isolation in `apps/agents/core/`, but was **never wired into `SecurityGraph` or `InvestigationService`**. `InvestigationService` simply instantiated `HybridPlanner` on line 127 and then ignored it, continuing to execute the legacy linear pipeline and synthesizing a mock decision trace afterwards.

---

## 5. Architectural Remediation Blueprint (Phases 6–17)

To eliminate all simulated, hardcoded, and disconnected behaviors:

1. **Phase 6–9: Integrate the Adaptive Investigation Loop into the Production Graph**:
   - Refactor `InvestigationNode` and `SecurityGraph` so that the actual investigation is driven by `InvestigationPlanner` (`RuleBasedPlanner`, `LLMPlanner`, or `HybridPlanner`).
   - The loop will follow:
     $$\text{Evidence} \to \text{Questions} \to \text{Planner} \to \text{SafetyGate} \to \text{ToolRegistry} \to \text{Tool Execution} \to \text{Evidence Update} \to \text{Replanning} \to \text{Stop/Escalate}$$
   - Causal adaptivity: tool execution results must directly alter the next planner decision.
2. **Phase 10: Wire `HybridPlanner` with Genuine Consensus**:
   - Parallel evaluation of `RuleBasedPlanner` and `LLMPlanner` proposals with explicit arbitration and observable rationale.
   - Clean fallback to `RuleBasedPlanner` when LLM is unavailable.
3. **Phase 11: Real URL Analysis & Transparent Sandbox Status**:
   - Real URL normalization and DNS resolution.
   - If Playwright is available on the host, run real controlled headless navigation.
   - If Playwright/network is unavailable, explicitly report status as `STATIC_ANALYSIS_ONLY` or `BROWSER_RUNTIME_UNAVAILABLE` without generating fake DOM events.
4. **Phase 12: Real Threat Intel Statusing**:
   - AbuseIPDB: If API key is not configured, explicitly report `ABUSEIPDB_UNAVAILABLE / NOT_CONFIGURED`, never return fake `is_malicious: False`.
   - CISA KEV: Explicitly label bundled records as `OFFLINE_SNAPSHOT`.
   - Quad9 / URLhaus: Retain verified live HTTP queries with proper error classification.
5. **Phase 13: Response Actions Integrity**:
   - Remove fake `lambda: {"status": "SUCCESS"}`.
   - State transition: `REQUESTED -> AUTHORIZED -> APPROVED -> DISPATCHED -> RESULT`.
   - If external connector (firewall, mail gateway, IdP) is not configured, return `NOT_CONFIGURED / UNAVAILABLE`. Never return `SUCCESS` without proof of external execution.
6. **Phase 14: Mailbox Ingestion Reality**:
   - Accurately label M365 and Gmail adapters as `WEBHOOK_PARSER_ONLY / NOT_CONFIGURED_FOR_POLLING`.
7. **Phase 15: Durable Investigation Persistence**:
   - Persist full `InvestigationState` (evidence, questions, hypotheses, planner decisions, tool outputs) to SQLite so investigations survive restarts.
8. **Phase 16: Multi-Tenant Authorization**:
   - Enforce tenant isolation and authorization checks preventing cross-tenant access.
9. **Phase 17: Genuine Runtime Event Trace**:
   - The UI Decision Trace must be generated exclusively from real, emitted planner and tool events, completely removing hardcoded `duration_ms` and static narrative templates.
