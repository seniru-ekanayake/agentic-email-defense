# FishingMails Operational Limitations & Boundaries

> **Platform Status:** `v1.0.0-RC1` (Release Candidate)  
> **Document Version:** 1.0  
> **Last Updated:** 2026-10-01  

---

## 1. Honest Architectural & Operational Boundaries

FishingMails is designed with an explicit commitment to transparency regarding its capabilities, latency profiles, and threat handling boundaries. This document outlines the verified constraints and known operational limitations of the platform at `v1.0.0-RC1`.

---

## 2. External LLM Dependency & Latency Profile

### 2.1 Latency Constraints
Investigations operating in `LLM_PLANNER` or `HYBRID` modes exhibit a substantial latency penalty compared to the deterministic `RULE_ENGINE`:

| Planner Mode | Mean Latency | Median (P50) | 95th Percentile (P95) | 99th Percentile (P99) | Suitability |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`RuleBasedPlanner`** | **0.012 s** | **0.010 s** | **0.025 s** | **0.040 s** | **Inline SMTP / MTA Gateway** |
| **`LLMPlanner` (OpenRouter)** | **10.59 s** | **5.90 s** | **34.35 s** | **73.36 s** | **Out-of-Band / SOC Copilot** |
| **`HybridPlanner`** | **11.20 s** | **6.10 s** | **35.10 s** | **74.50 s** | **Out-of-Band / Deep Forensics** |

- **Real-Time SMTP Pipeline Unsuitability**: Because the `LLMPlanner` requires an average of 10.6 seconds per planning step (and up to 34+ seconds under network congestion), **it cannot be deployed as an inline synchronous MTA gateway filter** without causing mail queue delivery timeouts.
- **Recommended Deployment**: The deterministic `RuleBasedPlanner` is suited for initial inline triage; `LLMPlanner` is designed for out-of-band asynchronous processing or tier-2 SOC escalation.

### 2.2 Free-Tier Model Rate-Limiting & HTTP 429 Trapping
- **Empirical Findings**: During multi-turn investigations involving rapid sequential replanning turns (3 to 5 iterations within 30 seconds), public free-tier models (such as `meta-llama/llama-3.3-70b-instruct:free` on OpenRouter) frequently trigger upstream HTTP 429 (Too Many Requests) throttling.
- **System Behavior**: FishingMails safely traps HTTP 429 exceptions and triggers immediate fallback to `RuleBasedPlanner`. However, organizations requiring sustained LLM investigation volume must configure dedicated, paid enterprise API endpoints or local high-throughput inference instances (e.g., vLLM or Ollama).

---

## 3. Dynamic Execution & Sandbox Scope

FishingMails provides a sandboxed URL inspection environment with explicit functional limitations:

- **Browser Runtime Status**: On headless host environments lacking Playwright browser binaries, browser automation is declared transparently as `BROWSER_RUNTIME_UNAVAILABLE`. In this mode, link analysis operates via `STATIC_URL_ANALYSIS` and live HTTP network fetches protected by `NetworkGuard`.
- **NO Native Binary / PE Kernel Detonation**: The sandbox does **not** execute Windows Portable Executable (`.exe`, `.dll`) binaries, MSI installers, or PowerShell/VBScript payloads. Attachment inspection is strictly static: archive container parsing, PE header extraction, and MOTW bypass identification.
- **Threat Intelligence Feed Keys**: AbuseIPDB queries require `ABUSEIPDB_API_KEY`. If unconfigured, the engine returns `NOT_CONFIGURED / UNAVAILABLE` and relies on Quad9 DoH and URLhaus feeds.
- **CISA KEV Snapshot**: The bundled CISA Known Exploited Vulnerabilities catalog is an offline snapshot dated `2024-02-13`. Live updates require scheduled sync.

---

## 4. Ingestion Connectors Status

The platform currently provides several email ingestion adapters, with differing levels of operational maturity:

| Connector | Status | Verified Functionality | Operational Limitation |
| :--- | :--- | :--- | :--- |
| **Raw RFC 822 / MIME (.eml)** | `VERIFIED` | Full parsing, attachment unpacking, header decoding, HTML sanitization. | Requires file drops or direct byte stream ingestion. |
| **M365 Graph Adapter** | `WEBHOOK_PARSER_ONLY` | Inbound JSON webhook payload parsing into canonical models. | Active polling/syncing requires tenant admin credentials. |
| **Gmail API Adapter** | `WEBHOOK_PARSER_ONLY` | Inbound push notification payload parsing into canonical models. | Active REST message retrieval requires Google Workspace service account. |
| **IMAP Daemon** | `WEBHOOK_PARSER_ONLY` | Protocol schema mapping and parser normalization. | High-concurrency background mailbox sync requires dedicated worker daemon. |

---

## 5. Defensive Response Actions Status

- **Safety Gate**: `VERIFIED`. High-risk actions (`quarantine_email`, `revoke_session`, `disable_account`, `block_sender`, `block_ioc`, `force_password_reset`) are strictly held for human analyst approval at tenant autonomy levels 1 and 2.
- **External Dispatchers**: `CONFIG_REQUIRED`. Unless live mail gateway (`MAIL_GATEWAY_URL`), IdP (`IDP_API_URL`), or firewall APIs are configured in the environment, response actions return:
  ```json
  {
    "status": "NOT_CONFIGURED",
    "execution_state": "DISPATCH_FAILED",
    "confirmed": false,
    "detail": "Target connector is NOT_CONFIGURED in this environment. Action proposed but not dispatched."
  }
  ```
  The platform **never** returns fake static `SUCCESS` for unconfigured connectors.

---

## 6. Trajectory Diversity vs. Forensic Reproducibility

A common misconception in agentic AI systems is that higher trajectory variance across identical inputs indicates superior intelligence. FishingMails explicitly rejects this premise:

- **The Forensic Stability Invariant**: When presented with identical forensic evidence (e.g., the same phishing email targeting the same organization), an enterprise forensic system **must arrive at consistent, repeatable, and legally defensible conclusions**.
- **Deliberate Convergence**: The system is designed to converge rapidly upon conclusive evidence. If SPF/DKIM verification and domain reputation conclusively confirm an email is malicious, continuing to invoke additional exploratory tools merely consumes unnecessary latency and token budget.

---

## 7. Storage & Concurrency Scaling Limits

- **Default SQLite Backend**: FishingMails utilizes SQLite (`data/fishingmails.db`) by default for state tracking and local attack graph relationships. SQLite is suitable for single-node installations and throughput up to $\approx 50$ concurrent investigations. High-volume enterprise installations processing hundreds of messages per second require transitioning to PostgreSQL for state storage and Neo4j for large-scale graph analytics.
- **In-Memory Cache**: Investigation state caches reside in-memory per worker process. Distributed multi-node worker fleets require external cache synchronization (e.g., Redis).
