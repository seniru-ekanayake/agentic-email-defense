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

- **Browser DOM & Network Inspection Only**: The Playwright sandbox operates in a containerized headless browser. It records DOM tree elements, extracts form submission actions, detects credential-harvesting input fields, captures full-page visual screenshots, and monitors HTTP network requests.
- **NO Native Binary / PE Kernel Detonation**: The sandbox does **not** execute Windows Portable Executable (`.exe`, `.dll`) binaries, MSI installers, or PowerShell/VBScript payloads. It does not provide kernel-level instrumentation, memory dump analysis, or hypervisor-level OS emulation.
- **File Payloads**: Non-HTML file attachments are evaluated statically (SHA-256 hash lookup against CISA KEV/known threat databases, MIME magic mismatch detection, and archive structure evaluation). They are **not** dynamically executed.

---

## 4. Ingestion Connectors Status

The platform currently provides several email ingestion adapters, with differing levels of operational maturity:

| Connector | Status | Verified Functionality | Operational Limitation |
| :--- | :--- | :--- | :--- |
| **Raw RFC 822 / MIME (.eml)** | `VERIFIED` | Full parsing, attachment unpacking, header decoding, HTML sanitization. | Requires file drops or direct byte stream ingestion. |
| **M365 Graph Adapter** | `IMPLEMENTED / NOT FULLY VERIFIED` | OAuth2 authentication flow, Graph API schema parsing, message fetch. | Tested with simulated Graph responses; requires active Azure tenant registration and tenant admin consent for live mail polling. |
| **Gmail API Adapter** | `IMPLEMENTED / NOT FULLY VERIFIED` | Service account auth, REST message retrieval, label management. | Tested via mock API responses; live deployment requires Google Cloud Workspace project verification. |
| **IMAP Daemon** | `IMPLEMENTED / NOT FULLY VERIFIED` | Protocol connection, folder polling, SSL/TLS handshake. | Tested against standard local IMAP fixtures; high-concurrency connection pooling is not verified. |

---

## 5. SIEM & SOAR Integration Status

- **Webhooks**: `VERIFIED`. HTTP POST webhooks deliver structured JSON incident notifications upon forensic completion.
- **CEF / Syslog Export**: `PLANNED`. Formatting incident records into Common Event Format (CEF) strings is architecturally planned, but direct forwarder daemons to external SIEM collectors (e.g., Splunk HEC, Microsoft Sentinel data collectors) are not currently implemented.
- **Active Directory / Okta Identity Revocation**: `IMPLEMENTED / NOT FULLY VERIFIED`. Core remediation wrappers exist in `ToolRegistry` (Level 4 actions), but production credential provisioning to live Active Directory / Azure AD tenants requires customer-specific API credentials.

---

## 6. Trajectory Diversity vs. Forensic Reproducibility

A common misconception in agentic AI systems is that higher trajectory variance across identical inputs indicates superior intelligence. FishingMails explicitly rejects this premise:

- **The Forensic Stability Invariant**: When presented with identical forensic evidence (e.g., the same phishing email targeting the same organization), an enterprise forensic system **must arrive at consistent, repeatable, and legally defensible conclusions**.
- **Deliberate Convergence**: The system is designed to converge rapidly upon conclusive evidence. If SPF/DKIM verification and domain reputation conclusively confirm an email is malicious, continuing to invoke additional exploratory tools merely consumes unnecessary latency and token budget.

---

## 7. Storage & Concurrency Scaling Limits

- **Default SQLite Backend**: FishingMails utilizes SQLite (`data/fishingmails.db`) by default for state tracking and local attack graph relationships. SQLite is suitable for single-node installations and throughput up to $\approx 50$ concurrent investigations. High-volume enterprise installations processing hundreds of messages per second require transitioning to PostgreSQL for state storage and Neo4j for large-scale graph analytics.
- **In-Memory Cache**: Investigation state caches reside in-memory per worker process. Distributed multi-node worker fleets require external cache synchronization (e.g., Redis).
