# Architecture

## Components

| Component | Code | Role |
| --- | --- | --- |
| API server | `apps/server.py` | FastAPI app: auth, tenant scoping, investigations, approvals, SSE, settings |
| Investigation service | `apps/agents/investigation_service.py` | Runs the pipeline and builds the incident report from recorded evidence |
| Pipeline | `apps/agents/graph.py` | Parser evidence seeding → planner/tool loop → context nodes → verdict → report → response |
| Planner | `apps/agents/core/investigation_planner.py` | Rule planner (default), optional LLM planner, hybrid arbitration |
| Verdict engine | `apps/agents/core/verdict_engine.py` | Single source of the risk score, severity and verdict |
| Tool registry | `apps/agents/core/tool_registry.py` | Analysis and response tools; risk-based approval gating |
| Approvals | `apps/agents/core/approval_manager.py` | Signed, single-use, role-gated approval tokens |
| Storage | `apps/agents/core/durable_storage.py` | SQLite (WAL): incidents, evidence, decisions, tools, events, approvals, audit, settings |
| Parser | `packages/email_parser/` | MIME, headers, Authentication-Results, URLs/URI schemes, Unicode, attachments |
| URL analysis | `apps/sandbox/src/url_sandbox.py` | SSRF-guarded static HTTP fetch: redirects, credential forms, brand impersonation |
| Web console | `apps/web/` | Next.js client for the API |

## Investigation flow

```
POST /api/v1/investigations (.eml)  → 202 {incident_id}; runs in a worker thread
  (POST /api/v1/investigate is the synchronous variant)
  │
  ├─ IngestionNode ── MimeParser.parse_eml
  │
  ├─ Seed typed evidence from the parser
  │     AUTHENTICATION (PASS / FAIL / UNKNOWN), URL_NORMALIZED, DECEPTIVE_LINK,
  │     UNICODE_ANOMALY, MONIKER_URI, UNC_PATH, ACTIVE_SCRIPT, DATA_URI, CVE_CANDIDATE
  │
  ├─ Match forensic playbooks (apps/agents/skills) → activated_skills + LLM guidance
  │
  ├─ Planner loop (max 15 steps); before each step an agent.thinking event is streamed
  │     questions: Q-01 auth · Q-02 unicode · Q-03 link reputation · Q-04 forced auth
  │                Q-05 attachments · Q-06 KEV status of a referenced CVE
  │     tools (read-only): UnicodeAnalyzer, ThreatIntelFeeds (Quad9 + URLhaus),
  │                        UrlSandboxRunner, AttachmentAnalyzer, dns_spf_dmarc_recon,
  │                        query_sender_history, CisaKevCorrelator
  │     each result is stored as typed evidence; the planner re-plans on it
  │     each decision records reasoning_steps, the LLM's thought text (reasoning_trace),
  │     the LLM proposal and any override_reason, and streams them as agent.planner.selected
  │
  ├─ ExposureNode ── records the recipient domain (no fingerprinting without real data)
  ├─ VulnResearchNode ── NVD/KEV context for CVE candidates only
  ├─ verdict_engine.compute_verdict(evidence) → score, severity, verdict, factors[evidence_id]
  ├─ InvestigationNode ── title, attack chain, MITRE mapping from observed evidence
  └─ ResponseNode ── proposals from the verdict; MEDIUM+ actions held for approval
  │
  └─ persisted to SQLite; GET /api/v1/investigations/{id}/events streams live, then replays from storage
```

## Verdict scoring

Each evidence type contributes at most once:

| Evidence | Points |
| --- | --- |
| Moniker URI / UNC path | 45 |
| Threat-intel reputation: malicious | 45 |
| URL analysis: MALICIOUS / BLOCKED_SSRF / SUSPICIOUS | 35 / 20 / 15 |
| Authentication failure (SPF/DMARC) | 25 |
| Deceptive link (text ≠ destination) | 25 |
| Unicode obfuscation, active scripting | 20 each |
| Attachment risk | 0.6 × attachment score |
| Mark-of-the-Web evasion container | 15 |
| CVE confirmed in CISA KEV | 10 |
| Inline data URI | 10 |

Severity: ≥70 CRITICAL, ≥45 HIGH, ≥20 MEDIUM, otherwise LOW. Verdict: ≥45 MALICIOUS (quarantine is
proposed), ≥20 SUSPICIOUS, otherwise BENIGN. Every factor cites the evidence ID that produced it,
which appears in the incident's `risk_provenance`.

## Planner modes

`RULE` uses deterministic information-gain selection. `LLM` uses an OpenRouter model to propose the
next tool, falling back to rules. `HYBRID` (default) runs both and arbitrates under a policy
(default `RULE_FIRST`). `AUTO` currently behaves like `HYBRID` because no risk score exists before the investigation runs. Settings are per tenant
(`/api/v1/planner-settings`). The planner chooses *which evidence to gather*; it never decides the verdict.

## Data

SQLite with WAL at `FISHINGMAILS_DB_PATH`. Tables: `incidents`, `evidence_items`, `decision_records`,
`tool_executions`, `investigation_states`, `agent_events`, `approval_tokens`, `audit_logs`
(tenant-indexed), `platform_settings`, `campaign_clusters`, `attack_graph_nodes/edges`.

## Library code not wired into the server

These are present and unit-tested but not called by the API: mailbox ingestion adapters
(`apps/agents/ingestion/`), SIEM forwarder (`packages/threat_intel/src/siem_forwarder.py`), and the
Neo4j attack-graph repository (`packages/attack_graph/src/neo4j_repository.py`). The DNS and telemetry
helpers in `apps/agents/core/mcp_servers/` are called in-process by the pipeline and can also run as MCP
stdio servers (`initialize`, `tools/list`, `tools/call`) for any MCP client.

## Live events

| Event | Meaning |
| --- | --- |
| `agent.started` | Investigation accepted |
| `agent.thinking` | Planner deciding the next step (step number, open questions) |
| `agent.planner.selected` | Decision with rationale, reasoning steps, thought text, LLM proposal, override reason |
| `agent.tool.executed` | Tool finished (duration, status) |
| `agent.evidence.created` | New typed evidence record |
| `agent.proposal.created` | Containment proposal awaiting approval (carries the approval token) |
| `agent.completed` / `agent.failed` | Terminal events; the stream closes after them |
