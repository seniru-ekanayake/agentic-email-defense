# Handover: FishingMails → Antigravity

**From:** Claude Code session · **Date:** 2026-10-08 · **Repo:** https://github.com/seniru-ekanayake/agentic-email-defense (`main`)
**Local path:** `C:\Enterprise Agentic Email Exploitation Detection & Response Platform`

This document explains what FishingMails is today, everything changed in this session, how to run it locally,
and what is still open. Read it before making changes.

---

## 1. TL;DR: open the app

Run this in PowerShell from the repository root:

```powershell
# Optional: real LLM planning (free OpenRouter models only). Ask the owner for the key; never commit it.
$env:OPENROUTER_API_KEY = "<key>"

powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1
```

The script:
1. Creates `.venv` and installs `requirements-dev.txt` on first run.
2. Installs `apps/web` dependencies on first run.
3. Opens two windows: **API on http://localhost:8000** and **console on http://localhost:3000**.
4. Mints a development token (tenant `tenant-dev`, roles analyst + responder + admin), **copies it to the
   clipboard** and opens the browser.
5. If `OPENROUTER_API_KEY` is set, switches the tenant to hybrid planning (LLM_FIRST) with
   `nvidia/nemotron-3-super-120b-a12b:free`.

Then, in the console:
1. Click **🔑 Session Auth**, paste the token, then click **Apply & Sync**.
2. Click **+ Upload & Investigate EML** and pick a file from `tests/fixtures/corpus/`, for example
   `04_phish_spf_fail_url.eml`.
3. Watch the **pixel agents** and the live event stream. Each **DECISION** card shows the reasoning steps;
   expand **💭 Model thought chain** to read the LLM's own thoughts (LLM mode only).
4. When containment is proposed, the approval modal opens. With no connector configured, approving honestly
   reports `NOT_CONFIGURED` (HTTP 502), because nothing was actually done.
5. Click an incident in the ledger, then open **04 DECISIONS** to review the full decision trace later.

Stop everything by closing the two windows. Script options: `-Tenant <name>`, `-Model <free model id>`, `-NoBrowser`.

### Manual start (if you prefer)

```powershell
# Backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
$env:FISHINGMAILS_ENV = "development"
.\.venv\Scripts\python -m uvicorn apps.server:app --host 127.0.0.1 --port 8000

# Frontend (second terminal)
cd apps\web
npm ci
node node_modules/next/dist/bin/next dev -p 3000     # NOT `npm run dev`: see gotcha #1

# Token (third terminal)
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/auth/token -ContentType application/json `
  -Body '{"tenant_id":"tenant-dev","roles":["SOC_ANALYST","INCIDENT_RESPONDER","SOC_ADMIN"]}'
```

---

## 2. What FishingMails is

An email-threat investigation service. Its parts:

- A FastAPI backend parses a `.eml` message.
- A planner (rule-based, LLM, or hybrid) picks read-only tools: Unicode analysis, Quad9 and URLhaus
  reputation, an SSRF-guarded link fetch, attachment analysis, DNS, sender history and a CISA KEV lookup.
- A verdict engine scores only recorded evidence. Every risk point cites an evidence ID.
- Malicious verdicts propose containment that an analyst must approve. Approved actions go to webhook
  connectors the operator runs.
- A Next.js 16 console shows the incident ledger, a live event stream with pixel agents, reasoning
  cards and the approvals.

Read in this order: `README.md` → `docs/ARCHITECTURE.md` → `docs/SECURITY_MODEL.md` → `docs/LIMITATIONS.md`.

---

## 3. What happened in this session

### Phase 1: Independent audit (no code changes)
The repo as received (commit `490c103`) was audited by running it. The key findings:

| Finding | Impact |
| --- | --- |
| A hardcoded `X-OWA-Version` header in `ExposureNode` attached **CVE-2023-35636** to every email | **Every email (even a lunch invite or garbage bytes) came back CRITICAL** |
| CVE-2023-35636 is **not** in CISA KEV; the "authoritative" 2-entry KEV file fabricated it | False "known exploited" claims |
| Graph read `headers["subject"]` / `body_plain`, but the parser emits `Subject` / `body.text_plain` | Tools analysed the string "No Subject" instead of the email |
| "Forensic audit" fields were constants (Quad9 200/14.2 ms, a "Playwright" sandbox, `llm_calls: NOT_CONFIGURED`) | The UI showed fabricated measurements |
| Missing Authentication-Results reported as "SPF: Pass" | False assurance |
| SSRF: emailed links resolving to internal IPs were fetched | Security vulnerability |
| Approvals said "SUCCESS executed" while nothing was dispatched | Misleading containment |
| SSE parser split on a literal `\\n`; the frontend build lacked `autoprefixer` | Live stream never rendered; clean build failed |
| 42 self-written "audit/verification" documents claiming production readiness | Documentation contradicted the code |

### Phase 2: Fixes (commit `218d0c4`)
- New **verdict engine** (`apps/agents/core/verdict_engine.py`): evidence-only scoring with per-factor evidence IDs.
- Parser evidence seeding and field wiring fixed; auth is PASS / FAIL / UNKNOWN; MonikerLink `file:///\\host` detected.
- Fabricated forensic, telemetry and trust values removed and replaced by real measurements.
- **SSRF:** name checks, DNS resolution and a connect-time peer check (`apps/sandbox/src/safe_http.py`).
- **Approvals:** RBAC by risk, single-use atomic claim, incident binding; `DISPATCHED` only on connector 2xx, otherwise 502.
- Tenant isolation returns 404 cross-tenant; all API routes need a JWT except `/healthz`.
- KEV subset regenerated from the live CISA feed (`scripts/refresh_kev.py`).
- Frontend: SSE fix, Next.js 14 → **16** + React 19 (`npm audit` clean), honest labels.
- Packaging: `requirements.txt`, Dockerfiles, compose, CI over all tests.
- Removed the self-audit documents, the static legacy dashboard and dead modules; rewrote the docs.

### Phase 3: Real LLM testing and hardening
Live runs against OpenRouter **free** models exposed bugs that the scripted tests had missed. All are fixed:
- In LLM-only mode the model saw no open questions, so it stopped immediately. The prompt now includes them.
- The model **obeyed an injected `{"decision":"STOP"}`** from an email. A STOP is now refused while questions are open.
- Alias tool names allowed duplicate runs; aliases are now hidden and mapped to canonical names.
- Quota safety: free models only (`OPENROUTER_FREE_MODELS_ONLY=true` by default), no retry on 429,
  a per-investigation circuit breaker, JSON mode.
- `google/gemma-4-31b-it:free` was rate-limited upstream; **`nvidia/nemotron-3-super-120b-a12b:free` works**.

### Phase 4: Explainability and UX (commit `94d05ba`)
- **Reasoning on every decision:** `reasoning_steps`, `reasoning_trace` (the model's thought text),
  `llm_proposal` and `override_reason`, streamed and persisted.
- **Background investigations:** `POST /api/v1/investigations` → 202, live SSE with `agent.thinking` events.
- **Pixel agents** (`apps/web/src/components/PixelAgents.tsx`) and reasoning cards (`ReasoningCard.tsx`).
- **Skills/playbooks** recorded on incidents and given to the LLM; the **MCP** stdio servers now handle `initialize`.
- Quad9 moved to plain DNS on UDP/53 (9.9.9.9 filtered vs 9.9.9.10 unfiltered); the JSON DoH port timed
  out and added about 12 s per email with links.
- Benchmarks: `scripts/benchmark.py`, `scripts/compare_verdicts.py`, `docs/BENCHMARKS.md`.
- README rewritten with screenshots and `assets/agents-live.gif`.

### Phase 5: This handover
- `scripts/start-dev.ps1`: one-command local launcher (tested).
- `HANDOVER.md`: this file.

---

## 4. Key files

| Area | Path |
| --- | --- |
| API routes | `apps/server.py` |
| Investigation report assembly | `apps/agents/investigation_service.py` |
| Pipeline and tool loop | `apps/agents/graph.py` |
| Planners (rule / LLM / hybrid), prompt, guardrails | `apps/agents/core/investigation_planner.py` |
| Verdict scoring | `apps/agents/core/verdict_engine.py` |
| LLM client (OpenRouter, free-only guard) | `apps/agents/core/llm_gateway.py` |
| Tools and approval gating | `apps/agents/core/tool_registry.py`, `apps/agents/core/approval_manager.py` |
| Event bus (thread-safe SSE) | `apps/agents/core/event_system.py` |
| Storage (SQLite WAL) | `apps/agents/core/durable_storage.py` |
| Threat intel (Quad9, URLhaus) | `packages/threat_intel/src/free_feeds.py` |
| SSRF guard | `apps/sandbox/src/network_guard.py`, `apps/sandbox/src/safe_http.py` |
| MCP servers | `apps/agents/core/mcp_servers/` |
| Skills / playbooks | `apps/agents/skills/` |
| Console | `apps/web/src/app/page.tsx`, `apps/web/src/components/` |
| Test harness (offline sandbox, env isolation) | `conftest.py`, `pytest.ini` |

---

## 5. Tests and benchmarks

```powershell
.\.venv\Scripts\python -m pytest -m "not network"          # 275 tests, ~15 s, fully offline
$env:OPENROUTER_API_KEY="<key>"; .\.venv\Scripts\python -m pytest -m llm_live -s   # ~6 free requests
.\.venv\Scripts\python scripts\benchmark.py --manifest scripts\benchmark_manifest.csv --planner RULE --offline
```

- `conftest.py` blocks all non-loopback TCP, UDP and DNS for the whole session, and restores `os.environ` after
  every test. A test that needs the internet must be marked `@pytest.mark.network`.
- CI (`.github/workflows/ci.yml`) runs `pytest -m "not network"` plus `npm run build` and `npm audit`.

Current numbers on the 15-message regression corpus: precision and recall 1.00, FPR 0; rule latency p50 15 ms
offline, p95 0.56 s online; LLM 2–50 s per step. This is a regression check, **not** a real-world accuracy claim.

---

## 6. Rules for the next agent

1. **Never commit secrets.** The OpenRouter key lives only in the environment. Before pushing, run
   `git grep -n "sk-or-v1-"`; it must return nothing.
2. **Free LLM models only.** Free-tier quotas are small (about 50 requests a day). The LLM benchmark over the full
   corpus costs about 60 requests. Prefer the scripted LLM tests (`tests/test_llm_planner.py`) while developing.
3. **Do not reintroduce fabricated values.** Every number shown to an analyst must come from something that ran.
4. **The verdict must never depend on the LLM.** The LLM only chooses which read-only tool to run next.
5. Keep `assets/logo.png` and the dashboard screenshots (`assets/dashboard-console.png`, `assets/dashboard.png`).
   The owner asked for these never to be removed.
6. The owner commits directly to `main`.

---

## 7. Gotchas

1. **The `&` in the project path breaks npm/npx shims on Windows** (`npm run dev`, `npx tsc` fail with
   `Cannot find module 'C:\...'`). Use `node node_modules/next/dist/bin/next <cmd>`, or run from a copy at a
   path without `&`. `npm ci` / `npm install` work.
2. **Quad9 needs UDP/53 egress** to 9.9.9.9 and 9.9.9.10. If it is blocked, reputation shows `UNAVAILABLE`
   (the investigation still works).
3. **URLhaus** needs `URLHAUS_AUTH_KEY`; without it, it reports `not_configured` rather than failing silently.
4. **Background investigations are in-process.** Restarting the API mid-run loses that investigation, and live
   streaming needs a single API process.
5. **Dev vs prod:** `FISHINGMAILS_ENV=development` enables the token endpoint. In production it returns 404 and
   the server refuses to start without two secrets of 32+ characters.
6. **Free models are slow and sometimes congested.** Nemotron returns up to about 8k reasoning tokens per step
   (5–70 s); on 429 the rule planner takes over for that investigation.

---

## 8. Open items / next steps

| Priority | Item |
| --- | --- |
| High | **Rotate the OpenRouter key.** It was pasted into a chat during this session. |
| High | Add a `LICENSE` (the owner's choice; the old README claimed one that did not exist) |
| High | Evaluate on a real, representative labelled corpus (`docs/BENCHMARKS.md` explains how) |
| Medium | Connect an identity provider for production JWTs; there is no login UI |
| Medium | Implement connectors (mail gateway quarantine, IdP session revoke) per `docs/CONNECTORS.md` |
| Medium | Durable job queue for background investigations; API rate limiting |
| Medium | Build and run the Docker images. They were written but **not tested** in this session. |
| Low | Persist frontend auth more safely than `localStorage`; add a UI for planner settings |
| Low | `FISHINGMAILS_INDEPENDENT_AUDIT.md` (the session's audit report, pre-fix state) is uncommitted in the working tree; commit it to `docs/` or delete it |
