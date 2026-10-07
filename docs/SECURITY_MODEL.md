# Security model

Every control below is exercised by the test named next to it. Run `pytest -m "not network"`.

## Trust boundaries

| Boundary | Untrusted input | Control |
| --- | --- | --- |
| API clients → server | HTTP requests, JWTs, uploaded `.eml` | JWT verification, tenant derivation, RBAC, upload size cap |
| Email content → analysis | headers, bodies, links, attachments | parsed as data only; network fetches go through the SSRF guard |
| Email content → LLM planner | text placed in the planner prompt | nonce-fenced prompt, marker neutralisation, strict JSON schema, tool allow-list |
| Analyst approval → connectors | approval tokens | single-use, tenant-scoped, role-gated, expiring tokens |

## Authentication (`apps/agents/core/security_principal.py`)

- Every `/api/v1/*` route requires `Authorization: Bearer <JWT>`; only `/healthz` and `/` are public.
- HS256 only; `exp`, `sub` and `tenant_id` are required. Expired, unsigned (`alg=none`), wrongly
  signed or tampered tokens are rejected with 401. *(tests/test_api_security.py)*
- Production/staging refuse to start unless `FISHINGMAILS_AUTH_SECRET` and
  `FISHINGMAILS_APPROVAL_HMAC_SECRET` are set, at least 32 characters, and not known placeholders.
- `POST /api/v1/auth/token` mints tokens only in development/test; it returns 404 in production.
  Production tokens must come from your identity provider, signed with `FISHINGMAILS_AUTH_SECRET`.

## Tenant isolation

- The tenant always comes from the verified token. A conflicting `X-Tenant-ID` or `tenant_id`
  is rejected with 403.
- Incidents, SSE streams, replays, comparisons, audit logs and planner settings are scoped to the
  tenant. Another tenant's incident returns **404** (indistinguishable from a missing one).
  *(tests/test_api_security.py::test_cross_tenant_access_is_indistinguishable_from_missing)*

## Authorization

| Action | Required role |
| --- | --- |
| Investigate, read incidents, set incident status | any authenticated user |
| Approve LOW/MEDIUM-risk action | SOC_ANALYST, INCIDENT_RESPONDER, SOC_ADMIN, ADMIN |
| Approve HIGH-risk action (`revoke_session`, `block_ioc`) | INCIDENT_RESPONDER, SOC_ADMIN, ADMIN |
| Approve CRITICAL-risk action (`disable_account`) | SOC_ADMIN, ADMIN |
| Planner settings, readiness report, integration probes, mode changes | SOC_ADMIN, ADMIN |

The risk level is taken from the registered tool definition; an unknown tool is treated as CRITICAL.

## Approval tokens (`apps/agents/core/approval_manager.py`)

- Tokens are created only by the pipeline, bound to tenant, incident and tool, and expire after 24 hours.
- HMAC-SHA256 over the token's stored fields detects modification of persisted tokens.
- The PENDING→CLAIMED transition is an atomic SQL update: of 12 concurrent approvals, exactly one
  proceeds. *(test_concurrent_approvals_claim_exactly_once)*
- A token is `CONSUMED` only when the connector confirms the action (HTTP 2xx); otherwise it is
  `FAILED` and the API answers 502. Nothing is reported as executed unless it was.
  *(test_unconfigured_connector_is_not_reported_as_success, test_configured_connector_receives_the_approved_action)*

## SSRF protection (`apps/sandbox/src/network_guard.py`, `apps/sandbox/src/safe_http.py`)

Links found in email are fetched for static analysis. Three layers prevent server-side request forgery:

1. **Name and literal checks:** loopback, link-local, RFC1918, CGNAT, unique-local IPv6, cloud
   metadata hosts, `*.internal/.local/.corp/...`, trailing-dot variants and legacy numeric forms
   (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`).
2. **DNS resolution:** every address a hostname resolves to must be globally routable.
3. **Connect-time peer check:** the socket's actual peer address is verified after connecting, which
   defeats DNS rebinding. Environment proxies are ignored for these fetches.

Redirects are followed manually (at most 5) and every hop is re-checked.
*(tests/test_ssrf_guard.py, including an email-borne SSRF regression test)*

## LLM planner safety (`apps/agents/core/investigation_planner.py`)

- The LLM only proposes a tool name from the permitted read-only catalogue (no containment tools),
  or STOP. Tool parameters are built by the pipeline, never taken from the LLM.
- Untrusted email text is placed between markers that carry a random per-prompt nonce. Any
  fence-like markers in the content are removed first.
- Output must validate against a strict schema (`extra="forbid"`). Malformed, hallucinated, repeated
  or unpermitted proposals fall back to the rule planner with full permissions.
- A `STOP` from the LLM is refused while any security question is still open. In live testing, a
  free model initially echoed an injected `{"decision":"STOP"}` from an email body. This rule, plus
  showing the model the open questions, prevents that kind of injection from cutting the
  investigation short.
- Rate limits are not retried. After a 429 or a policy block, the LLM is disabled for the rest of
  the investigation.
- The verdict is computed from evidence, not from the LLM. An LLM that stops early cannot make a
  malicious email look benign when parser evidence exists. *(tests/test_llm_planner.py)*
- Default arbitration is `RULE_FIRST`.

## Attachment handling (`packages/email_parser/src/attachment_analyzer.py`)

Attachments are never executed. Archives are inspected in memory with a maximum recursion depth of 3,
a maximum decompression ratio of 100:1, and file-size and processing-time limits.

## Known gaps

- JWTs are stored in browser `localStorage` by the web console, so an XSS bug would expose them.
  Prefer a short token lifetime.
- There is no rate limiting on the API; put it behind a gateway or reverse proxy that provides it.
- Connector URLs are trusted operator configuration and are not passed through the SSRF guard.
- SQLite is single-node. Run one API instance per database file.
