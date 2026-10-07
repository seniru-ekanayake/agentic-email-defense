# Limitations

Read this before deploying.

## Detection

- Detection is rule-based over parser, attachment, reputation and static-fetch evidence. It is a
  triage aid, not a replacement for a secure email gateway.
- Correctness is checked against a small labelled corpus (`tests/test_verdict_accuracy.py`, 15
  messages, offline). That is a regression guard, **not** an accuracy measurement. Measure precision
  and recall on your own mail before relying on verdicts.
- URL analysis is a static HTTP fetch: no JavaScript execution, no browser rendering, and no file
  detonation. Attachments are inspected statically.
- With no reputation feed available (no `URLHAUS_AUTH_KEY`, Quad9 unreachable), links are judged only
  by deceptive-text and static-fetch evidence.
- CVE attribution is limited to patterns with a clear mapping (for example, the Outlook MonikerLink
  form maps to CVE-2024-21413). Other moniker/UNC links are flagged as forced-authentication attempts
  without a CVE. The bundled KEV subset must be refreshed with `scripts/refresh_kev.py`.
- Sender history counts only incidents already investigated in the same tenant, so a new deployment
  sees every sender as new.

## LLM planner

- Optional. Without `OPENROUTER_API_KEY`, the rule planner is used.
- LLM calls add seconds per planning step and are subject to provider rate limits. The rule planner
  takes milliseconds.
- The LLM only selects which read-only tool to run next; verdicts never depend on it.

## Response

- Containment is delivered through webhook connectors you operate (see [CONNECTORS.md](CONNECTORS.md)).
  There are no built-in Microsoft Graph, Okta or gateway integrations.
- Autonomy is fixed at level 1: every MEDIUM-or-higher action needs an analyst approval.

## Operations

- Investigations run synchronously within the upload request. SSE replays a finished investigation's
  events; it does not show progress while the request is still running.
- SQLite is single-node. Run one API process per database file, and back up the file and its `-wal`.
- No built-in rate limiting or SSO login: front the API with a gateway, and issue JWTs from your IdP.
- Mailbox ingestion (M365/Gmail/IMAP) is not connected; emails must be submitted via the API.
