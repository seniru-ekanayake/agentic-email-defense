# Response connector contract

FishingMails does not call Microsoft Graph, Okta, Exchange or firewall APIs directly. Each response
action is delivered to an HTTP endpoint you operate (an adapter, SOAR webhook, Logic App, etc.) that
performs the real change in your environment.

## Request

```
POST <CONNECTOR_URL>
Content-Type: application/json
Authorization: Bearer <CONNECTOR_TOKEN>      # only when a token is configured
User-Agent: FishingMails-AutomatedResponse/1.0

{
  "action": "quarantine_email",
  "parameters": { "message_id": "<...>", "mailbox": "bob@example.com" },
  "timestamp": "2026-10-08T12:00:00+00:00"
}
```

Timeout: 3 seconds. No retries.

## Response semantics

| Connector response | FishingMails result | Approval token |
| --- | --- | --- |
| HTTP 2xx | `DISPATCHED` (HTTP 200 to the analyst); JSON body stored as `remote_response` | `CONSUMED` |
| HTTP 401/403 | `AUTH_FAILED` (HTTP 502 to the analyst) | `FAILED` |
| HTTP 429 | `RATE_LIMITED` (HTTP 502) | `FAILED` |
| Any other status, timeout, or network error | `DISPATCH_FAILED` / `TIMEOUT` / `NETWORK_ERROR` (HTTP 502) | `FAILED` |
| URL not configured | `NOT_CONFIGURED` (HTTP 502) | `FAILED` |

Return 2xx **only after** the action has actually been carried out. FishingMails treats 2xx as confirmation.

## Actions and environment variables

| Action | Risk | Approval needed at autonomy L1 | URL variable | Token variable | Parameters |
| --- | --- | --- | --- | --- | --- |
| `quarantine_email` | MEDIUM | yes (any analyst) | `MAIL_GATEWAY_URL` (or `M365_GRAPH_ENDPOINT`) | `MAIL_GATEWAY_TOKEN` | `message_id`, `mailbox` |
| `block_sender` | MEDIUM | yes (any analyst) | `GATEWAY_BLOCK_URL` | `GATEWAY_BLOCK_TOKEN` | `sender_or_domain`, `reason` |
| `force_password_reset` | MEDIUM | yes (any analyst) | `IDP_PASSWORD_RESET_URL` | `IDP_PASSWORD_RESET_TOKEN` | `user_id` |
| `revoke_session` | HIGH | yes (INCIDENT_RESPONDER+) | `IDP_API_URL` | `IDP_API_TOKEN` | `user_id` |
| `block_ioc` | HIGH | yes (INCIDENT_RESPONDER+) | `FIREWALL_API_URL` | `FIREWALL_API_TOKEN` | `ioc_value`, `ioc_type` |
| `disable_account` | CRITICAL | yes (SOC_ADMIN/ADMIN) | `ACTIVE_DIRECTORY_URL` | `ACTIVE_DIRECTORY_TOKEN` | `user_id`, `reason` |
| `search_mailbox_history` | LOW | no | `MAILBOX_SEARCH_URL` | `MAILBOX_SEARCH_TOKEN` | `query`, `days_back`; return `{"matched_messages": [...]}` |
| `create_soc_ticket` | LOW | no | `SOC_TICKET_WEBHOOK_URL` | `SOC_TICKET_WEBHOOK_TOKEN` | `title`, `severity`, `details` |

The pipeline currently proposes `quarantine_email`, `revoke_session` and `search_mailbox_history`.
The other actions can be dispatched through the approval API when proposed by future rules.

Connector URLs are operator configuration and are not subject to the SSRF guard that protects
analysis fetches; point them only at endpoints you control.
