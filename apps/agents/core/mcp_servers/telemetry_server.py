"""
Sender-history telemetry.

Answers "has this tenant seen this sender before?" from the tenant's own persisted incidents
in DurableStorage. Nothing is seeded: a new deployment correctly reports every sender as new.
Can be called in-process (handle_query_sender_history) or served over stdio JSON-RPC (main).
"""

import json
import sys
from typing import Any, Dict

from apps.agents.core.durable_storage import DurableStorage


def handle_query_sender_history(params: Dict[str, Any]) -> Dict[str, Any]:
    sender_email = str(params.get("sender_email", "")).strip().lower()
    sender_domain = str(params.get("sender_domain", "")).strip().lower()
    recipient_email = str(params.get("recipient_email", "")).strip().lower()
    tenant_id = str(params.get("tenant_id", "")).strip()
    if not tenant_id:
        return {"error": "tenant_id is required"}
    if not sender_domain and "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1]

    conn = DurableStorage.get_instance()._get_connection()
    row = conn.execute(
        """
        SELECT COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
               SUM(CASE WHEN lower(json_extract(data_json, '$.sender')) = ? THEN 1 ELSE 0 END) AS exact_sender
        FROM incidents
        WHERE tenant_id = ?
          AND (lower(json_extract(data_json, '$.sender')) = ?
               OR lower(json_extract(data_json, '$.sender')) LIKE ?)
        """,
        (sender_email, tenant_id, sender_email, f"%@{sender_domain}" if sender_domain else "\x00"),
    ).fetchone()
    count = int(row["n"] or 0)
    return {
        "tenant_id": tenant_id,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "recipient_email": recipient_email,
        "historical_email_count": count,
        "historical_exact_sender_count": int(row["exact_sender"] or 0),
        "is_first_time_sender": count == 0,
        "first_seen_timestamp": row["first_seen"],
        "last_seen_timestamp": row["last_seen"],
        "source": "tenant incident history",
    }


TOOLS = {"query_sender_history": handle_query_sender_history}


def process_request(line: str) -> str:
    try:
        req = json.loads(line)
    except Exception as exc:
        return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}})
    msg_id, method = req.get("id"), req.get("method")
    if method == "tools/list":
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{
            "name": "query_sender_history",
            "description": "Count prior incidents from a sender/domain within a tenant",
            "inputSchema": {"type": "object", "properties": {
                "sender_email": {"type": "string"}, "sender_domain": {"type": "string"},
                "recipient_email": {"type": "string"}, "tenant_id": {"type": "string"}},
                "required": ["tenant_id"]},
        }]}})
    if method == "tools/call":
        params = req.get("params", {})
        handler = TOOLS.get(params.get("name"))
        if not handler:
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Tool not found"}})
        result = handler(params.get("arguments", {}))
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": json.dumps(result)}]}})
    return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32600, "message": "Invalid Request"}})


def main():
    from apps.agents.core.mcp_servers.mcp_stdio import serve
    serve(process_request, "fishingmails-telemetry")


if __name__ == "__main__":
    main()
