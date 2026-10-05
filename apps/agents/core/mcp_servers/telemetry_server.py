"""Self-Hosted Historical Telemetry MCP Server (JSON-RPC over stdio).

Provides temporal communication anomaly querying:
- Historical sender-recipient frequency
- First-seen / Last-seen baseline lookups
- Previous authentication pass/fail stats
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import threading
from typing import Any, Dict

# Thread-safe in-memory SQLite database initialized with baseline schema
_DB_LOCK = threading.RLock()
CONN = sqlite3.connect(":memory:", check_same_thread=False)
CONN.row_factory = sqlite3.Row


def init_db():
    with _DB_LOCK:
        with CONN:
            CONN.execute("""
                CREATE TABLE IF NOT EXISTS email_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    sender_email TEXT NOT NULL,
                    sender_domain TEXT NOT NULL,
                    recipient_email TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    auth_status TEXT NOT NULL,
                    subject_hash TEXT
                )
            """)
            # Seed realistic baseline data for common enterprise domains
            now = int(time.time())
            CONN.execute("""
                INSERT INTO email_history (tenant_id, sender_email, sender_domain, recipient_email, timestamp, auth_status, subject_hash)
                VALUES
                    ('default', 'billing@trusted-vendor.com', 'trusted-vendor.com', 'finance@victim-corp.com', ?, 'PASS', 'hash_01'),
                    ('default', 'hr@victim-corp.com', 'victim-corp.com', 'finance@victim-corp.com', ?, 'PASS', 'hash_02'),
                    ('default', 'ceo@victim-corp.com', 'victim-corp.com', 'finance@victim-corp.com', ?, 'PASS', 'hash_03')
            """, (now - 86400 * 30, now - 86400 * 15, now - 86400 * 5))


init_db()


def handle_query_sender_history(params: Dict[str, Any]) -> Dict[str, Any]:
    sender_email = params.get("sender_email", "").strip().lower()
    recipient_email = params.get("recipient_email", "").strip().lower()
    sender_domain = params.get("sender_domain", "").strip().lower()
    tenant_id = params.get("tenant_id", "").strip().lower()

    if not sender_domain and "@" in sender_email:
        sender_domain = sender_email.split("@")[1]

    with _DB_LOCK:
        with CONN:
            cur = CONN.cursor()
            if tenant_id:
                if recipient_email:
                    cur.execute("""
                        SELECT COUNT(*) as count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                        FROM email_history
                        WHERE (tenant_id = ? OR tenant_id = 'default')
                          AND (sender_email = ? OR sender_domain = ?) AND recipient_email = ?
                    """, (tenant_id, sender_email, sender_domain, recipient_email))
                else:
                    cur.execute("""
                        SELECT COUNT(*) as count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                        FROM email_history
                        WHERE (tenant_id = ? OR tenant_id = 'default')
                          AND (sender_email = ? OR sender_domain = ?)
                    """, (tenant_id, sender_email, sender_domain))
            else:
                if recipient_email:
                    cur.execute("""
                        SELECT COUNT(*) as count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                        FROM email_history
                        WHERE (sender_email = ? OR sender_domain = ?) AND recipient_email = ?
                    """, (sender_email, sender_domain, recipient_email))
                else:
                    cur.execute("""
                        SELECT COUNT(*) as count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                        FROM email_history
                        WHERE sender_email = ? OR sender_domain = ?
                    """, (sender_email, sender_domain))

            row = cur.fetchone()
            count = row["count"] if row else 0
            first_seen = row["first_seen"] if row else None
            last_seen = row["last_seen"] if row else None

    return {
        "tenant_id": tenant_id or "default",
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "recipient_email": recipient_email,
        "historical_email_count": count,
        "is_first_time_sender": count == 0,
        "first_seen_timestamp": first_seen,
        "last_seen_timestamp": last_seen,
        "baseline_reputation": "established" if count >= 5 else ("known" if count > 0 else "unknown_anomaly"),
    }


def handle_record_interaction(params: Dict[str, Any]) -> Dict[str, Any]:
    sender_email = params.get("sender_email", "").strip().lower()
    recipient_email = params.get("recipient_email", "").strip().lower()
    auth_status = params.get("auth_status", "PASS")
    sender_domain = sender_email.split("@")[1] if "@" in sender_email else ""
    tenant_id = params.get("tenant_id", "default").strip().lower()
    ts = int(params.get("timestamp", time.time()))

    with _DB_LOCK:
        with CONN:
            CONN.execute("""
                INSERT INTO email_history (tenant_id, sender_email, sender_domain, recipient_email, timestamp, auth_status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tenant_id, sender_email, sender_domain, recipient_email, ts, auth_status))

    return {"status": "recorded", "tenant_id": tenant_id, "sender_email": sender_email, "recipient_email": recipient_email}


TOOLS = {
    "query_sender_history": handle_query_sender_history,
    "record_interaction": handle_record_interaction,
}


def process_request(line: str) -> str:
    try:
        req = json.loads(line)
        method = req.get("method")
        msg_id = req.get("id")

        if method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "query_sender_history",
                            "description": "Query historical communication baseline between sender and recipient",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sender_email": {"type": "string"},
                                    "recipient_email": {"type": "string"},
                                    "sender_domain": {"type": "string"},
                                },
                            },
                        },
                        {
                            "name": "record_interaction",
                            "description": "Record a new email interaction in the historical telemetry database",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "sender_email": {"type": "string"},
                                    "recipient_email": {"type": "string"},
                                    "auth_status": {"type": "string"},
                                },
                                "required": ["sender_email", "recipient_email"],
                            },
                        },
                    ]
                },
            })

        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name in TOOLS:
                handler = TOOLS[tool_name]
                result = handler(tool_args)
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                })
            else:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                })

        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request"},
        })
    except Exception as exc:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"},
        })


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        res = process_request(line)
        sys.stdout.write(res + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
