"""
Minimal Model Context Protocol (MCP) stdio framing shared by the bundled servers.

Handles the lifecycle messages an MCP client sends before using tools (`initialize`,
`notifications/initialized`, `ping`) and delegates everything else to the server's own handler.
Messages are newline-delimited JSON-RPC 2.0, as in the MCP stdio transport.
"""

import json
import sys
from typing import Callable, Optional

PROTOCOL_VERSION = "2024-11-05"


def handle_lifecycle(req: dict, server_name: str, version: str = "1.0.0") -> Optional[str]:
    """Returns a response for lifecycle methods, "" for notifications, or None if not a lifecycle message."""
    method = req.get("method", "")
    if method == "initialize":
        return json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": server_name, "version": version},
        }})
    if method == "ping":
        return json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {}})
    if method.startswith("notifications/") or "id" not in req:
        return ""  # notifications never get a response
    return None


def serve(process_request: Callable[[str], str], server_name: str) -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except Exception:
            req = None
        reply = handle_lifecycle(req, server_name) if isinstance(req, dict) else None
        if reply is None:
            reply = process_request(line)
        if reply:
            sys.stdout.write(reply + "\n")
            sys.stdout.flush()
