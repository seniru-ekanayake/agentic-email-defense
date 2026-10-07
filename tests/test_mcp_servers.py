"""The bundled DNS and telemetry servers speak MCP over stdio (initialize, tools/list, tools/call)."""

import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _session(module, messages):
    env = {**os.environ, "PYTHONPATH": REPO}
    proc = subprocess.run([sys.executable, "-m", module], input="\n".join(json.dumps(m) for m in messages) + "\n",
                          capture_output=True, text=True, timeout=30, env=env, cwd=REPO)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_telemetry_server_mcp_handshake_and_tools():
    replies = _session("apps.agents.core.mcp_servers.telemetry_server", [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "query_sender_history", "arguments": {"tenant_id": "t-mcp", "sender_email": "a@b.example"}}},
    ])
    assert [r["id"] for r in replies] == [1, 2, 3]  # the notification gets no reply
    assert replies[0]["result"]["serverInfo"]["name"] == "fishingmails-telemetry"
    assert replies[1]["result"]["tools"][0]["name"] == "query_sender_history"
    body = json.loads(replies[2]["result"]["content"][0]["text"])
    assert body["is_first_time_sender"] is True


def test_dns_server_lists_tools_after_initialize():
    replies = _session("apps.agents.core.mcp_servers.dns_server", [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ])
    assert replies[0]["result"]["capabilities"] == {"tools": {}}
    assert {t["name"] for t in replies[1]["result"]["tools"]} == {"dns_resolve", "spf_dmarc_audit", "dkim_selector_check"}
