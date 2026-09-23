"""Asynchronous Model Context Protocol (MCP) Client over stdio.

Manages process-isolated MCP server subprocesses, sends JSON-RPC 2.0 requests,
and registers dynamic tools into LangGraph agent workflows.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mcp_client")


class MCPProcessServer:
    """Manages an individual stdio-based MCP server subprocess."""

    def __init__(self, name: str, command: List[str], env: Optional[Dict[str, str]] = None):
        self.name = name
        self.command = command
        self.env = env or os.environ.copy()
        self.process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the MCP subprocess."""
        if self.process is None or self.process.returncode is not None:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.env,
            )
            logger.info(f"Started MCP server '{self.name}' (PID {self.process.pid})")

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
        """Send a JSON-RPC 2.0 request over stdin and await response from stdout."""
        await self.start()
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise RuntimeError(f"MCP server '{self.name}' is not running")

        async with self._lock:
            self._request_id += 1
            msg_id = self._request_id
            payload = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params

            req_bytes = (json.dumps(payload) + "\n").encode("utf-8")
            self.process.stdin.write(req_bytes)
            await self.process.stdin.drain()

            try:
                line = await asyncio.wait_for(self.process.stdout.readline(), timeout=timeout)
                if not line:
                    raise EOFError(f"MCP server '{self.name}' closed stdout unexpectedly")
                
                resp = json.loads(line.decode("utf-8"))
                if "error" in resp:
                    raise RuntimeError(f"MCP Error from '{self.name}': {resp['error']}")
                return resp.get("result", {})
            except asyncio.TimeoutError:
                logger.error(f"Timeout awaiting response from MCP server '{self.name}'")
                await self.stop()
                raise TimeoutError(f"MCP server '{self.name}' timed out after {timeout}s")

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Query available tools from the MCP server."""
        res = await self.send_request("tools/list")
        return res.get("tools", [])

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Invoke a tool on the MCP server."""
        res = await self.send_request("tools/call", {"name": tool_name, "arguments": arguments})
        contents = res.get("content", [])
        if contents and contents[0].get("type") == "text":
            try:
                return json.loads(contents[0]["text"])
            except Exception:
                return contents[0]["text"]
        return res

    async def stop(self) -> None:
        """Terminate the MCP subprocess."""
        if self.process and self.process.returncode is None:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=2.0)
            except Exception:
                self.process.kill()
            logger.info(f"Stopped MCP server '{self.name}'")
        self.process = None


class MCPManager:
    """Central registry and lifecycle manager for all MCP server connections."""

    _instance: Optional[MCPManager] = None

    def __init__(self):
        self.servers: Dict[str, MCPProcessServer] = {}
        self._register_default_servers()

    @classmethod
    def get_instance(cls) -> MCPManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _register_default_servers(self) -> None:
        """Register built-in, self-hosted stdio MCP servers."""
        base_dir = os.path.dirname(__file__)
        dns_script = os.path.join(base_dir, "mcp_servers", "dns_server.py")
        telemetry_script = os.path.join(base_dir, "mcp_servers", "telemetry_server.py")

        self.register_server("dns_recon", [sys.executable, dns_script])
        self.register_server("telemetry", [sys.executable, telemetry_script])

    def register_server(self, name: str, command: List[str], env: Optional[Dict[str, str]] = None) -> None:
        self.servers[name] = MCPProcessServer(name, command, env)

    async def list_all_tools(self) -> Dict[str, List[Dict[str, Any]]]:
        results = {}
        for name, server in self.servers.items():
            try:
                tools = await server.list_tools()
                results[name] = tools
            except Exception as exc:
                logger.warning(f"Could not list tools from MCP server '{name}': {exc}")
        return results

    async def call_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if server_name not in self.servers:
            raise KeyError(f"MCP server '{server_name}' not registered")
        return await self.servers[server_name].call_tool(tool_name, arguments)

    async def shutdown_all(self) -> None:
        for server in self.servers.values():
            await server.stop()
