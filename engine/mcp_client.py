"""MCP client — consume tools from external MCP servers.

Connects to MCP servers over stdio or HTTP (JSON-RPC 2.0 Streamable HTTP),
discovers their tools, and invokes them with guard + budget integration.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .guard import check_command
except ImportError:
    from guard import check_command


@dataclass
class ServerConfig:
    name: str
    transport: str = "stdio"  # "stdio" | "http"
    command: list[str] = field(default_factory=list)  # for stdio
    url: str = ""  # for http
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)


class MCPClientError(RuntimeError):
    pass


class MCPClient:
    """Client for a single MCP server connection."""

    def __init__(self, config: ServerConfig, audit_dir: str = ".",
                 budget_manager: Any = None, phase: str = "hunting"):
        self.config = config
        self.audit_dir = audit_dir
        self._budget = budget_manager
        self._phase = phase
        self._tools: dict[str, MCPTool] = {}
        self._process: subprocess.Popen | None = None
        self._connected = False
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def connect(self) -> dict:
        if self.config.transport == "stdio":
            return self._connect_stdio()
        elif self.config.transport == "http":
            return self._connect_http()
        raise MCPClientError(f"Unknown transport: {self.config.transport}")

    def _connect_stdio(self) -> dict:
        if not self.config.command:
            raise MCPClientError("stdio transport requires command")
        import os
        env = {**os.environ, **self.config.env}
        self._process = subprocess.Popen(
            self.config.command, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True,
        )
        resp = self._send_jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pentest-plugin", "version": "1.0"},
        })
        self._connected = True
        self._send_jsonrpc_notification("notifications/initialized", {})
        return resp

    def _connect_http(self) -> dict:
        if not self.config.url:
            raise MCPClientError("http transport requires url")
        resp = self._http_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pentest-plugin", "version": "1.0"},
        })
        self._connected = True
        return resp

    def list_tools(self) -> list[MCPTool]:
        self._require_connected()
        if self.config.transport == "stdio":
            resp = self._send_jsonrpc("tools/list", {})
        else:
            resp = self._http_request("tools/list", {})

        tools = []
        for t in resp.get("result", {}).get("tools", []):
            tool = MCPTool(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            )
            self._tools[tool.name] = tool
            tools.append(tool)
        return tools

    def call_tool(self, name: str, params: dict | None = None) -> dict:
        self._require_connected()

        guard_result = check_command(
            f"mcp:{self.config.name}:{name}", audit_dir=self.audit_dir)
        if not guard_result.get("allowed"):
            return {"error": guard_result.get("blocked_reason", "Blocked by guard"),
                    "allowed": False}

        if self._budget:
            budget_result = self._budget.record_call(
                self._phase, f"mcp:{self.config.name}:{name}")
            if not budget_result.get("allowed"):
                return {"error": "Budget exhausted", "budget": budget_result}

        call_params = {"name": name, "arguments": params or {}}
        if self.config.transport == "stdio":
            resp = self._send_jsonrpc("tools/call", call_params)
        else:
            resp = self._http_request("tools/call", call_params)

        return resp.get("result", resp)

    def disconnect(self):
        if self._process:
            try:
                self._process.stdin.close()
                self._process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self._process.kill()
            self._process = None
        self._connected = False
        self._tools.clear()

    def _require_connected(self):
        if not self._connected:
            raise MCPClientError("Not connected — call connect() first")

    def _send_jsonrpc(self, method: str, params: dict) -> dict:
        msg = json.dumps({
            "jsonrpc": "2.0", "id": self._next_id(),
            "method": method, "params": params,
        }) + "\n"
        try:
            self._process.stdin.write(msg)
            self._process.stdin.flush()
            line = self._process.stdout.readline()
            if not line:
                raise MCPClientError("Server closed connection")
            return json.loads(line)
        except (BrokenPipeError, OSError) as exc:
            raise MCPClientError(f"stdio communication failed: {exc}") from exc

    def _send_jsonrpc_notification(self, method: str, params: dict):
        msg = json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params,
        }) + "\n"
        try:
            self._process.stdin.write(msg)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def _http_request(self, method: str, params: dict) -> dict:
        import urllib.request
        body = json.dumps({
            "jsonrpc": "2.0", "id": self._next_id(),
            "method": method, "params": params,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.config.headers}
        req = urllib.request.Request(self.config.url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            raise MCPClientError(f"HTTP request failed: {exc}") from exc

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()
