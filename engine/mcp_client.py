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

import re
from urllib.parse import urlsplit

try:
    from .guard import check_command
    from .policy import url_policy, PolicyDenied
except ImportError:
    from guard import check_command
    from policy import url_policy, PolicyDenied


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


_URL_RE = re.compile(r'https?://[^\s"\'<>\]\)]+')


def _extract_urls(obj: Any) -> list[str]:
    """Recursively extract HTTP(S) URLs from a JSON-like structure."""
    urls: list[str] = []
    if isinstance(obj, str):
        urls.extend(_URL_RE.findall(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            urls.extend(_extract_urls(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            urls.extend(_extract_urls(item))
    return urls


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

    # Executables allowed to be spawned as stdio MCP servers. A server config
    # is operator-controlled but may come from a shareable catalog, so the
    # surface is limited to the standard runtimes.
    ALLOWED_STDBIN = {"npx", "node", "python3", "python", "uvx", "docker",
                      "ruby", "go", "bunx"}

    def _connect_stdio(self) -> dict:
        if not self.config.command:
            raise MCPClientError("stdio transport requires command")
        import os
        import shutil as _shutil
        exe = _shutil.which(self.config.command[0]) or self.config.command[0]
        exe_base = Path(exe).name if os.sep not in self.config.command[0] \
            else Path(self.config.command[0]).name
        if exe_base not in self.ALLOWED_STDBIN:
            raise MCPClientError(
                f"MCP server executable {self.config.command[0]!r} not in "
                f"allowlist {sorted(self.ALLOWED_STDBIN)}")
        # Minimal environment: do NOT inherit the operator's full env (API
        # keys and secrets would leak into a third-party server process).
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM",
                "http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY",
                "HTTPS_PROXY", "NO_PROXY", "NODE_PATH", "PYTHONPATH",
                "SSL_CERT_FILE", "SSL_CERT_DIR")
        env = {k: v for k, v in os.environ.items() if k in keep}
        env.update(self.config.env)
        self._process = subprocess.Popen(
            [exe, *self.config.command[1:]], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True,
        )
        resp = self._send_jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "quarry", "version": "1.0"},
        })
        self._connected = True
        self._send_jsonrpc_notification("notifications/initialized", {})
        return resp

    def _connect_http(self) -> dict:
        if not self.config.url:
            raise MCPClientError("http transport requires url")
        if self.audit_dir:
            try:
                url_policy(self.config.url, self.audit_dir)
            except PolicyDenied as exc:
                raise MCPClientError(f"MCP server URL out of scope: {exc}") from exc
        resp = self._http_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "quarry", "version": "1.0"},
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

        if params and self.audit_dir:
            for target_url in _extract_urls(params):
                try:
                    url_policy(target_url, self.audit_dir)
                except PolicyDenied as exc:
                    return {"error": f"Scope violation: {exc}", "allowed": False}

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
        req_id = self._next_id()
        msg = json.dumps({
            "jsonrpc": "2.0", "id": req_id,
            "method": method, "params": params,
        }) + "\n"
        try:
            self._process.stdin.write(msg)
            self._process.stdin.flush()
            # Read until the response with OUR id arrives: a notification or
            # log line printed first used to be returned as if it were the
            # result of this call.
            for _ in range(100):
                line = self._process.stdout.readline()
                if not line:
                    raise MCPClientError("Server closed connection")
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # server log line, not JSON-RPC
                if rec.get("id") != req_id:
                    continue  # notification or unrelated response
                if "error" in rec:
                    err = rec["error"]
                    raise MCPClientError(
                        f"JSON-RPC error {err.get('code')}: {err.get('message')}")
                return rec
            raise MCPClientError("Too many non-matching lines while waiting "
                                 "for JSON-RPC response")
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
