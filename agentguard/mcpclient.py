"""A minimal MCP client that connects to a server over stdio.

MCP uses JSON-RPC 2.0 over stdio: the client launches the server process, sends
an ``initialize`` request, then ``tools/list`` to enumerate the advertised
tools. We implement just that slice here, with no third-party dependency, so
AgentGuard can inspect the *live* tools a server exposes (not only what a config
file declares) and feed them to the detectors and the fingerprint diff.

This is intentionally small and defensive: we never *call* a tool, we only read
its advertised definition.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from .detectors import Tool

PROTOCOL_VERSION = "2024-11-05"


class MCPClientError(RuntimeError):
    pass


class StdioMCPClient:
    """Launch an MCP server via a command and read its tool list over stdio."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None,
                 timeout: float = 15.0) -> None:
        self.command = command
        self.env = env
        self.timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._id = 0

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "StdioMCPClient":
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=self.env,
        )
        return self

    def __exit__(self, *exc: object) -> None:
        if self._proc:
            try:
                self._proc.stdin and self._proc.stdin.close()
            finally:
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()

    # -- JSON-RPC plumbing --------------------------------------------------
    def _send(self, method: str, params: dict[str, Any] | None = None,
              is_notification: bool = False) -> None:
        assert self._proc and self._proc.stdin
        self._id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not is_notification:
            msg["id"] = self._id
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _read(self) -> dict[str, Any]:
        assert self._proc and self._proc.stdout
        line = self._proc.stdout.readline()
        if not line:
            raise MCPClientError("server closed the connection unexpectedly")
        return json.loads(line)

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._send(method, params)
        resp = self._read()
        if "error" in resp:
            raise MCPClientError(f"{method} failed: {resp['error']}")
        return resp.get("result", {})

    # -- public API ---------------------------------------------------------
    def initialize(self) -> dict[str, Any]:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentguard", "version": "0.1.0"},
            },
        )
        self._send("notifications/initialized", is_notification=True)
        return result

    def list_tools(self) -> list[Tool]:
        result = self._request("tools/list")
        tools: list[Tool] = []
        for t in result.get("tools", []):
            tools.append(
                Tool(
                    name=t.get("name", "<unnamed>"),
                    description=t.get("description", ""),
                    raw=t,
                )
            )
        return tools


def list_server_tools(command: list[str], env: dict[str, str] | None = None) -> list[Tool]:
    """Convenience: connect, handshake, and return the server's live tools."""
    with StdioMCPClient(command, env=env) as client:
        client.initialize()
        return client.list_tools()
