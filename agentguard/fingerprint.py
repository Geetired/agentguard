"""Tool fingerprinting and rug-pull detection.

A "rug pull" is when an MCP server advertises a benign tool while you review it,
then silently changes that tool's behaviour after you've approved it. AgentGuard
defends against this by recording a fingerprint (a hash of the tool's name,
description and input schema) the first time it sees a server, and comparing
every later scan against that saved baseline.

The baseline is a small JSON file, so it's easy to commit alongside a project
and diff in code review.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from .detectors import Tool


def fingerprint_tool(tool: Tool) -> str:
    """Stable SHA-256 over the parts of a tool the agent actually reads."""
    payload = {
        "name": tool.name,
        "description": tool.description or "",
        "schema": tool.raw.get("inputSchema") or tool.raw.get("input_schema") or {},
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class ToolChange:
    kind: str  # "added" | "removed" | "changed"
    tool_name: str
    old: str = ""
    new: str = ""

    @property
    def severity(self) -> str:
        # A silently changed tool is the rug-pull signal and the most dangerous.
        return {"changed": "high", "added": "medium", "removed": "low"}[self.kind]


class Baseline:
    """A saved set of tool fingerprints for one MCP server."""

    def __init__(self, server: str, tools: dict[str, str] | None = None,
                 created_at: float | None = None) -> None:
        self.server = server
        self.tools = tools or {}  # tool_name -> fingerprint
        self.created_at = created_at or time.time()

    @classmethod
    def from_tools(cls, server: str, tools: list[Tool]) -> "Baseline":
        return cls(server, {t.name: fingerprint_tool(t) for t in tools})

    def to_dict(self) -> dict:
        return {"server": self.server, "created_at": self.created_at, "tools": self.tools}

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data["server"], data.get("tools", {}), data.get("created_at"))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    def diff(self, tools: list[Tool]) -> list[ToolChange]:
        """Compare a fresh tool listing against this baseline."""
        current = {t.name: fingerprint_tool(t) for t in tools}
        changes: list[ToolChange] = []
        for name, fp in current.items():
            if name not in self.tools:
                changes.append(ToolChange("added", name, new=fp))
            elif self.tools[name] != fp:
                changes.append(ToolChange("changed", name, old=self.tools[name], new=fp))
        for name, fp in self.tools.items():
            if name not in current:
                changes.append(ToolChange("removed", name, old=fp))
        # Most dangerous first.
        order = {"changed": 0, "added": 1, "removed": 2}
        changes.sort(key=lambda c: order[c.kind])
        return changes
