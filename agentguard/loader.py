"""Load MCP tool definitions from client config files.

Supports the common shapes used by Claude Desktop / Claude Code, Cursor and
VS Code, which all store an ``mcpServers`` map. We read the *declared* servers
here (static analysis). Milestone 2 adds live connection + tool listing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detectors import Tool


def load_config(path: str | Path) -> list[Tool]:
    """Parse an MCP client config file into a list of Tool objects.

    Each configured server becomes one Tool whose ``raw`` carries its launch
    command/args/env, so the supply-chain and secret detectors can inspect it.
    Server-advertised tools (with descriptions) are read in milestone 2.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    tools: list[Tool] = []
    for name, cfg in servers.items():
        cfg = cfg if isinstance(cfg, dict) else {}
        tools.append(
            Tool(
                name=name,
                description=cfg.get("description", ""),
                raw=cfg,
            )
        )
    return tools


def load_tools_json(path: str | Path) -> list[Tool]:
    """Load a raw list of tool definitions (name/description) from JSON.

    Used for the benchmark corpus, where each sample file is a list of tool
    objects with descriptions to exercise the text detectors.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items: list[dict[str, Any]] = data if isinstance(data, list) else data.get("tools", [])
    return [
        Tool(name=i.get("name", "<unnamed>"), description=i.get("description", ""), raw=i)
        for i in items
    ]
