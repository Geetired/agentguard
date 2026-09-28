"""Static detection rules for MCP tool definitions.

Each detector takes a parsed MCP tool (name + description + metadata) and
returns a list of Finding objects. Detectors are intentionally small and
independent so new attack classes are easy to add and easy to test.

References: OWASP MCP Top 10 (2026), Invariant Labs / Snyk mcp-scan research.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any


# Severity ordering used for ranking and exit codes.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    tool_name: str
    detail: str
    # OWASP MCP Top 10 identifier, e.g. "MCP-01".
    owasp: str = ""
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")


@dataclass
class Tool:
    """A single MCP tool definition as read from a server or config."""

    name: str
    description: str = ""
    # Free-form extras: input schema, annotations, server command, etc.
    raw: dict[str, Any] = field(default_factory=dict)


# --- Individual detectors ---------------------------------------------------

# Phrases that, inside a *tool description*, are attempts to steer the agent
# rather than describe the tool. This is the core of "tool poisoning".
_INJECTION_PATTERNS = [
    r"ignore (all |any |previous |prior |the |above )*(instructions|rules)",
    r"do not (tell|mention|inform|reveal).{0,40}(user|human)",
    r"</?(system|instructions?|important)>",
    r"before (using|calling) (this|any) tool",
    r"you must (always|first|secretly)",
    r"send .{0,40}(to|via) (http|https|the following)",
    r"read .{0,40}(\.env|secrets?|credentials?|id_rsa|\.aws)",
]


def detect_prompt_injection(tool: Tool) -> list[Finding]:
    text = tool.description or ""
    lowered = text.lower()
    matches = [re.search(pat, lowered) for pat in _INJECTION_PATTERNS]
    matches = [m for m in matches if m]
    if not matches:
        return []
    # One finding per tool; cite the earliest match and count the rest.
    first = min(matches, key=lambda m: m.start())
    extra = f" (+{len(matches) - 1} more phrase(s))" if len(matches) > 1 else ""
    return [
        Finding(
            rule_id="AG001",
            title="Instructional phrasing in tool description",
            severity="high",
            tool_name=tool.name,
            detail=(
                "The description contains language that instructs the agent "
                "rather than describing the tool. This is the signature of a "
                "tool-poisoning / prompt-injection attack." + extra
            ),
            owasp="MCP-01",
            evidence=_excerpt(text, first.start(), first.end()),
        )
    ]


# Characters that render invisibly or can hide a second instruction: zero-width
# spaces, bidi controls, tag characters (U+E0000 block), etc.
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",
}


def detect_hidden_unicode(tool: Tool) -> list[Finding]:
    text = tool.description or ""
    hits = [c for c in text if c in _INVISIBLE or (0xE0000 <= ord(c) <= 0xE007F)]
    if not hits:
        return []
    names = sorted({_char_name(c) for c in hits})
    return [
        Finding(
            rule_id="AG002",
            title="Invisible / control characters in tool description",
            severity="high",
            tool_name=tool.name,
            detail=(
                "Hidden characters can carry instructions a human reviewer never "
                "sees while the agent still reads them: "
                + ", ".join(names)
            ),
            owasp="MCP-01",
            evidence=repr(text[:120]),
        )
    ]


# Rough secret shapes. Kept deliberately conservative to limit false positives;
# each match is reported as needing human confirmation.
_SECRET_PATTERNS = {
    "AWS access key id": r"AKIA[0-9A-Z]{16}",
    "GitHub token": r"gh[pousr]_[A-Za-z0-9]{20,}",
    "Private key block": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic api key assignment": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9/+_-]{16,}",
}


def detect_hardcoded_secrets(tool: Tool) -> list[Finding]:
    findings: list[Finding] = []
    # Scan both the description and any server launch command / env.
    blob = " ".join(
        [tool.description or "", str(tool.raw.get("command", "")), str(tool.raw.get("env", ""))]
    )
    for label, pat in _SECRET_PATTERNS.items():
        m = re.search(pat, blob)
        if m:
            findings.append(
                Finding(
                    rule_id="AG003",
                    title=f"Possible hardcoded secret ({label})",
                    severity="critical",
                    tool_name=tool.name,
                    detail="A credential-shaped string is embedded in the tool or its launch config.",
                    owasp="MCP-08",
                    evidence=_redact(m.group(0)),
                )
            )
    return findings


def detect_unpinned_package(tool: Tool) -> list[Finding]:
    """Flag servers launched via npx/uvx/pip without a pinned version.

    An unpinned remote package is a supply-chain rug-pull risk: the code you
    audited today can be replaced tomorrow.
    """
    command = str(tool.raw.get("command", ""))
    args = " ".join(str(a) for a in tool.raw.get("args", []))
    line = f"{command} {args}".strip()
    if not line:
        return []
    launchers = ("npx", "uvx", "pipx", "pip install", "bunx")
    if not any(l in line for l in launchers):
        return []
    # Pinned if it contains name@version or ==version.
    if re.search(r"@[0-9]", line) or "==" in line:
        return []
    return [
        Finding(
            rule_id="AG004",
            title="MCP server launched from an unpinned package",
            severity="medium",
            tool_name=tool.name,
            detail=(
                "The server is fetched at run time without a version pin, so the "
                "code can change after you review it (supply-chain rug-pull)."
            ),
            owasp="MCP-02",
            evidence=line[:160],
        )
    ]


ALL_DETECTORS = [
    detect_prompt_injection,
    detect_hidden_unicode,
    detect_hardcoded_secrets,
    detect_unpinned_package,
]


def scan_tool(tool: Tool) -> list[Finding]:
    findings: list[Finding] = []
    for det in ALL_DETECTORS:
        findings.extend(det(tool))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return findings


# --- helpers ---------------------------------------------------------------

def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", " ")
    return ("..." if lo else "") + snippet + ("..." if hi < len(text) else "")


def _char_name(c: str) -> str:
    try:
        return unicodedata.name(c)
    except ValueError:
        return f"U+{ord(c):04X}"


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]
