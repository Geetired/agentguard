"""Cross-tool "toxic flow" analysis (AG007).

A tool can look harmless on its own yet become dangerous in combination with
another. The classic pattern (the "lethal trifecta": private data + untrusted
content + a way to communicate externally) is an MCP server that offers *both*
a tool able to reach sensitive data *and* a tool able to send data out. An
attacker who can influence the agent — e.g. via a poisoned tool description or
injected content — can chain the two into an exfiltration path, even though
neither tool is malicious in isolation.

Unlike the per-tool detectors in ``detectors.py``, this analysis looks at the
whole set of tools a server advertises and reports dangerous source -> sink
pairs. Capability tagging is deliberately coarse (name + description + declared
inputs) so it needs no execution and stays dependency-free.
"""
from __future__ import annotations

from .detectors import (
    Finding,
    Tool,
    _PATH_PARAM_HINTS,
    _URL_PARAM_HINTS,
    _iter_properties,
)

# Capability tags.
SENSITIVE_READ = "sensitive-read"
NETWORK_EGRESS = "network-egress"
CODE_EXEC = "code-exec"

_READ_VERBS = (
    "read", "get", "fetch", "load", "list", "cat", "dump", "export",
    "query", "retrieve", "open", "access",
)
_SENSITIVE_NOUNS = (
    "secret", "credential", "password", "token", "api key", "api_key",
    "private key", ".env", "env var", "environment variable", ".aws",
    "ssh", "id_rsa", "keychain", "vault", "database", "filesystem",
)
_EGRESS_TERMS = (
    "http", "https", "url", "upload", "webhook", "publish", "exfil",
    "slack", "discord", "telegram", "smtp", "outbound", "post to", "send to",
    "send a", "send the", "send data", "email", "fetch url", "external",
)
_EXEC_TERMS = (
    "exec", "shell", "bash", "run command", "eval", "subprocess", "spawn",
    "os.system", "powershell", "execute code", "arbitrary command",
)


def _text(tool: Tool) -> str:
    return f"{tool.name} {tool.description or ''}".lower()


def _has_param(tool: Tool, hints) -> bool:
    return any(
        any(h in pname.lower() for h in hints) for pname, _ in _iter_properties(tool)
    )


def capabilities(tool: Tool) -> set[str]:
    """Coarse capability tags for a single tool."""
    t = _text(tool)
    caps: set[str] = set()
    if (any(v in t for v in _READ_VERBS) and any(n in t for n in _SENSITIVE_NOUNS)) \
            or _has_param(tool, _PATH_PARAM_HINTS):
        caps.add(SENSITIVE_READ)
    if any(term in t for term in _EGRESS_TERMS) or _has_param(tool, _URL_PARAM_HINTS):
        caps.add(NETWORK_EGRESS)
    if any(term in t for term in _EXEC_TERMS):
        caps.add(CODE_EXEC)
    return caps


def _pick_pair(sources: list[Tool], sinks: list[Tool]) -> tuple[Tool, Tool]:
    """Prefer two distinct tools; fall back to a single tool that is both."""
    for s in sources:
        for k in sinks:
            if s is not k:
                return s, k
    return sources[0], sinks[0]


def analyze_toxic_flows(tools: list[Tool]) -> list[Finding]:
    """Report dangerous capability combinations across a set of tools."""
    tagged = [(tool, capabilities(tool)) for tool in tools]
    readers = [t for t, c in tagged if SENSITIVE_READ in c]
    egress = [t for t, c in tagged if NETWORK_EGRESS in c]
    execs = [t for t, c in tagged if CODE_EXEC in c]

    findings: list[Finding] = []

    if readers and egress:
        src, sink = _pick_pair(readers, egress)
        same = src is sink
        findings.append(
            Finding(
                rule_id="AG007",
                title="Toxic flow: data-exfiltration path across tools",
                severity="high",
                tool_name=(src.name if same else f"{src.name} + {sink.name}"),
                detail=(
                    "This server exposes both a tool that can reach sensitive data "
                    f"('{src.name}') and a tool that can send data to an external "
                    f"destination ('{sink.name}'). An attacker who influences the agent "
                    "can chain them to exfiltrate secrets — the 'lethal trifecta' — even "
                    "though neither tool is malicious alone."
                    + (" Both capabilities live in the SAME tool, which is worse."
                       if same else "")
                ),
                owasp="MCP-06",
                evidence=f"source: {src.name} (reads sensitive data) -> sink: {sink.name} (network egress)",
            )
        )

    if execs and egress:
        src, sink = _pick_pair(execs, egress)
        same = src is sink
        findings.append(
            Finding(
                rule_id="AG007",
                title="Toxic flow: code-execution feeding a network sink",
                severity="high",
                tool_name=(src.name if same else f"{src.name} + {sink.name}"),
                detail=(
                    f"A tool that can execute code ('{src.name}') combined with a tool "
                    f"that can reach the network ('{sink.name}') gives the agent a path to "
                    "run attacker-chosen commands and send the results out."
                ),
                owasp="MCP-06",
                evidence=f"source: {src.name} (code execution) -> sink: {sink.name} (network egress)",
            )
        )

    return findings
