"""AgentGuard command-line interface.

    agentguard scan <config.json|tools.json> [--json] [--min-severity low]

Exit code is non-zero when a finding at or above --fail-on is present, so it
works as a CI gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detectors import SEVERITY_ORDER, Finding, scan_tool
from .loader import load_config, load_tools_json

_COLORS = {"critical": "\033[41m", "high": "\033[91m", "medium": "\033[93m",
           "low": "\033[94m", "info": "\033[90m"}
_RESET = "\033[0m"


def _looks_like_config(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(data, dict) and ("mcpServers" in data or "servers" in data)


def _collect(path: Path):
    return load_config(path) if _looks_like_config(path) else load_tools_json(path)


def _render_text(findings: list[Finding], use_color: bool) -> str:
    if not findings:
        return "No findings. ✓"
    lines = []
    for f in findings:
        tag = f.severity.upper()
        if use_color:
            tag = f"{_COLORS.get(f.severity, '')}{tag}{_RESET}"
        owasp = f" [{f.owasp}]" if f.owasp else ""
        lines.append(f"{tag:<9} {f.tool_name}: {f.title}{owasp}")
        lines.append(f"          {f.detail}")
        if f.evidence:
            lines.append(f"          evidence: {f.evidence}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an MCP config or tools file")
    scan.add_argument("path", type=Path)
    scan.add_argument("--json", action="store_true", help="Emit JSON findings")
    scan.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    scan.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER),
                      help="Exit non-zero if a finding at/above this severity exists")
    scan.add_argument("--no-color", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.path.exists():
            print(f"error: no such file: {args.path}", file=sys.stderr)
            return 2
        tools = _collect(args.path)
        findings: list[Finding] = []
        for tool in tools:
            findings.extend(scan_tool(tool))
        threshold = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
        findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)

        if args.json:
            print(json.dumps([f.__dict__ for f in findings], indent=2))
        else:
            print(_render_text(findings, use_color=not args.no_color and sys.stdout.isatty()))
            print(f"\nScanned {len(tools)} tool(s), {len(findings)} finding(s).")

        fail_at = SEVERITY_ORDER[args.fail_on]
        return 1 if any(SEVERITY_ORDER[f.severity] >= fail_at for f in findings) else 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
