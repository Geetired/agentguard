"""AgentGuard command-line interface.

    agentguard scan  <config.json|tools.json>     static scan a config/tools file
    agentguard live  -- <server command...>       connect to a running server, scan it
    agentguard baseline -o base.json -- <cmd...>   record a fingerprint baseline
    agentguard diff  -b base.json -- <cmd...>      detect rug-pulls vs a baseline

Exit code is non-zero when a finding at or above --fail-on is present (scan/live)
or when any change is detected (diff), so each works as a CI gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detectors import SEVERITY_ORDER, Finding, scan_tool
from .fingerprint import Baseline
from .loader import load_config, load_tools_json
from .mcpclient import MCPClientError, list_server_tools

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


def _scan_and_report(tools, args) -> int:
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


def _add_scan_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Emit JSON findings")
    p.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    p.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER),
                   help="Exit non-zero if a finding at/above this severity exists")
    p.add_argument("--no-color", action="store_true")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Static scan of an MCP config or tools file")
    scan.add_argument("path", type=Path)
    _add_scan_flags(scan)

    live = sub.add_parser("live", help="Connect to a running MCP server and scan its tools")
    live.add_argument("server", nargs=argparse.REMAINDER,
                      help="-- followed by the server launch command")
    _add_scan_flags(live)

    base = sub.add_parser("baseline", help="Record a fingerprint baseline for a server")
    base.add_argument("-o", "--out", type=Path, required=True)
    base.add_argument("server", nargs=argparse.REMAINDER)

    diff = sub.add_parser("diff", help="Detect rug-pulls against a saved baseline")
    diff.add_argument("-b", "--baseline", type=Path, required=True)
    diff.add_argument("server", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.path.exists():
            print(f"error: no such file: {args.path}", file=sys.stderr)
            return 2
        return _scan_and_report(_collect(args.path), args)

    if args.command in ("live", "baseline", "diff"):
        command = _server_command(args.server)
        if not command:
            print("error: provide the server command after --, e.g. "
                  "`agentguard live -- npx some-mcp-server`", file=sys.stderr)
            return 2
        try:
            tools = list_server_tools(command)
        except (MCPClientError, OSError) as exc:
            print(f"error: could not talk to the MCP server: {exc}", file=sys.stderr)
            return 2

        if args.command == "live":
            return _scan_and_report(tools, args)

        if args.command == "baseline":
            Baseline.from_tools(" ".join(command), tools).save(args.out)
            print(f"Recorded {len(tools)} tool fingerprint(s) to {args.out}")
            return 0

        if args.command == "diff":
            if not args.baseline.exists():
                print(f"error: no baseline at {args.baseline}", file=sys.stderr)
                return 2
            changes = Baseline.load(args.baseline).diff(tools)
            if not changes:
                print("No changes since baseline. ✓")
                return 0
            for c in changes:
                print(f"{c.severity.upper():<9} {c.kind}: {c.tool_name}")
            print(f"\n{len(changes)} change(s) since baseline.")
            return 1

    return 2


def _server_command(remainder: list[str]) -> list[str]:
    # argparse.REMAINDER keeps a leading "--"; drop it.
    return remainder[1:] if remainder and remainder[0] == "--" else remainder


if __name__ == "__main__":
    raise SystemExit(main())
