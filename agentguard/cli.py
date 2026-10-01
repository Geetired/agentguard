"""AgentGuard command-line interface.

    agentguard scan  <config.json|tools.json>     static scan a config/tools file
    agentguard live  -- <server command...>       connect to a running server, scan it
    agentguard baseline -o base.json -- <cmd...>   record a fingerprint baseline
    agentguard diff  -b base.json -- <cmd...>      detect rug-pulls vs a baseline
    agentguard iam   -p policy.json                report an identity's AWS blast-radius
    agentguard benchmark <corpus dir>             score detection over a labeled corpus

scan/live also take --sarif PATH and --html PATH to write reports. Exit code is
non-zero when a finding at or above --fail-on is present (scan/live/iam) or when
any change is detected (diff), so each works as a CI gate.
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
from .toxicflow import analyze_toxic_flows

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


def _scan_and_report(tools, args, source: str = "mcp-config") -> int:
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(scan_tool(tool))
    # Cross-tool pass: toxic flows need the whole tool set, not one tool.
    findings.extend(analyze_toxic_flows(list(tools)))
    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        print(_render_text(findings, use_color=not args.no_color and sys.stdout.isatty()))
        print(f"\nScanned {len(tools)} tool(s), {len(findings)} finding(s).")

    _write_reports(findings, args, source)

    fail_at = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= fail_at for f in findings) else 0


def _add_scan_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Emit JSON findings")
    p.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    p.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER),
                   help="Exit non-zero if a finding at/above this severity exists")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--sarif", metavar="PATH", help="Also write a SARIF report to PATH")
    p.add_argument("--html", metavar="PATH", help="Also write an HTML report to PATH")


def _write_reports(findings, args, source: str = "mcp-config") -> None:
    if getattr(args, "sarif", None):
        from .report import write_sarif
        write_sarif(findings, args.sarif, source_uri=source)
        print(f"Wrote SARIF report to {args.sarif}")
    if getattr(args, "html", None):
        from .report import write_html
        write_html(findings, args.html)
        print(f"Wrote HTML report to {args.html}")


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

    iam = sub.add_parser("iam", help="Analyze IAM blast-radius of an identity's policies")
    iam.add_argument("-p", "--policy", type=Path, action="append", default=[],
                     help="A policy document JSON file (repeatable)")
    iam.add_argument("--role", help="Fetch policies live for this IAM role name (needs boto3)")
    iam.add_argument("--profile", help="AWS profile to use with --role")
    iam.add_argument("--json", action="store_true")
    iam.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER))
    iam.add_argument("--no-color", action="store_true")

    bench = sub.add_parser("benchmark", help="Score detection over a labeled corpus")
    bench.add_argument("corpus", type=Path, help="Dir with malicious/ and benign/ subdirs")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.path.exists():
            print(f"error: no such file: {args.path}", file=sys.stderr)
            return 2
        return _scan_and_report(_collect(args.path), args, source=str(args.path))

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
            return _scan_and_report(tools, args, source=" ".join(command))

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

    if args.command == "iam":
        return _run_iam(args)

    if args.command == "benchmark":
        from .benchmark import evaluate, to_markdown_table
        if not args.corpus.is_dir():
            print(f"error: not a directory: {args.corpus}", file=sys.stderr)
            return 2
        metrics = evaluate(args.corpus)
        print(to_markdown_table([metrics]))
        print(f"\n{metrics.true_positive}/{metrics.detected} malicious caught, "
              f"{metrics.false_positive} false positive(s).")
        return 0

    return 2


def _run_iam(args) -> int:
    from .iam import analyze_policies

    policies: list[dict] = []
    identity = "identity"
    for path in args.policy:
        if not path.exists():
            print(f"error: no such policy file: {path}", file=sys.stderr)
            return 2
        policies.append(json.loads(path.read_text(encoding="utf-8")))

    if args.role:
        try:
            from .collect import collect_role_policies
            policies.extend(collect_role_policies(args.role, profile=args.profile))
            identity = args.role
        except Exception as exc:  # AWSUnavailable or a boto error
            print(f"error: could not fetch IAM policies: {exc}", file=sys.stderr)
            return 2

    if not policies:
        print("error: pass at least one --policy file or --role", file=sys.stderr)
        return 2

    report = analyze_policies(identity, policies)
    if args.json:
        print(json.dumps([f.__dict__ for f in report.findings], indent=2))
    else:
        print(_render_text(report.findings, use_color=not args.no_color and sys.stdout.isatty()))
        print(f"\nAnalyzed {len(report.allowed_actions)} distinct allowed action(s), "
              f"{len(report.findings)} finding(s).")

    fail_at = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= fail_at for f in report.findings) else 0


def _server_command(remainder: list[str]) -> list[str]:
    # argparse.REMAINDER keeps a leading "--"; drop it.
    return remainder[1:] if remainder and remainder[0] == "--" else remainder


if __name__ == "__main__":
    raise SystemExit(main())
