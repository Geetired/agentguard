"""Report renderers: SARIF (for GitHub's Security tab) and a standalone HTML report.

SARIF is the format GitHub code scanning ingests, so `agentguard ... --sarif out.sarif`
plus the upload-sarif action makes AgentGuard findings appear as annotations in the
Security tab and on the PR diff. The HTML report is a self-contained artifact for a
demo or a portfolio.
"""
from __future__ import annotations

import html
import json
from typing import Iterable

from .detectors import Finding

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(findings: Iterable[Finding], tool_version: str = "0.7.0",
             source_uri: str = "mcp-config") -> dict:
    """Build a SARIF 2.1.0 document from findings.

    ``source_uri`` is the artifact each finding points at. GitHub code scanning
    requires every result to carry a *physical* location (an artifact URI), so
    we anchor findings to the scanned file/server, keeping the tool name as a
    logical location for readability.
    """
    findings = list(findings)
    # One rule per distinct rule_id, with its most severe title as the name.
    rules: dict[str, dict] = {}
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "properties": {"owasp-mcp": f.owasp} if f.owasp else {},
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.detail}"},
            "properties": {"severity": f.severity, "tool": f.tool_name,
                           "owasp-mcp": f.owasp, "evidence": f.evidence},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": source_uri},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.tool_name, "kind": "resource"}],
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentGuard",
                "informationUri": "https://github.com/Geetired/agentguard",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(findings: Iterable[Finding], path: str, source_uri: str = "mcp-config") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(findings, source_uri=source_uri), fh, indent=2)


_SEV_COLOR = {"critical": "#b71c1c", "high": "#e53935", "medium": "#fb8c00",
              "low": "#1e88e5", "info": "#757575"}


def to_html(findings: Iterable[Finding], title: str = "AgentGuard report") -> str:
    """A single self-contained HTML page summarizing findings."""
    findings = list(findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    def esc(s: str) -> str:
        return html.escape(s or "")

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{counts[s]} {s}</span>'
        for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    ) or '<span class="chip" style="background:#2e7d32">0 findings</span>'

    rows = "\n".join(
        f'<tr>'
        f'<td><span class="dot" style="background:{_SEV_COLOR[f.severity]}"></span>{esc(f.severity)}</td>'
        f'<td><code>{esc(f.tool_name)}</code></td>'
        f'<td>{esc(f.title)}<div class="detail">{esc(f.detail)}</div></td>'
        f'<td>{esc(f.owasp)}</td>'
        f'<td><code>{esc(f.evidence)}</code></td>'
        f'</tr>'
        for f in findings
    ) or '<tr><td colspan="5" class="clean">No findings ✓</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:2rem;
  background:#fafafa;color:#1a1a1a}}
@media (prefers-color-scheme:dark){{body{{background:#121212;color:#e8e8e8}}
  table{{background:#1e1e1e}} th{{background:#262626}}}}
h1{{margin:0 0 .25rem;font-size:1.4rem}}
.sub{{color:#888;margin-bottom:1rem}}
.chip{{display:inline-block;color:#fff;padding:.2rem .6rem;border-radius:999px;
  font-size:.8rem;margin-right:.4rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem;background:#fff;
  border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th,td{{text-align:left;padding:.6rem .8rem;border-bottom:1px solid rgba(128,128,128,.2);
  vertical-align:top}}
th{{background:#f0f0f0;font-size:.75rem;text-transform:uppercase;letter-spacing:.03em}}
.dot{{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.4rem}}
.detail{{color:#888;font-size:.85rem;margin-top:.2rem}}
code{{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace}}
.clean{{text-align:center;color:#2e7d32;padding:2rem}}
</style></head>
<body>
<h1>{esc(title)}</h1>
<div class="sub">AgentGuard — MCP / AI-agent security scan</div>
<div>{chips}</div>
<table>
<thead><tr><th>Severity</th><th>Tool</th><th>Finding</th><th>OWASP MCP</th><th>Evidence</th></tr></thead>
<tbody>
{rows}
</tbody></table>
</body></html>"""


def write_html(findings: Iterable[Finding], path: str, title: str = "AgentGuard report") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_html(findings, title=title))
