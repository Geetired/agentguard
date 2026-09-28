# Changelog

## 0.5.0
- Reusable GitHub Action (`action.yml`) — add AgentGuard to any CI in a few lines.
- PyPI packaging and a Trusted-Publishing release workflow (publishes on `v*` tags).
- `python -m agentguard` entry point.
- Write-up, example consumer workflow, and this changelog.

## 0.4.0
- SARIF output (GitHub code scanning) and a standalone HTML report.
- Benchmark runner over a labeled corpus with a Markdown comparison table.
- Optional, pluggable LLM second-opinion (offline heuristic default).

## 0.3.0
- AWS IAM blast-radius analyzer (admin, wildcards, 20+ privilege-escalation paths).
- Optional read-only boto3 collector for live roles.

## 0.2.0
- Live stdio MCP client (connect + list tools).
- Tool fingerprinting and rug-pull diff (`baseline` / `diff`).

## 0.1.0
- Static scanner for MCP configs and tool definitions (injection, hidden Unicode,
  secrets, unpinned packages), CLI, labeled sample corpus, and CI.
