# Changelog

## 0.7.0
- AG007: cross-tool "toxic flow" analysis. Tags each tool's capabilities
  (sensitive-read, network-egress, code-exec) and flags dangerous source -> sink
  combinations — e.g. a data reader plus a network sink that can be chained to
  exfiltrate secrets (the "lethal trifecta") — even when no single tool is
  malicious. Runs over the whole tool set in `scan`/`live`.

## 0.6.0
- AG005: unvalidated URL parameters in a tool's input schema (SSRF risk, CWE-918).
- AG006: unrestricted file-path parameters in a tool's input schema (path traversal, CWE-22).
  Both read the declared JSON-Schema inputs and suppress findings when the param is
  constrained (enum/pattern) or the tool documents an allow-list, and skip deprecated tools.
- Corrected OWASP MCP Top 10 mappings to the official 2025 list: tool poisoning MCP-03,
  secret exposure MCP-01, supply chain MCP-04, privilege escalation (IAM) MCP-02,
  input-validation flaws MCP-05.

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
