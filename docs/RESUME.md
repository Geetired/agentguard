# Resume material for AgentGuard

## One-line project title
**AgentGuard — open-source security scanner for AI agents and MCP servers**

## Resume bullets (pick 2–3)

- Built **AgentGuard**, an open-source security scanner for AI agents and MCP
  servers that detects tool-poisoning, prompt-injection, hidden-Unicode and
  supply-chain risks in tool definitions, mapped to the OWASP MCP Top 10.
- Added a **live MCP client** and tool-fingerprinting that catches "rug-pull"
  attacks (a tool silently changing after approval), with an end-to-end test
  suite proving detection against a mock malicious server.
- Implemented **AWS IAM blast-radius analysis** linking each flagged tool to what
  its credentials can reach, detecting effective admin, service-wide wildcards,
  and 20+ known privilege-escalation paths.
- Shipped **SARIF output into GitHub code scanning** and a reusable **GitHub
  Action**, so the scanner drops into any CI pipeline in a few lines and reports
  findings on the PR diff and Security tab.
- Published a **measured detection benchmark** (100% detection / 0% false
  positives on the labeled corpus) with an extensible runner for head-to-head
  comparison against other scanners.

## Talking points for interviews

- **Why it matters (2026 context):** agentic AI and MCP are the fastest-growing
  new attack surface; tool poisoning and non-human-identity risk are top security
  concerns. Few candidates have shipped anything here.
- **The differentiator:** existing scanners mostly read tool text. AgentGuard ties
  a finding to real IAM blast radius, and proves accuracy with a benchmark.
- **Engineering choices:** dependency-free core, one small detector per attack
  class (easy to test and extend), IAM analyzer that works offline on policy JSON,
  minimal hand-rolled MCP JSON-RPC client.
- **Defensive framing:** the malicious samples are test fixtures (like malware
  samples used to test antivirus), used only to validate the detector.

## Links
- Repo: https://github.com/Geetired/agentguard
- Write-up: docs/WRITEUP.md
