"""AgentGuard: a security scanner for AI agents and MCP servers."""
from .detectors import Finding, Tool, scan_tool
from .fingerprint import Baseline, ToolChange, fingerprint_tool
from .iam import PolicyReport, analyze_policies
from .report import to_html, to_sarif
from .benchmark import Metrics, evaluate
from .classify import Verdict, review

__version__ = "0.4.0"
__all__ = [
    "Finding", "Tool", "scan_tool",
    "Baseline", "ToolChange", "fingerprint_tool",
    "PolicyReport", "analyze_policies",
    "to_html", "to_sarif",
    "Metrics", "evaluate",
    "Verdict", "review",
    "__version__",
]
