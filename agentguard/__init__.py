"""AgentGuard: a security scanner for AI agents and MCP servers."""
from .detectors import Finding, Tool, scan_tool
from .fingerprint import Baseline, ToolChange, fingerprint_tool
from .iam import PolicyReport, analyze_policies

__version__ = "0.3.0"
__all__ = [
    "Finding", "Tool", "scan_tool",
    "Baseline", "ToolChange", "fingerprint_tool",
    "PolicyReport", "analyze_policies",
    "__version__",
]
