"""AgentGuard: a security scanner for AI agents and MCP servers."""
from .detectors import Finding, Tool, scan_tool

__version__ = "0.1.0"
__all__ = ["Finding", "Tool", "scan_tool", "__version__"]
