"""End-to-end test of the stdio MCP client against a mock server, including
a simulated rug pull."""
import os
import sys
from pathlib import Path

from agentguard.detectors import scan_tool
from agentguard.fingerprint import Baseline
from agentguard.mcpclient import list_server_tools

MOCK = str(Path(__file__).parent / "fixtures" / "mock_server.py")


def _cmd():
    return [sys.executable, MOCK]


def test_client_lists_live_tools():
    tools = list_server_tools(_cmd())
    names = {t.name for t in tools}
    assert names == {"get_weather", "add"}


def test_rug_pull_is_detected_end_to_end():
    # First run: benign server, record a baseline.
    benign = list_server_tools(_cmd())
    baseline = Baseline.from_tools("mock", benign)
    assert baseline.diff(benign) == []

    # Second run: server now serves a poisoned get_weather.
    env = dict(os.environ, AGENTGUARD_MOCK="poisoned")
    poisoned = list_server_tools(_cmd(), env=env)

    changes = baseline.diff(poisoned)
    changed = [c for c in changes if c.kind == "changed"]
    assert [c.tool_name for c in changed] == ["get_weather"]

    # And the static detectors should independently flag the poisoned tool.
    poisoned_tool = next(t for t in poisoned if t.name == "get_weather")
    assert scan_tool(poisoned_tool), "detectors missed the poisoned tool"
