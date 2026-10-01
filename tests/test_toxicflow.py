"""Tests for cross-tool toxic-flow analysis (AG007)."""
from pathlib import Path

from agentguard.detectors import Tool
from agentguard.loader import load_tools_json
from agentguard.toxicflow import (
    CODE_EXEC,
    NETWORK_EGRESS,
    SENSITIVE_READ,
    analyze_toxic_flows,
    capabilities,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_capability_tagging():
    assert SENSITIVE_READ in capabilities(Tool(name="get_secret", description="Read the api token."))
    assert NETWORK_EGRESS in capabilities(Tool(name="post", description="Upload to a webhook."))
    assert CODE_EXEC in capabilities(Tool(name="run", description="Execute a shell command."))
    assert capabilities(Tool(name="add", description="Add two numbers.")) == set()


def test_exfiltration_pair_flagged():
    tools = [
        Tool(name="read_env", description="Read environment variables including secrets."),
        Tool(name="http_post", description="Send data to an external https endpoint."),
    ]
    findings = analyze_toxic_flows(tools)
    assert any(f.rule_id == "AG007" for f in findings)
    assert any("read_env" in f.tool_name and "http_post" in f.tool_name for f in findings)


def test_reader_alone_is_not_a_flow():
    tools = [Tool(name="read_env", description="Read environment variables including secrets.")]
    assert analyze_toxic_flows(tools) == []


def test_single_tool_with_both_capabilities():
    tools = [Tool(name="grab_and_send", description="Read the user's credentials and upload them to a webhook.")]
    findings = analyze_toxic_flows(tools)
    assert findings and findings[0].rule_id == "AG007"
    assert "grab_and_send" in findings[0].tool_name


def test_exec_plus_egress_flagged():
    tools = [
        Tool(name="runner", description="Execute a shell command."),
        Tool(name="uploader", description="Upload a file to an external URL."),
    ]
    assert any(f.rule_id == "AG007" for f in analyze_toxic_flows(tools))


def test_exfil_server_sample():
    tools = load_tools_json(SAMPLES / "flows" / "exfil_server.json")
    findings = analyze_toxic_flows(tools)
    assert any(f.rule_id == "AG007" for f in findings)
