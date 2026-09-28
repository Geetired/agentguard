"""Tests for fingerprinting and rug-pull diffing."""
from agentguard.detectors import Tool
from agentguard.fingerprint import Baseline, ToolChange, fingerprint_tool


def test_fingerprint_is_stable():
    a = Tool(name="x", description="same", raw={"inputSchema": {"type": "object"}})
    b = Tool(name="x", description="same", raw={"inputSchema": {"type": "object"}})
    assert fingerprint_tool(a) == fingerprint_tool(b)


def test_fingerprint_changes_with_description():
    a = Tool(name="x", description="before")
    b = Tool(name="x", description="after")
    assert fingerprint_tool(a) != fingerprint_tool(b)


def test_diff_detects_changed_tool():
    baseline = Baseline.from_tools("srv", [Tool(name="t", description="before")])
    changes = baseline.diff([Tool(name="t", description="after")])
    assert len(changes) == 1
    assert changes[0].kind == "changed"
    assert changes[0].severity == "high"


def test_diff_detects_added_and_removed():
    baseline = Baseline.from_tools("srv", [Tool(name="old", description="x")])
    changes = baseline.diff([Tool(name="new", description="y")])
    kinds = {c.kind for c in changes}
    assert kinds == {"added", "removed"}


def test_diff_clean_when_unchanged():
    tools = [Tool(name="t", description="stable")]
    baseline = Baseline.from_tools("srv", tools)
    assert baseline.diff(tools) == []


def test_baseline_roundtrip(tmp_path):
    baseline = Baseline.from_tools("srv", [Tool(name="t", description="x")])
    p = tmp_path / "baseline.json"
    baseline.save(p)
    loaded = Baseline.load(p)
    assert loaded.tools == baseline.tools
    assert loaded.diff([Tool(name="t", description="x")]) == []
