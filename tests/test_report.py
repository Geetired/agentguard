"""Tests for SARIF and HTML report rendering."""
from agentguard.detectors import Finding
from agentguard.report import to_html, to_sarif


def _finding():
    return Finding(rule_id="AG001", title="Injection", severity="high",
                   tool_name="get_weather", detail="bad", owasp="MCP-01",
                   evidence="ignore previous instructions")


def test_sarif_is_valid_shape():
    doc = to_sarif([_finding()])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AgentGuard"
    assert run["results"][0]["ruleId"] == "AG001"
    assert run["results"][0]["level"] == "error"  # high -> error
    # Each result's rule must be declared in the driver's rule list.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"][0]["ruleId"] in rule_ids


def test_sarif_severity_mapping():
    med = Finding(rule_id="X", title="t", severity="medium", tool_name="n", detail="d")
    assert to_sarif([med])["runs"][0]["results"][0]["level"] == "warning"


def test_html_contains_finding_and_escapes():
    evil = Finding(rule_id="X", title="<script>", severity="critical",
                   tool_name="t", detail="d", evidence="<b>")
    out = to_html([evil])
    assert "AgentGuard" in out
    assert "&lt;script&gt;" in out  # escaped, not raw
    assert "<script>" not in out.replace("&lt;script&gt;", "")


def test_html_empty_is_clean():
    out = to_html([])
    assert "No findings" in out
