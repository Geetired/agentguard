"""Tests for the pluggable LLM second-opinion interface (heuristic backend)."""
from agentguard.classify import HeuristicBackend, Verdict, review
from agentguard.detectors import Finding


def _f(severity, evidence=""):
    return Finding(rule_id="X", title="t", severity=severity,
                   tool_name="n", detail="d", evidence=evidence)


def test_high_severity_with_signal_is_confident_real():
    v = HeuristicBackend().judge(_f("high", "ignore previous instructions"))
    assert v.is_real
    assert v.confidence >= 0.9


def test_low_severity_no_signal_is_not_real():
    v = HeuristicBackend().judge(_f("low"))
    assert not v.is_real


def test_review_attaches_a_verdict_per_finding():
    findings = [_f("high"), _f("info")]
    pairs = review(findings)
    assert len(pairs) == 2
    assert all(isinstance(v, Verdict) for _, v in pairs)


def test_review_accepts_a_custom_backend():
    class AlwaysReal:
        def judge(self, finding):
            return Verdict(True, 1.0, "stub")

    pairs = review([_f("info")], backend=AlwaysReal())
    assert pairs[0][1].is_real
