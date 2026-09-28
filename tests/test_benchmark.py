"""Tests for the benchmark runner over the labeled corpus."""
from pathlib import Path

from agentguard.benchmark import evaluate, to_markdown_table

CORPUS = Path(__file__).resolve().parent.parent / "samples"


def test_agentguard_catches_all_malicious_and_no_false_positives():
    m = evaluate(CORPUS)
    assert m.false_negative == 0, "missed a malicious sample"
    assert m.false_positive == 0, "flagged a benign sample"
    assert m.detection_rate == 1.0
    assert m.true_positive > 0 and m.true_negative > 0


def test_blind_scanner_scores_poorly():
    # A scanner that flags nothing should miss every malicious sample.
    m = evaluate(CORPUS, scanner=lambda tool: [], name="no-op")
    assert m.detection_rate == 0.0
    assert m.false_positive_rate == 0.0


def test_markdown_table_has_a_row_per_scanner():
    a = evaluate(CORPUS, name="AgentGuard")
    b = evaluate(CORPUS, scanner=lambda t: [], name="no-op")
    table = to_markdown_table([a, b])
    assert "AgentGuard" in table
    assert "no-op" in table
    assert table.count("\n") == 3  # header, separator, two rows
