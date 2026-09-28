"""Benchmark AgentGuard's detection against a labeled corpus.

The corpus is a directory of tool-definition JSON files split into `malicious/`
(should produce at least one finding) and `benign/` (should produce none). We
compute standard detection metrics so the accuracy claim is measured, not
asserted, and emit a Markdown table you can paste into a README or blog post.

`run_scanner` takes any callable that maps a Tool to a list of findings, so a
second scanner (e.g. an adapter around another tool's output) can be dropped in
to produce a head-to-head comparison. AgentGuard's own detector is the default.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .detectors import Tool, scan_tool
from .loader import load_tools_json

Scanner = Callable[[Tool], list]


@dataclass
class Metrics:
    scanner: str
    true_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    false_positive: int = 0

    @property
    def detected(self) -> int:
        return self.true_positive + self.false_negative

    @property
    def detection_rate(self) -> float:
        total_bad = self.true_positive + self.false_negative
        return self.true_positive / total_bad if total_bad else 0.0

    @property
    def false_positive_rate(self) -> float:
        total_good = self.true_negative + self.false_positive
        return self.false_positive / total_good if total_good else 0.0

    @property
    def precision(self) -> float:
        flagged = self.true_positive + self.false_positive
        return self.true_positive / flagged if flagged else 0.0


def _load_labeled(corpus_dir: Path) -> list[tuple[Tool, bool]]:
    """Return (tool, is_malicious) for every sample in the corpus."""
    items: list[tuple[Tool, bool]] = []
    for label, is_bad in (("malicious", True), ("benign", False)):
        for path in sorted((corpus_dir / label).glob("*.json")):
            for tool in load_tools_json(path):
                items.append((tool, is_bad))
    return items


def evaluate(corpus_dir: str | Path, scanner: Scanner = scan_tool,
             name: str = "AgentGuard") -> Metrics:
    """Run a scanner over the corpus and tally detection metrics."""
    metrics = Metrics(scanner=name)
    for tool, is_bad in _load_labeled(Path(corpus_dir)):
        flagged = bool(scanner(tool))
        if is_bad and flagged:
            metrics.true_positive += 1
        elif is_bad and not flagged:
            metrics.false_negative += 1
        elif not is_bad and flagged:
            metrics.false_positive += 1
        else:
            metrics.true_negative += 1
    return metrics


def to_markdown_table(results: list[Metrics]) -> str:
    """Render a comparison table across one or more scanners."""
    header = ("| Scanner | Detection rate | False-positive rate | Precision |\n"
              "|---------|---------------:|--------------------:|----------:|")
    rows = [
        f"| {m.scanner} | {m.detection_rate:.0%} | "
        f"{m.false_positive_rate:.0%} | {m.precision:.0%} |"
        for m in results
    ]
    return "\n".join([header, *rows])
