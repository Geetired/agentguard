"""Optional LLM second opinion on borderline findings.

The static detectors are deliberately conservative and can misfire (e.g. a tool
whose description legitimately says "read credentials" in docs). A second opinion
from an LLM helps triage: is this finding a real attack, or benign phrasing?

The backend is pluggable. The default `HeuristicBackend` is offline and
deterministic so the tool and its tests need no network or API key. An optional
`AnthropicBackend` sends the finding to Claude for a verdict; install it with
`pip install 'agentguard[llm]'` and set ANTHROPIC_API_KEY.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .detectors import Finding


@dataclass
class Verdict:
    is_real: bool
    confidence: float  # 0.0 - 1.0
    rationale: str


class Backend(Protocol):
    def judge(self, finding: Finding) -> Verdict: ...


class HeuristicBackend:
    """A cheap, offline triage that needs no API key.

    It leans on the detector's own severity plus a few strong lexical signals,
    so it is useful as a default and as a deterministic test double for the
    pluggable interface.
    """

    _STRONG = ("ignore previous", "do not tell", "~/.aws", ".env", "secret",
               "exfil", "credentials", "api key")

    def judge(self, finding: Finding) -> Verdict:
        text = f"{finding.detail} {finding.evidence}".lower()
        hits = [s for s in self._STRONG if s in text]
        if finding.severity in ("critical", "high") and hits:
            return Verdict(True, 0.9, f"High severity with strong signals: {', '.join(hits)}")
        if finding.severity in ("critical", "high"):
            return Verdict(True, 0.65, "High severity finding; likely real.")
        if hits:
            return Verdict(True, 0.55, f"Lower severity but strong signals: {', '.join(hits)}")
        return Verdict(False, 0.4, "No strong signals; may be benign phrasing.")


class AnthropicBackend:
    """Ask Claude whether a finding is a real attack. Optional; needs the SDK."""

    def __init__(self, model: str = "claude-opus-5") -> None:
        try:
            import anthropic  # noqa: WPS433
        except ImportError as exc:  # pragma: no cover - only without the SDK
            raise RuntimeError(
                "anthropic is not installed; run `pip install 'agentguard[llm]'`"
            ) from exc
        self._client = anthropic.Anthropic()
        self._model = model

    def judge(self, finding: Finding) -> Verdict:  # pragma: no cover - needs network
        import json

        prompt = (
            "You are a security triage assistant for MCP tool definitions. "
            "Decide whether the following scanner finding is a REAL attack "
            "(tool poisoning, prompt injection, credential theft) or a benign "
            "false positive. Respond with JSON: "
            '{"is_real": bool, "confidence": 0-1, "rationale": "..."}.\n\n'
            f"Rule: {finding.title}\nDetail: {finding.detail}\n"
            f"Evidence: {finding.evidence}\nSeverity: {finding.severity}"
        )
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        try:
            data = json.loads(text)
            return Verdict(bool(data["is_real"]), float(data["confidence"]),
                           str(data.get("rationale", "")))
        except (ValueError, KeyError):
            # Fall back to a conservative verdict if the model didn't return JSON.
            return Verdict(True, 0.5, "Model response was not parseable; kept as real.")


def review(findings: list[Finding], backend: Backend | None = None) -> list[tuple[Finding, Verdict]]:
    """Attach a verdict to each finding using the given (or heuristic) backend."""
    backend = backend or HeuristicBackend()
    return [(f, backend.judge(f)) for f in findings]
