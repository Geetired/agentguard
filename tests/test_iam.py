"""Tests for the IAM blast-radius analyzer (offline, no AWS)."""
import json
from pathlib import Path

from agentguard.iam import analyze_policies

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "iam"


def _load(name):
    return json.loads((SAMPLES / name).read_text())


def _ids(report):
    return {f.rule_id for f in report.findings}


def test_admin_star_is_critical():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    report = analyze_policies("admin-role", [policy])
    assert "IAM001" in _ids(report)
    assert report.findings[0].severity == "critical"


def test_overprivileged_role_flags_wildcard_and_escalation():
    report = analyze_policies("role", [_load("overprivileged_role.json")])
    ids = _ids(report)
    assert "IAM002" in ids  # s3:* wildcard
    assert "IAM003" in ids  # iam:CreateAccessKey / iam:PassRole escalation
    assert "IAM004" in ids  # secretsmanager:GetSecretValue sensitive
    titles = " ".join(f.title for f in report.findings)
    assert "iam:CreateAccessKey" in titles
    assert "iam:PassRole" in titles


def test_least_privilege_role_is_clean():
    report = analyze_policies("role", [_load("least_privilege_role.json")])
    assert report.findings == []


def test_wildcard_action_covers_escalation():
    # A "*" action should count as being able to escalate.
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    report = analyze_policies("role", [policy])
    assert "IAM003" in _ids(report)


def test_deny_statements_are_ignored_for_allow_analysis():
    policy = {"Statement": [
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
    ]}
    report = analyze_policies("role", [policy])
    # The Deny "*" must not be read as granting admin.
    assert "IAM001" not in _ids(report)
    assert report.findings == []
