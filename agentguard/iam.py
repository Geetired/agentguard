"""AWS IAM blast-radius analysis.

When an MCP server (or the agent hosting it) runs with AWS credentials, a
poisoned tool's real danger is bounded by what those credentials can do. This
module takes the IAM policies attached to an identity and reports the blast
radius: wildcard access, effective admin, and known privilege-escalation
permissions that let a limited role become admin.

It is pure-Python and works on policy documents you pass in, so it can be unit
tested with no AWS account. `collect.py` fetches those documents live from a
read-only session when you do have one.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from .detectors import Finding


# A compact catalog of IAM actions that let a principal escalate to broader
# access. Each is a well-documented escalation path (see Rhino Security Labs'
# "AWS IAM Privilege Escalation" research). Kept short and high-signal.
PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:CreateAccessKey": "Mint access keys for another user",
    "iam:CreateLoginProfile": "Set a console password for another user",
    "iam:UpdateLoginProfile": "Reset another user's console password",
    "iam:AttachUserPolicy": "Attach any managed policy to a user",
    "iam:AttachRolePolicy": "Attach any managed policy to a role",
    "iam:AttachGroupPolicy": "Attach any managed policy to a group",
    "iam:PutUserPolicy": "Inline any policy onto a user",
    "iam:PutRolePolicy": "Inline any policy onto a role",
    "iam:PutGroupPolicy": "Inline any policy onto a group",
    "iam:CreatePolicyVersion": "Publish a new default version of a policy",
    "iam:SetDefaultPolicyVersion": "Switch a policy to a more permissive version",
    "iam:PassRole": "Pass a role to a service (pairs with compute to run as it)",
    "iam:CreateRole": "Create a new role to assume",
    "iam:UpdateAssumeRolePolicy": "Rewrite who may assume a role",
    "sts:AssumeRole": "Assume another role",
    "lambda:CreateFunction": "Run code under a passed role",
    "lambda:UpdateFunctionCode": "Replace code in a function that has a role",
    "ec2:RunInstances": "Launch an instance with an instance profile",
    "glue:CreateDevEndpoint": "Run code under a passed Glue role",
    "cloudformation:CreateStack": "Deploy resources under a passed role",
}

# Actions whose reach is high enough to call out even without escalation.
_SENSITIVE_PREFIXES = ("secretsmanager:", "kms:", "s3:Delete", "s3:PutObject",
                       "rds:Delete", "ec2:TerminateInstances", "dynamodb:Delete")


@dataclass
class Statement:
    effect: str
    actions: list[str]
    resources: list[str]

    @classmethod
    def from_doc(cls, raw: dict[str, Any]) -> "Statement":
        def _as_list(v: Any) -> list[str]:
            if v is None:
                return []
            return [v] if isinstance(v, str) else list(v)
        return cls(
            effect=raw.get("Effect", "Allow"),
            actions=_as_list(raw.get("Action")),
            resources=_as_list(raw.get("Resource")),
        )


@dataclass
class PolicyReport:
    identity: str
    allowed_actions: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)


def _statements(policy: dict[str, Any]) -> list[Statement]:
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [Statement.from_doc(s) for s in stmts]


def _action_matches(pattern: str, action: str) -> bool:
    # IAM uses '*' globbing, case-insensitive on the action name.
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def analyze_policies(identity: str, policies: list[dict[str, Any]]) -> PolicyReport:
    """Analyze the Allow statements of an identity's attached policies."""
    report = PolicyReport(identity=identity)
    allow_stmts: list[Statement] = []
    for policy in policies:
        for st in _statements(policy):
            if st.effect == "Allow":
                allow_stmts.append(st)
                report.allowed_actions.update(st.actions)

    # 1. Full admin: Action "*" on Resource "*".
    for st in allow_stmts:
        if any(a == "*" for a in st.actions) and any(r == "*" for r in st.resources):
            report.findings.append(Finding(
                rule_id="IAM001",
                title="Effective administrator access",
                severity="critical",
                tool_name=identity,
                detail="Grants Action '*' on Resource '*': these credentials can do anything in the account.",
                owasp="MCP-02",
                evidence='"Action": "*", "Resource": "*"',
            ))
            break

    # 2. Service-wide wildcards, e.g. "s3:*" or "iam:*".
    for st in allow_stmts:
        for a in st.actions:
            if a.endswith(":*"):
                report.findings.append(Finding(
                    rule_id="IAM002",
                    title=f"Service-wide wildcard: {a}",
                    severity="high",
                    tool_name=identity,
                    detail=f"Grants every action in {a.split(':')[0]}; far broader than least privilege.",
                    owasp="MCP-02",
                    evidence=a,
                ))

    # 3. Privilege-escalation actions.
    for action, why in PRIVILEGE_ESCALATION_ACTIONS.items():
        if _identity_can(action, allow_stmts):
            report.findings.append(Finding(
                rule_id="IAM003",
                title=f"Privilege-escalation permission: {action}",
                severity="high",
                tool_name=identity,
                detail=f"{why}. A limited role with this can become admin.",
                owasp="MCP-02",
                evidence=action,
            ))

    # 4. Otherwise-sensitive reach worth surfacing at medium.
    for action in sorted(report.allowed_actions):
        if action.startswith(_SENSITIVE_PREFIXES):
            report.findings.append(Finding(
                rule_id="IAM004",
                title=f"Sensitive permission: {action}",
                severity="medium",
                tool_name=identity,
                detail="High-impact action (secrets, keys, or destructive) reachable by these credentials.",
                owasp="MCP-02",
                evidence=action,
            ))

    from .detectors import SEVERITY_ORDER
    report.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return report


def _identity_can(action: str, statements: list[Statement]) -> bool:
    """True if any Allow statement's action patterns cover `action`."""
    for st in statements:
        for pattern in st.actions:
            if pattern == "*" or _action_matches(pattern, action):
                return True
    return False
