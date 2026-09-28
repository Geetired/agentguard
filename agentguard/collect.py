"""Fetch IAM policy documents from a live AWS account (read-only).

Optional: needs boto3 (``pip install 'agentguard[aws]'``) and read-only
credentials, ideally the AWS-managed ``SecurityAudit`` policy. We only call
read/get/list APIs here; AgentGuard never modifies IAM.

If boto3 or credentials are missing we raise a clear error rather than failing
obscurely, so the offline analyzer in ``iam.py`` stays fully usable on its own.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import unquote


class AWSUnavailable(RuntimeError):
    pass


def _session(profile: str | None):
    try:
        import boto3  # noqa: WPS433 (optional dependency)
    except ImportError as exc:  # pragma: no cover - exercised only without boto3
        raise AWSUnavailable(
            "boto3 is not installed; run `pip install 'agentguard[aws]'`"
        ) from exc
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def whoami(profile: str | None = None) -> str:
    """Return the ARN of the caller's current identity."""
    ident = _session(profile).client("sts").get_caller_identity()
    return ident["Arn"]


def collect_role_policies(role_name: str, profile: str | None = None) -> list[dict[str, Any]]:
    """Fetch the inline + attached policy documents for an IAM role."""
    iam = _session(profile).client("iam")
    docs: list[dict[str, Any]] = []

    for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        resp = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        docs.append(_normalize(resp["PolicyDocument"]))

    for att in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        arn = att["PolicyArn"]
        meta = iam.get_policy(PolicyArn=arn)["Policy"]
        version = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
        docs.append(_normalize(version["PolicyVersion"]["Document"]))

    return docs


def _normalize(document: Any) -> dict[str, Any]:
    """IAM inline policy docs may arrive URL-encoded; normalize to a dict."""
    if isinstance(document, str):
        import json
        return json.loads(unquote(document))
    return document
