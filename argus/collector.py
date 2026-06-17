"""
Collector — queries Cloud Asset Inventory + IAM REST API (via discovery client).
Returns raw findings (rule-based, no LLM) to feed the agent pipeline.
"""

import datetime
import logging
import os

import google.auth
from google.cloud import asset_v1
from googleapiclient import discovery

logger = logging.getLogger(__name__)

PROJECT_ID = os.environ.get("PROJECT_ID", "shri-radha-tm")
PROJECT_SCOPE = f"projects/{PROJECT_ID}"

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
STALE_KEY_DAYS = int(os.environ.get("STALE_KEY_DAYS", "90"))


async def collect() -> list[dict]:
    findings = []
    try:
        findings.extend(_iam_bindings())
    except Exception as e:
        logger.error(f"[collector] IAM bindings scan failed: {e}")
    try:
        findings.extend(_stale_keys())
    except Exception as e:
        logger.error(f"[collector] Stale keys scan failed: {e}")
    try:
        findings.extend(_database_configs())
    except Exception as e:
        logger.error(f"[collector] Database scan failed: {e}")
    logger.info(f"[collector] total raw findings: {len(findings)}")
    return findings


def _iam_bindings() -> list[dict]:
    findings = []
    client = asset_v1.AssetServiceClient()

    # Primitive roles on service accounts
    try:
        request = asset_v1.SearchAllIamPoliciesRequest(
            scope=PROJECT_SCOPE,
            query="policy:(roles/owner OR roles/editor)",
        )
        for policy in client.search_all_iam_policies(request=request):
            for binding in policy.policy.bindings:
                if binding.role not in PRIMITIVE_ROLES:
                    continue
                for member in binding.members:
                    if not member.startswith("serviceAccount:"):
                        continue
                    findings.append({
                        "category": "iam",
                        "type": "primitive_role",
                        "resource": policy.resource,
                        "member": member,
                        "role": binding.role,
                        "severity_hint": "HIGH",
                    })
    except Exception as e:
        logger.warning(f"[collector] primitive role scan: {e}")

    # Public bindings (allUsers / allAuthenticatedUsers)
    try:
        request2 = asset_v1.SearchAllIamPoliciesRequest(
            scope=PROJECT_SCOPE,
            query="policy:(allUsers OR allAuthenticatedUsers)",
        )
        for policy in client.search_all_iam_policies(request=request2):
            for binding in policy.policy.bindings:
                public = [m for m in binding.members if m in ("allUsers", "allAuthenticatedUsers")]
                if public:
                    findings.append({
                        "category": "iam",
                        "type": "public_binding",
                        "resource": policy.resource,
                        "role": binding.role,
                        "public_members": public,
                        "severity_hint": "HIGH",
                    })
    except Exception as e:
        logger.warning(f"[collector] public binding scan: {e}")

    return findings


def _stale_keys() -> list[dict]:
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc)

    credentials, _ = google.auth.default()
    iam_service = discovery.build("iam", "v1", credentials=credentials)

    try:
        sa_list = iam_service.projects().serviceAccounts().list(
            name=f"projects/{PROJECT_ID}"
        ).execute()

        for sa in sa_list.get("accounts", []):
            sa_name = sa["name"]
            sa_email = sa["email"]

            keys_response = iam_service.projects().serviceAccounts().keys().list(
                name=sa_name, keyTypes=["USER_MANAGED"]
            ).execute()

            for key in keys_response.get("keys", []):
                valid_after_str = key.get("validAfterTime", "")
                if not valid_after_str:
                    continue
                valid_after = datetime.datetime.fromisoformat(
                    valid_after_str.replace("Z", "+00:00")
                )
                age_days = (now - valid_after).days
                if age_days > STALE_KEY_DAYS:
                    findings.append({
                        "category": "iam",
                        "type": "stale_key",
                        "resource": sa_email,
                        "key_id": key["name"].split("/")[-1],
                        "age_days": age_days,
                        "severity_hint": "MEDIUM",
                    })
    except Exception as e:
        logger.warning(f"[collector] stale key scan: {e}")

    return findings


def _database_configs() -> list[dict]:
    findings = []
    client = asset_v1.AssetServiceClient()

    try:
        request = asset_v1.SearchAllResourcesRequest(
            scope=PROJECT_SCOPE,
            asset_types=["sqladmin.googleapis.com/Instance"],
        )
        for resource in client.search_all_resources(request=request):
            attrs = dict(resource.additional_attributes) if resource.additional_attributes else {}
            name = resource.name or resource.display_name

            if attrs.get("ipAddresses"):
                findings.append({
                    "category": "database",
                    "type": "public_ip",
                    "resource": name,
                    "display_name": resource.display_name,
                    "severity_hint": "HIGH",
                })

            if not attrs.get("requireSsl", False):
                findings.append({
                    "category": "database",
                    "type": "ssl_not_required",
                    "resource": name,
                    "display_name": resource.display_name,
                    "severity_hint": "HIGH",
                })

            auth_nets = attrs.get("authorizedNetworks", [])
            if any(n.get("value") == "0.0.0.0/0" for n in auth_nets if isinstance(n, dict)):
                findings.append({
                    "category": "database",
                    "type": "open_authorized_network",
                    "resource": name,
                    "display_name": resource.display_name,
                    "severity_hint": "HIGH",
                })

            if not attrs.get("backupEnabled", True):
                findings.append({
                    "category": "database",
                    "type": "backups_disabled",
                    "resource": name,
                    "display_name": resource.display_name,
                    "severity_hint": "MEDIUM",
                })
    except Exception as e:
        logger.warning(f"[collector] database scan: {e}")

    return findings
