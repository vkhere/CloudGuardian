"""
remediations/storage_public_access.py

CONTROL: storage_public_access
MAPS TO: Week 1 misconfig `misconfig_storage_public_container` /
         `misconfig_storage_allow_public_network_access`
MCSB:    DP-2 (Discover, classify, protect sensitive data) /
         NS-2 (Secure cloud services with network controls)
CIS Azure Benchmark: 3.1 "Ensure Secure transfer required is Enabled"
                     family; 3.6 "Ensure default network access rule
                     for Storage Accounts is Deny"

WHAT THIS FIXES: Sets `allow_blob_public_access = False` on the
                  target Storage Account, which is the account-level
                  switch that governs whether ANY container can be
                  made anonymously readable, regardless of that
                  container's own access level.

WHY ACCOUNT-LEVEL AND NOT PER-CONTAINER: The account-level flag is a
                  hard override - if it's False, no container can be
                  public even if someone flips an individual
                  container's access level later. Fixing it here
                  closes the misconfiguration at its root cause
                  rather than chasing every container.

SAFE TO AUTOMATE BECAUSE: this is a boolean toggle with no data loss
                  risk, is fully idempotent (calling it twice is a
                  no-op the second time), and is trivially reversible
                  by flipping the Terraform variable back in Week 1's
                  stack if it ever needs to be false for a legitimate
                  reason (e.g. a public static website container).
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.storage.models import StorageAccountUpdateParameters

from shared.audit_logger import audit_scope
from shared.azure_clients import get_storage_client
from shared.config import Settings
from shared.resource_id import parse_resource_id

CONTROL_ID = "storage_public_access"


def remediate(
    settings: Settings,
    resource_id: str,
    dry_run: bool = False,
    finding_id: str | None = None,
    approved_by: str | None = None,
) -> dict[str, Any]:
    try:
        parsed = parse_resource_id(resource_id)
        resource_group = parsed.resource_group
        account_name = parsed.resource_name
    except Exception:
        # Fall back to the single lab target if the finding didn't
        # carry a fully-formed resource ID (e.g. a manual demo call).
        resource_group = settings.resource_group
        account_name = settings.storage_account_name

    client = get_storage_client(settings.subscription_id)

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        current = client.storage_accounts.get_properties(resource_group, account_name)
        detail["before"] = {"allow_blob_public_access": current.allow_blob_public_access}

        if current.allow_blob_public_access is False:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        if dry_run:
            detail["planned_change"] = {"allow_blob_public_access": False}
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        client.storage_accounts.update(
            resource_group,
            account_name,
            StorageAccountUpdateParameters(allow_blob_public_access=False),
        )
        detail["after"] = {"allow_blob_public_access": False}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
