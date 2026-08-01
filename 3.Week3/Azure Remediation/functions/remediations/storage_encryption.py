"""
remediations/storage_encryption.py

CONTROL: storage_encryption
MAPS TO: Week 1's storage tier. NOTE - Azure Storage Accounts always
         encrypt data at rest with Microsoft-managed keys; there is
         no "off switch" for encryption-at-rest itself (unlike AWS
         S3 default encryption, which historically could be absent).
         The realistic, remediable "storage encryption" misconfigs
         in Azure are secure-TRANSIT settings: whether HTTPS is
         enforced and the minimum allowed TLS version. This module
         fixes both. If your Week 1 catalogue defines this control
         differently (e.g. customer-managed keys / infrastructure
         double encryption), adjust the `StorageAccountUpdateParameters`
         call below accordingly - the pattern (get -> compare -> patch)
         stays the same.
MCSB:    DP-3 (Encrypt sensitive data in transit) / DP-4 (Enable data
         at rest encryption by default)
CIS Azure Benchmark: 3.1 "Ensure Secure transfer required is Enabled",
         3.12 "Ensure the minimum TLS version is 1.2"

SAFE TO AUTOMATE BECAUSE: enforcing HTTPS-only and TLS 1.2 cannot
         break a compliant client (any client capable of talking to
         Azure Storage already supports both); it can only break a
         client that was itself misconfigured to use plaintext HTTP
         or TLS 1.0/1.1, which is a finding in its own right.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.storage.models import StorageAccountUpdateParameters, MinimumTlsVersion

from shared.audit_logger import audit_scope
from shared.azure_clients import get_storage_client
from shared.config import Settings
from shared.resource_id import parse_resource_id

CONTROL_ID = "storage_encryption"


def remediate(
    settings: Settings,
    resource_id: str,
    dry_run: bool = False,
    finding_id: str | None = None,
    approved_by: str | None = None,
) -> dict[str, Any]:
    try:
        parsed = parse_resource_id(resource_id)
        resource_group, account_name = parsed.resource_group, parsed.resource_name
    except Exception:
        resource_group, account_name = settings.resource_group, settings.storage_account_name

    client = get_storage_client(settings.subscription_id)

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        current = client.storage_accounts.get_properties(resource_group, account_name)
        needs_https = current.enable_https_traffic_only is not True
        needs_tls = current.minimum_tls_version != MinimumTlsVersion.TLS1_2

        detail["before"] = {
            "enable_https_traffic_only": current.enable_https_traffic_only,
            "minimum_tls_version": str(current.minimum_tls_version),
        }

        if not needs_https and not needs_tls:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        if dry_run:
            detail["planned_change"] = {
                "enable_https_traffic_only": True,
                "minimum_tls_version": "TLS1_2",
            }
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        client.storage_accounts.update(
            resource_group,
            account_name,
            StorageAccountUpdateParameters(
                enable_https_traffic_only=True,
                minimum_tls_version=MinimumTlsVersion.TLS1_2,
            ),
        )
        detail["after"] = {"enable_https_traffic_only": True, "minimum_tls_version": "TLS1_2"}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
