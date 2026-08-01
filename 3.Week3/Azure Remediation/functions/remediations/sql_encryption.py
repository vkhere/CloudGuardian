"""
remediations/sql_encryption.py

CONTROL: sql_encryption
MAPS TO: Week 1's database.tf tier (TDE). Per your own Week 1
         discovery notes: Transparent Data Encryption in Azure is
         NOT a separate resource (there is no
         `azurerm_mssql_database_transparent_data_encryption`
         resource type in current AzureRM provider versions) - it
         is a state attribute reachable through the
         `transparent_data_encryptions` operation group on the
         database. This module uses the same SDK-level operation
         Terraform itself uses under the hood.
MCSB:    DP-4 (Enable data at rest encryption by default)
CIS Azure Benchmark: 4.1.1 "Ensure Transparent Data Encryption is
         enabled"

SAFE TO AUTOMATE BECAUSE: enabling TDE is transparent to
         applications (the "T" in TDE) - no connection string,
         query, or client code changes. Microsoft enables TDE by
         default on new databases specifically because it's safe
         to always have on; a database with it explicitly disabled
         is virtually always a misconfiguration, not an intentional
         choice.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.sql.models import TransparentDataEncryption, TransparentDataEncryptionState

from shared.audit_logger import audit_scope
from shared.azure_clients import get_sql_client
from shared.config import Settings
from shared.resource_id import parse_resource_id

CONTROL_ID = "sql_encryption"


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
        server_name = parsed.resource_name
        database_name = parsed.child_name or settings.sql_database_name
    except Exception:
        resource_group = settings.resource_group
        server_name = settings.sql_server_name
        database_name = settings.sql_database_name

    client = get_sql_client(settings.subscription_id)

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        current = client.transparent_data_encryptions.get(
            resource_group_name=resource_group,
            server_name=server_name,
            database_name=database_name,
            # NOTE: the azure-mgmt-sql SDK's real keyword here is
            # transparent_data_encryption_name, not the shorter
            # tde_name an earlier draft of this module assumed.
            # Passing the wrong keyword doesn't raise "unexpected
            # keyword argument" because the SDK client absorbs
            # unrecognized kwargs - it instead surfaces as this
            # required positional argument appearing "missing".
            transparent_data_encryption_name="current",
        )
        # NOTE #2: the installed SDK's TransparentDataEncryption model
        # exposes the on/off flag as `.status`, not `.state` - confirmed
        # by introspecting the real model's _attribute_map on this
        # machine (['id', 'name', 'type', 'location', 'status']). An
        # earlier draft of this module assumed `.state` by analogy with
        # the TransparentDataEncryptionState enum's name, but the model
        # attribute and the enum type name are two different things.
        # The enum VALUES themselves (TransparentDataEncryptionState.ENABLED)
        # are unaffected - only which model attribute holds that value.
        detail["before"] = {"status": str(current.status)}

        if current.status == TransparentDataEncryptionState.ENABLED:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        if dry_run:
            detail["planned_change"] = {"status": "Enabled"}
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        poller = client.transparent_data_encryptions.begin_create_or_update(
            resource_group_name=resource_group,
            server_name=server_name,
            database_name=database_name,
            transparent_data_encryption_name="current",
            parameters=TransparentDataEncryption(status=TransparentDataEncryptionState.ENABLED),
        )
        result = poller.result()
        detail["after"] = {"status": str(result.status)}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
