"""
remediations/keyvault_firewall.py

CONTROL: keyvault_firewall
MAPS TO: Week 1's Key Vault. A Key Vault with network ACLs
         `default_action = Allow` accepts requests from any IP on
         the internet, relying only on Azure AD auth (RBAC/access
         policy) as its sole line of defense - defense-in-depth
         says the network boundary should ALSO deny by default.
MCSB:    NS-2 (Secure cloud services with network controls) /
         DP-8 (Ensure security of key and certificate repository)
CIS Azure Benchmark: 8.4 "Ensure that Key Vault is recoverable" /
         8.x network ACL guidance

WHAT THIS FIXES: Sets `default_action = Deny` and explicitly allows
         `AzureServices` to bypass (so trusted first-party Azure
         services - like this very Function App's own Managed
         Identity calls, and Azure Backup, etc. - keep working)
         plus any IP ranges passed in `allowed_ip_ranges`.

WHY THIS ONE HAS A GUARDRAIL THE OTHERS DON'T: unlike the other 5
         controls, tightening a Key Vault firewall CAN break a
         legitimate caller if that caller's IP isn't in the allow
         list yet. This module is intentionally the most cautious:
         it defaults to `bypass=AzureServices` (which is what lets
         Functions/Automation Account/Portal admin calls keep
         working) and requires you to pass known-good IP ranges
         explicitly rather than guessing them.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.keyvault.models import (
    VaultPatchParameters,
    VaultPatchProperties,
    NetworkRuleSet,
    NetworkRuleBypassOptions,
    NetworkRuleAction,
    IPRule,
)

from shared.audit_logger import audit_scope
from shared.azure_clients import get_keyvault_client
from shared.config import Settings
from shared.resource_id import parse_resource_id

CONTROL_ID = "keyvault_firewall"


def remediate(
    settings: Settings,
    resource_id: str,
    dry_run: bool = False,
    finding_id: str | None = None,
    approved_by: str | None = None,
    allowed_ip_ranges: list[str] | None = None,
) -> dict[str, Any]:
    try:
        parsed = parse_resource_id(resource_id)
        resource_group, vault_name = parsed.resource_group, parsed.resource_name
    except Exception:
        resource_group, vault_name = settings.resource_group, settings.key_vault_name

    client = get_keyvault_client(settings.subscription_id)
    allowed_ip_ranges = allowed_ip_ranges or []

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        current = client.vaults.get(resource_group, vault_name)
        current_default = current.properties.network_acls.default_action if current.properties.network_acls else None
        detail["before"] = {"default_action": str(current_default)}

        if current_default == NetworkRuleAction.DENY:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        if dry_run:
            detail["planned_change"] = {
                "default_action": "Deny",
                "bypass": "AzureServices",
                "ip_rules": allowed_ip_ranges,
            }
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        client.vaults.update(
            resource_group,
            vault_name,
            VaultPatchParameters(
                properties=VaultPatchProperties(
                    network_acls=NetworkRuleSet(
                        default_action=NetworkRuleAction.DENY,
                        bypass=NetworkRuleBypassOptions.AZURE_SERVICES,
                        ip_rules=[IPRule(value=ip) for ip in allowed_ip_ranges],
                    )
                )
            ),
        )
        detail["after"] = {"default_action": "Deny", "ip_rules": allowed_ip_ranges}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
