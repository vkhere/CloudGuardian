"""
shared/azure_clients.py

WHAT: Thin factory functions that build authenticated Azure SDK
      management clients using DefaultAzureCredential.

WHY DefaultAzureCredential AND NOT A SERVICE PRINCIPAL SECRET:
      DefaultAzureCredential tries a chain of auth methods in order
      (environment variables, Managed Identity, Azure CLI, VS Code,
      etc.) and uses the first one that works. In Azure, the
      Function App's System-Assigned Managed Identity is picked up
      automatically - zero configuration, zero secrets. On your
      laptop during local testing, it falls back to your `az login`
      session automatically. Same code, two environments, no
      hardcoded credential either way - this is the Zero Trust /
      Well-Architected "no static secrets" pattern.

WHERE THIS RUNS: imported by every remediation module.
"""

from __future__ import annotations

from functools import lru_cache

from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient


@lru_cache(maxsize=1)
def get_credential() -> DefaultAzureCredential:
    """One credential object, reused across a warm Function instance.

    Token acquisition has real latency - caching the credential (not
    the token; the SDK handles token caching/refresh internally) avoids
    re-negotiating the auth chain on every single remediation call.
    """
    return DefaultAzureCredential(
        exclude_interactive_browser_credential=True,  # never prompt a human in a Function
    )


def get_storage_client(subscription_id: str) -> StorageManagementClient:
    return StorageManagementClient(get_credential(), subscription_id)


def get_sql_client(subscription_id: str) -> SqlManagementClient:
    return SqlManagementClient(get_credential(), subscription_id)


def get_keyvault_client(subscription_id: str) -> KeyVaultManagementClient:
    return KeyVaultManagementClient(get_credential(), subscription_id)


def get_monitor_client(subscription_id: str) -> MonitorManagementClient:
    return MonitorManagementClient(get_credential(), subscription_id)


def get_resource_client(subscription_id: str) -> ResourceManagementClient:
    return ResourceManagementClient(get_credential(), subscription_id)
