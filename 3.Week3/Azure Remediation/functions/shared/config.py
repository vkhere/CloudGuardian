"""
shared/config.py

WHAT: Single place that reads every environment variable this
      Function App needs, with type hints and fail-fast validation.

WHY:  The coding standard for this project bans hardcoded values.
      Every target resource name comes from Terraform's app_settings
      (see function_app.tf) so the SAME code works for your lab
      subscription and a teammate's, or a future prod subscription,
      with zero code changes - only different Terraform variable
      values.

WHERE THIS RUNS: imported by function_app.py and every module in
      remediations/. Never edit this file to add a resource name -
      add it as a Terraform app_setting instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when a required environment variable is missing."""


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"Required environment variable '{name}' is not set. "
            f"Check the Function App's Application Settings in the "
            f"Portal or your local.settings.json."
        )
    return value


@dataclass(frozen=True)
class Settings:
    subscription_id: str
    resource_group: str
    storage_account_name: str
    sql_server_name: str
    sql_database_name: str
    key_vault_name: str
    log_analytics_workspace_id: str
    dry_run_default: bool
    # Approval-gate / ACS Email settings (see acs_email.tf and
    # shared/notifications.py). Not needed by the 6 remediation
    # modules themselves - only by request_approval/approval_decision
    # in function_app.py - but loaded here too so there is still only
    # ONE place in the codebase that reads os.environ.
    acs_endpoint: str
    acs_sender_address: str
    approver_email: str
    callback_shared_secret: str


def load_settings() -> Settings:
    """Read and validate all required configuration once per invocation.

    Deliberately NOT cached at module import time: Azure Functions can
    reuse a "warm" Python process across invocations, and reading fresh
    each call keeps local testing (where you might swap
    local.settings.json between calls) predictable.
    """
    return Settings(
        subscription_id=_require("TARGET_SUBSCRIPTION_ID"),
        resource_group=_require("TARGET_RESOURCE_GROUP"),
        storage_account_name=_require("TARGET_STORAGE_ACCOUNT_NAME"),
        sql_server_name=_require("TARGET_SQL_SERVER_NAME"),
        sql_database_name=_require("TARGET_SQL_DATABASE_NAME"),
        key_vault_name=_require("TARGET_KEY_VAULT_NAME"),
        log_analytics_workspace_id=_require("LOG_ANALYTICS_WORKSPACE_ID"),
        dry_run_default=os.environ.get("DRY_RUN_DEFAULT", "false").lower() == "true",
        acs_endpoint=_require("ACS_ENDPOINT"),
        acs_sender_address=_require("ACS_SENDER_ADDRESS"),
        approver_email=_require("APPROVER_EMAIL"),
        callback_shared_secret=_require("CALLBACK_SHARED_SECRET"),
    )
