"""
remediations/diagnostic_logging.py

CONTROL: diagnostic_logging
MAPS TO: Week 1 misconfig `misconfig_disable_storage_logging`
MCSB:    LT-3 (Enable logging for security investigation) /
         LT-4 (Enable network logging for security investigation)
CIS Azure Benchmark: 5.1.x "Ensure diagnostic setting captures
         appropriate categories"

WHAT THIS FIXES: Re-creates a Diagnostic Setting on the target
         resource pointing at the Week 1 Log Analytics Workspace,
         capturing all available log categories and metrics. This
         is a GENERIC remediation - it works for any resource type
         that supports diagnostic settings (Storage Accounts, SQL
         servers, Key Vaults, VMs, etc.), not just storage, because
         it reads the resource's own supported categories from
         Azure at runtime instead of hardcoding a category list.

SAFE TO AUTOMATE BECAUSE: attaching a diagnostic setting is
         additive and non-destructive - it cannot break the
         resource's normal operation, only adds visibility. There
         is no plausible legitimate reason to have logging
         deliberately disabled in this lab's threat model.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.monitor.models import (
    DiagnosticSettingsResource,
    LogSettings,
    MetricSettings,
)

from shared.audit_logger import audit_scope
from shared.azure_clients import get_monitor_client
from shared.config import Settings

CONTROL_ID = "diagnostic_logging"
DIAGNOSTIC_SETTING_NAME = "diag-cloudguardian-remediated"


def remediate(
    settings: Settings,
    resource_id: str,
    dry_run: bool = False,
    finding_id: str | None = None,
    approved_by: str | None = None,
) -> dict[str, Any]:
    client = get_monitor_client(settings.subscription_id)

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        existing = list(client.diagnostic_settings.list(resource_uri=resource_id))
        already_wired = any(
            ds.workspace_id
            and ds.workspace_id.lower() == settings.log_analytics_workspace_id.lower()
            for ds in existing
        )
        detail["before"] = {"existing_diagnostic_settings": [ds.name for ds in existing]}

        if already_wired:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        # Discover which log/metric categories this resource type
        # actually supports, instead of guessing a hardcoded list
        # that might not apply (e.g. SQL categories differ from
        # Storage categories).
        categories = client.diagnostic_settings_category.list(resource_uri=resource_id)
        log_settings = [
            LogSettings(category=c.name, enabled=True)
            for c in categories.value
            if c.category_type == "Logs"
        ]
        metric_settings = [
            MetricSettings(category=c.name, enabled=True)
            for c in categories.value
            if c.category_type == "Metrics"
        ]

        if dry_run:
            detail["planned_change"] = {
                "diagnostic_setting_name": DIAGNOSTIC_SETTING_NAME,
                "log_categories": [ls.category for ls in log_settings],
                "metric_categories": [ms.category for ms in metric_settings],
                "workspace_id": settings.log_analytics_workspace_id,
            }
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        client.diagnostic_settings.create_or_update(
            resource_uri=resource_id,
            name=DIAGNOSTIC_SETTING_NAME,
            parameters=DiagnosticSettingsResource(
                workspace_id=settings.log_analytics_workspace_id,
                logs=log_settings,
                metrics=metric_settings,
            ),
        )
        detail["after"] = {"diagnostic_setting_name": DIAGNOSTIC_SETTING_NAME}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
