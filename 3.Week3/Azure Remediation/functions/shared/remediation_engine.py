"""
shared/remediation_engine.py

WHAT: The single dispatcher both entry points (the HTTP-triggered
      post-approval function AND the Event-Grid-triggered
      auto-remediate function) call into. One registry, one place
      that knows "remediation_type string -> which module runs."

WHY A SHARED DISPATCHER INSTEAD OF DUPLICATING THE LOOKUP IN BOTH
TRIGGERS: the two entry points differ only in HOW a remediation gets
      authorized (human approval vs. auto for low/medium severity) -
      not in HOW a remediation executes. Keeping execution logic in
      exactly one place means a bug fix or a 7th control added later
      only has to happen once, and both paths stay behaviorally
      identical (same audit format, same dry-run support, same
      error handling).

WHERE THIS RUNS: imported by function_app.py.
"""

from __future__ import annotations

from typing import Any, Callable

from shared.config import Settings, load_settings
from remediations import (
    storage_public_access,
    storage_encryption,
    diagnostic_logging,
    sql_encryption,
    keyvault_firewall,
    tagging,
)

RemediationFn = Callable[..., dict[str, Any]]

REMEDIATION_REGISTRY: dict[str, RemediationFn] = {
    storage_public_access.CONTROL_ID: storage_public_access.remediate,
    storage_encryption.CONTROL_ID: storage_encryption.remediate,
    diagnostic_logging.CONTROL_ID: diagnostic_logging.remediate,
    sql_encryption.CONTROL_ID: sql_encryption.remediate,
    keyvault_firewall.CONTROL_ID: keyvault_firewall.remediate,
    tagging.CONTROL_ID: tagging.remediate,
}


class UnknownRemediationTypeError(ValueError):
    pass


def execute(
    remediation_type: str,
    resource_id: str,
    finding_id: str | None = None,
    approved_by: str | None = None,
    dry_run: bool | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Look up and run the remediation function for `remediation_type`.

    `dry_run=None` means "use the Function App's DRY_RUN_DEFAULT
    setting" - this is what makes it safe to deploy this whole engine
    with dry-run ON by default in a new environment, prove it does
    the right thing by inspecting `detail.planned_change` in the
    logs, and only flip DRY_RUN_DEFAULT to false once you trust it.
    """
    settings = settings or load_settings()
    if dry_run is None:
        dry_run = settings.dry_run_default

    fn = REMEDIATION_REGISTRY.get(remediation_type)
    if fn is None:
        raise UnknownRemediationTypeError(
            f"'{remediation_type}' is not a registered remediation. "
            f"Known types: {sorted(REMEDIATION_REGISTRY)}"
        )

    return fn(
        settings=settings,
        resource_id=resource_id,
        dry_run=dry_run,
        finding_id=finding_id,
        approved_by=approved_by,
    )
