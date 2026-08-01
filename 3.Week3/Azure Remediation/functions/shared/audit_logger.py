"""
shared/audit_logger.py

WHAT: One function that every remediation module calls, before and
      after it acts, to emit a structured (JSON) audit record.

WHY STRUCTURED LOGGING INSTEAD OF PLAIN print()/free-text strings:
      Azure Functions' Python worker ships every `logging` call to
      Application Insights automatically (wired in function_app.tf
      via `application_insights_connection_string`), which in turn
      forwards to the Week 1 Log Analytics Workspace. By logging a
      JSON blob instead of a sentence, you can write a single KQL
      query in Log Analytics like:

          traces
          | where customDimensions.event_type == "remediation_result"
          | project timestamp, customDimensions.control_id,
                     customDimensions.outcome, customDimensions.resource_id
          | order by timestamp desc

      ...and get a live, queryable audit trail - "execution logs,
      audit trail" from the Week 3 brief - with no extra database.
      If you later wire the existing Streamlit dashboard to this
      Function App, it can read from the same Log Analytics table
      via the Log Analytics query API instead of maintaining a
      second source of truth.

WHERE THIS RUNS: called from remediation_engine.py, wrapping every
      remediation call.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Optional

logger = logging.getLogger("cloudguardian.remediation")


@dataclass
class AuditRecord:
    event_type: str
    finding_id: Optional[str]
    control_id: str
    resource_id: str
    outcome: str  # "started" | "success" | "failed" | "dry_run"
    dry_run: bool
    approved_by: Optional[str] = None
    duration_ms: Optional[float] = None
    detail: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def log(self) -> None:
        # extra={} is how Application Insights receives structured
        # "customDimensions" instead of a flat string message.
        logger.info(
            "remediation_%s control=%s resource=%s",
            self.outcome,
            self.control_id,
            self.resource_id,
            extra={"custom_dimensions": asdict(self)},
        )


@contextmanager
def audit_scope(
    control_id: str,
    resource_id: str,
    finding_id: Optional[str] = None,
    approved_by: Optional[str] = None,
    dry_run: bool = False,
) -> Iterator[dict[str, Any]]:
    """Wrap a remediation call, emitting start/success/failure audit
    records automatically and timing the call - so no remediation
    module has to remember to log correctly on every code path,
    including exceptions.
    """
    start = time.perf_counter()
    AuditRecord(
        event_type="remediation_result",
        finding_id=finding_id,
        control_id=control_id,
        resource_id=resource_id,
        outcome="dry_run" if dry_run else "started",
        dry_run=dry_run,
        approved_by=approved_by,
    ).log()

    detail: dict[str, Any] = {}
    try:
        yield detail
        AuditRecord(
            event_type="remediation_result",
            finding_id=finding_id,
            control_id=control_id,
            resource_id=resource_id,
            outcome="dry_run" if dry_run else "success",
            dry_run=dry_run,
            approved_by=approved_by,
            duration_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=detail,
        ).log()
    except Exception as exc:  # noqa: BLE001 - we re-raise after logging
        AuditRecord(
            event_type="remediation_result",
            finding_id=finding_id,
            control_id=control_id,
            resource_id=resource_id,
            outcome="failed",
            dry_run=dry_run,
            approved_by=approved_by,
            duration_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=detail,
            error=str(exc),
        ).log()
        raise
