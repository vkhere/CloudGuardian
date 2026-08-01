"""
function_app.py

WHAT: The entry points into the remediation engine and the human
      approval gate, using the Azure Functions Python v2
      (decorator-based) programming model.

  1. execute_remediation  - HTTP trigger, function-key protected.
     Callable directly (curl/Postman, for testing and your demo)
     and internally by approval_decision after a human approves.

  2. auto_remediate       - Event Grid trigger. Called directly by
     the Event Grid subscription for Low/Medium findings that skip
     human approval entirely (see event_grid.tf's advanced filter).

  3. request_approval     - HTTP trigger, function-key protected.
     Called by the Logic App (see logic_app.tf) when Event Grid
     routes a High/Critical finding here. Sends the Approve/Reject
     email via Azure Communication Services (shared/notifications.py)
     and returns immediately - it does NOT wait for the click.

  4. approval_decision    - HTTP trigger, ANONYMOUS at the platform
     level (see shared/notifications.py for exactly why), reached
     when a human clicks Approve or Reject in that email. Validates
     a shared secret, then either calls the same dispatcher
     execute_remediation() uses, or just records a rejection -
     returning a small HTML confirmation page either way.

WHY FOUR ENTRY POINTS INTO ONE DISPATCHER: see shared/remediation_engine.py
      for why execution logic lives in exactly one place. This file
      is deliberately thin - it only translates "how did this call
      arrive" (HTTP body, Event Grid event, or query string) into the
      dispatcher's arguments, then translates the result back into an
      HTTP response (or an HTML page, for the one endpoint a human
      browser actually hits).

WHERE THIS RUNS: this IS the Function App's entry point - Azure
      discovers every @app.route / @app.event_grid_trigger
      decorated function in this file automatically at startup
      (AzureWebJobsFeatureFlags=EnableWorkerIndexing in function_app.tf
      is what turns this discovery on).

HOW TO RUN LOCALLY: func start from this folder, after
      pip install -r requirements.txt and copying
      local.settings.json.example to local.settings.json with your
      own values. See the setup guide for the full walkthrough.
"""

from __future__ import annotations

import json
import logging

import azure.functions as func

from shared.remediation_engine import execute, UnknownRemediationTypeError
from shared.config import ConfigError, load_settings
from shared.audit_logger import AuditRecord
from shared.notifications import (
    is_valid_secret,
    send_approval_request_email,
    send_decision_confirmation_email,
)

app = func.FunctionApp()
logger = logging.getLogger("cloudguardian.function_app")


@app.route(route="execute-remediation", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def execute_remediation(req: func.HttpRequest) -> func.HttpResponse:
    """POST body (sent manually for testing/demo, or internally by
    approval_decision below after a human approves):

        {
          "finding_id": "...",
          "control_id": "storage_public_access",
          "remediation_type": "storage_public_access",
          "resource_id": "/subscriptions/.../storageAccounts/stxxx",
          "approved_by": "alice@yourdomain.com",
          "approved_at": "2026-07-11T02:00:00Z",
          "dry_run": false
        }
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Request body must be valid JSON."}),
            status_code=400,
            mimetype="application/json",
        )

    remediation_type = body.get("remediation_type") or body.get("control_id")
    resource_id = body.get("resource_id")

    if not remediation_type or not resource_id:
        return func.HttpResponse(
            json.dumps({"error": "'remediation_type' (or 'control_id') and 'resource_id' are required."}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        result = execute(
            remediation_type=remediation_type,
            resource_id=resource_id,
            finding_id=body.get("finding_id"),
            approved_by=body.get("approved_by"),
            dry_run=body.get("dry_run"),  # None -> falls back to DRY_RUN_DEFAULT
        )
        return func.HttpResponse(json.dumps(result), status_code=200, mimetype="application/json")

    except UnknownRemediationTypeError as exc:
        return func.HttpResponse(json.dumps({"error": str(exc)}), status_code=400, mimetype="application/json")
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return func.HttpResponse(json.dumps({"error": "Server misconfigured."}), status_code=500, mimetype="application/json")
    except Exception as exc:  # noqa: BLE001 - deliberately broad: never leak a raw 500 stack trace externally
        logger.exception("Unhandled error executing remediation")
        return func.HttpResponse(
            json.dumps({"error": "Remediation failed. See Application Insights traces for detail.", "reference": str(exc)[:200]}),
            status_code=500,
            mimetype="application/json",
        )


@app.event_grid_trigger(arg_name="event")
def auto_remediate(event: func.EventGridEvent) -> None:
    """Triggered directly by Event Grid for Low/Medium severity
    findings (see event_grid.tf's auto_remediate subscription,
    which advanced-filters on data.severity). No human approval
    in this path BY DESIGN - only low-risk, fully reversible,
    idempotent controls should ever be routed here. If you add a
    7th remediation later, decide deliberately whether it belongs
    in the auto path or the approval-required path; don't assume.
    """
    data = event.get_json()
    logger.info(
        "Auto-remediate triggered: severity=%s control=%s resource=%s",
        data.get("severity"),
        data.get("remediation_type"),
        data.get("resource_id"),
    )

    try:
        execute(
            remediation_type=data.get("remediation_type") or data.get("control_id"),
            resource_id=data["resource_id"],
            finding_id=data.get("finding_id"),
            approved_by="auto-remediation-engine",
            dry_run=data.get("dry_run"),
        )
    except Exception:
        # Event Grid retries on unhandled exceptions per the retry
        # policy in event_grid.tf (5 attempts / 60 min TTL) - log
        # and re-raise so that retry behavior actually kicks in
        # instead of silently swallowing a transient Azure API error.
        logger.exception("Auto-remediation failed for event id=%s", event.id)
        raise


@app.route(route="request-approval", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def request_approval(req: func.HttpRequest) -> func.HttpResponse:
    """Called by the Logic App (logic_app.tf) for High/Critical
    findings. Body is the raw Event Grid array Event Grid itself
    posted, forwarded through unchanged - so this endpoint, not the
    Logic App, is the one place that knows the finding's shape.

    Sends the approval email and returns immediately (HTTP 202) -
    the actual approve/reject decision arrives later, asynchronously,
    at approval_decision below, whenever a human clicks a link.
    """
    try:
        events = req.get_json()
        finding = events[0]["data"] if isinstance(events, list) else events.get("data", events)
    except (ValueError, IndexError, KeyError, TypeError):
        return func.HttpResponse(
            json.dumps({"error": "Expected an Event Grid-shaped array with a 'data' object."}),
            status_code=400,
            mimetype="application/json",
        )

    settings = load_settings()
    function_base_url = f"https://{req.url.split('/')[2]}"

    AuditRecord(
        event_type="approval_requested",
        finding_id=finding.get("finding_id"),
        control_id=finding.get("control_id", "unknown"),
        resource_id=finding.get("resource_id", "unknown"),
        outcome="started",
        dry_run=False,
    ).log()

    try:
        send_approval_request_email(settings, finding, function_base_url)
    except Exception:
        logger.exception("Failed to send approval-request email for finding_id=%s", finding.get("finding_id"))
        return func.HttpResponse(
            json.dumps({"error": "Failed to send approval email. See Application Insights traces."}),
            status_code=500,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps({"status": "approval_email_sent", "finding_id": finding.get("finding_id")}),
        status_code=202,
        mimetype="application/json",
    )


def _html_response(title: str, message: str, ok: bool) -> func.HttpResponse:
    color = "#1E2761" if ok else "#B8324A"
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head>
    <body style="font-family:Arial,sans-serif;max-width:520px;margin:80px auto;text-align:center;">
      <h2 style="color:{color};">{title}</h2>
      <p style="color:#444;">{message}</p>
    </body></html>"""
    return func.HttpResponse(html, status_code=200 if ok else 403, mimetype="text/html")


@app.route(route="approval-decision", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def approval_decision(req: func.HttpRequest) -> func.HttpResponse:
    """Reached when a human clicks Approve or Reject inside the
    email request_approval sent. ANONYMOUS at the Functions-platform
    level BY DESIGN - see the big docstring at the top of
    shared/notifications.py for exactly why, and for the known
    limitation of a GET-triggered approval link (email security
    scanners pre-fetching links). This endpoint's own
    is_valid_secret() check is what actually protects it.

    FUTURE WORK (flagged, not implemented, to keep this a lab-
    appropriate scope): return an intermediate HTML confirmation
    page with its own "Yes, really approve" button that fires a
    second, POST-based call - closes the pre-fetch gap entirely.
    """
    params = req.params
    decision = (params.get("decision") or "").lower()
    finding = {
        "finding_id": params.get("finding_id", ""),
        "control_id": params.get("control_id", ""),
        "remediation_type": params.get("remediation_type", params.get("control_id", "")),
        "resource_id": params.get("resource_id", ""),
    }
    provided_secret = params.get("secret", "")

    settings = load_settings()

    if not is_valid_secret(provided_secret, settings.callback_shared_secret):
        logger.warning("approval_decision called with an invalid/missing secret for finding_id=%s", finding["finding_id"])
        return _html_response("Link not valid", "This approval link is invalid or has expired.", ok=False)

    if decision not in ("approve", "reject"):
        return _html_response("Invalid request", "This link is missing a valid decision.", ok=False)

    if decision == "reject":
        AuditRecord(
            event_type="approval_decision",
            finding_id=finding["finding_id"],
            control_id=finding["control_id"],
            resource_id=finding["resource_id"],
            outcome="rejected",
            dry_run=False,
        ).log()
        try:
            send_decision_confirmation_email(settings, finding, "reject", None)
        except Exception:
            logger.exception("Failed to send rejection confirmation email")
        return _html_response("Rejected", "No changes were made. This decision has been recorded in the audit log.", ok=True)

    # decision == "approve"
    try:
        result = execute(
            remediation_type=finding["remediation_type"],
            resource_id=finding["resource_id"],
            finding_id=finding["finding_id"],
            approved_by=settings.approver_email,
            dry_run=None,  # falls back to DRY_RUN_DEFAULT
        )
    except Exception as exc:
        logger.exception("Remediation failed after approval for finding_id=%s", finding["finding_id"])
        return _html_response("Approved, but remediation failed", f"The approval was recorded, but the remediation itself failed: {str(exc)[:200]}. See Application Insights.", ok=False)

    try:
        send_decision_confirmation_email(settings, finding, "approve", result)
    except Exception:
        logger.exception("Failed to send approval confirmation email")

    return _html_response("Approved and remediated", f"Result: {result.get('status', 'unknown')}. A confirmation email has been sent.", ok=True)
