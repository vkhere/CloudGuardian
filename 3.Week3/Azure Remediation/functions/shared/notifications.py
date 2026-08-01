"""
shared/notifications.py

WHAT: Everything about sending the approval-request email and the
      approve/reject confirmation email, plus building the two
      links the email contains, and validating the shared secret
      those links carry.

WHY THIS LIVES IN THE FUNCTION APP AND NOT THE LOGIC APP:
      The original design tried to send this email from inside the
      Logic App itself, using the Office 365 Outlook connector's
      built-in "Send approval email" action. That action needs a
      real Microsoft 365 mailbox and a one-time manual OAuth click
      Terraform can't perform. Moving email-sending here instead
      means: (1) authentication is the Function App's existing
      Managed Identity via Microsoft Entra ID - no mailbox, no
      OAuth, no connection string; (2) the Approve/Reject decision
      logic lives in ordinary, testable Python instead of a Logic
      App If/Else action a reviewer has to open the Designer to
      read; (3) the Logic App itself stays a one-line HTTP hop
      (see logic_app.tf), which is all native azurerm HCL can
      express without the azapi provider.

WHY THE CALLBACK LINKS CARRY A SHARED SECRET, NOT JUST A FUNCTION KEY:
      Two separate concerns, two separate mechanisms:
      - `request_approval` (called only by the Logic App, never by
        a human) is protected by an ordinary Azure Functions host
        key (`?code=...`), exactly like `execute_remediation`.
      - `approval_decision` (clicked by a HUMAN from inside an email
        client) is `AuthLevel.ANONYMOUS` at the Functions-platform
        level, and instead checks `CALLBACK_SHARED_SECRET` itself in
        code. This is deliberate, not an oversight: some corporate
        email-security gateways "pre-fetch" every link in an inbound
        email to scan it for phishing BEFORE a human ever clicks
        anything. If that GET request carried a working Functions
        host key, a security scanner could accidentally trigger a
        real approval. Using a plain string comparison against an
        app-setting value the Function reads about itself means the
        SAME protection is in force, but it's fully under this
        code's control - e.g. you could extend `is_valid_secret` to
        also reject a link after first use, or after N hours,
        without touching anything at the Functions-platform/Terraform
        layer at all.

KNOWN LIMITATION TO STATE PLAINLY IN YOUR REPORT: even with the
      shared secret, a GET-based approval link is still weaker than
      a proper "confirm this action" POST flow, because email
      security scanners rewriting/pre-fetching links is a known,
      widespread phenomenon (Microsoft Defender for Office 365 and
      similar products do this by design). For a student lab this
      is an acceptable, clearly-documented trade-off. A production
      system should have `approval_decision` return an HTML
      confirmation PAGE with its own "Yes, I really approve this"
      button that fires the actual state-changing POST - i.e. two
      hops instead of one. That upgrade is a natural "future work"
      item; the code below is structured so it's a small addition,
      not a rewrite (see the TODO in `approval_decision`'s docstring
      in function_app.py).

WHERE THIS RUNS: imported by function_app.py's `request_approval`
      and `approval_decision` endpoints.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any
from urllib.parse import urlencode

from azure.communication.email import EmailClient

from shared.azure_clients import get_credential
from shared.config import Settings
from shared.resource_id import parse_resource_id

logger = logging.getLogger("cloudguardian.notifications")

# WHY THIS DICT EXISTS: the raw finding only carries a control_id and
# an ARM resource_id - both accurate, neither readable by a human
# deciding whether to click Approve at 11pm on a phone. Each of the
# six remediation modules already documents its issue/risk/fix in its
# own docstring (see functions/remediations/*.py) - this dict restates
# that same information in one place so the email can quote it without
# importing every remediation module just to read a comment. If you
# add a 7th control, add its entry here too; unknown control_ids fall
# back to _DEFAULT_CONTROL_METADATA rather than raising.
CONTROL_METADATA: dict[str, dict[str, str]] = {
    "storage_public_access": {
        "issue": "The storage account allows public (anonymous) blob access at the account level, so any container can be made internet-readable.",
        "risk": "Anyone on the internet can read blob data if a container's access level is set to Blob/Container - a common cause of accidental data exposure.",
        "change": "Sets allow_blob_public_access = False on the storage account. Authenticated access (keys, SAS, Azure AD) is unaffected. Fully reversible.",
    },
    "storage_encryption": {
        "issue": "The storage account permits plain HTTP connections and/or a TLS version below 1.2 for data in transit.",
        "risk": "Traffic to/from this account could be intercepted or downgraded to a weaker, breakable protocol on the wire.",
        "change": "Enforces HTTPS-only traffic and sets the minimum TLS version to 1.2. Only affects clients that are themselves still using HTTP or old TLS.",
    },
    "diagnostic_logging": {
        "issue": "No Diagnostic Setting is forwarding this resource's logs and metrics to the Log Analytics Workspace.",
        "risk": "Security-relevant activity on this resource isn't being captured - a blind spot for incident investigation and compliance audits.",
        "change": "Re-attaches a Diagnostic Setting sending all available log categories and metrics to the existing Log Analytics Workspace. Purely additive - no impact to the resource's normal operation.",
    },
    "sql_encryption": {
        "issue": "Transparent Data Encryption (TDE) is currently disabled on this SQL database.",
        "risk": "Data at rest (backups, replicas, disk-level exports) is unencrypted - readable by anyone who ever obtained the underlying storage media.",
        "change": "Enables TDE on the database. Transparent to applications - no downtime, no connection string or client code changes.",
    },
    "keyvault_firewall": {
        "issue": "The Key Vault's network ACL default action is Allow, accepting requests from any IP address on the internet.",
        "risk": "Only Azure AD authentication stands between this vault's secrets/keys/certificates and the public internet - there is no network-layer boundary.",
        "change": "Sets default_action = Deny with an AzureServices bypass (keeps this Function App, Azure Backup, and other first-party Azure callers working). Any other legitimate caller not yet on the allow-list will need an explicit IP rule added afterward.",
    },
    "tagging": {
        "issue": "One or more required governance tags (Environment, Owner, DataClassification, CostCenter) are missing on this resource.",
        "risk": "Missing tags break cost allocation, ownership tracking, and any automated governance policy that is keyed off tags.",
        "change": "Merges only the missing required tags onto the resource. Existing tags already set by a human (e.g. Project=CloudGuardian) are preserved, never overwritten.",
    },
}

_DEFAULT_CONTROL_METADATA = {
    "issue": "See the finding detail captured by the Week 2 CSPM pipeline for the specific condition detected.",
    "risk": "Risk detail is not pre-authored for this control - refer to the CSPM finding record and its CVSS/exposure score.",
    "change": "The remediation function registered for this control_id will run automatically once approved.",
}


def _control_metadata(control_id: str) -> dict[str, str]:
    return CONTROL_METADATA.get(control_id, _DEFAULT_CONTROL_METADATA)


def _friendly_resource_label(resource_id: str) -> str:
    """Turn a raw ARM resource ID into a short, human CI reference,
    e.g. "servers 'sql-cloudguardian-lab-abc12' / databases 'appdb'
    (resource group: rg-cloudguardian-lab)" instead of the full
    /subscriptions/.../providers/... string. Falls back to the raw
    ID if it doesn't parse (e.g. a malformed or test resource_id) -
    this is a display helper only, never the value actually acted on.
    """
    try:
        parsed = parse_resource_id(resource_id)
    except Exception:
        return resource_id or "n/a"
    label = f"{parsed.resource_type} '{parsed.resource_name}'"
    if parsed.child_name:
        label += f" / {parsed.child_type} '{parsed.child_name}'"
    label += f" (resource group: {parsed.resource_group})"
    return label


def _email_client(settings: Settings) -> EmailClient:
    # Same DefaultAzureCredential pattern as every Azure SDK client
    # in this project (see shared/azure_clients.py) - Managed Identity
    # in Azure, your `az login` session locally, no branching.
    return EmailClient(settings.acs_endpoint, get_credential())


def build_decision_url(
    base_url: str,
    decision: str,
    finding_id: str,
    control_id: str,
    remediation_type: str,
    resource_id: str,
    shared_secret: str,
) -> str:
    """Build one Approve or Reject link for the approval email.

    `base_url` is the Function App's own hostname (the Function
    builds a link pointing back at itself) - passed in rather than
    read from an env var here, so this function stays a pure,
    easily-unit-tested string builder.
    """
    query = urlencode({
        "decision": decision,
        "finding_id": finding_id,
        "control_id": control_id,
        "remediation_type": remediation_type,
        "resource_id": resource_id,
        "secret": shared_secret,
    })
    return f"{base_url}/api/approval-decision?{query}"


def is_valid_secret(provided: str, expected: str) -> bool:
    """Constant-time comparison - an ordinary `==` leaks timing
    information an attacker could in theory use to guess the secret
    one byte at a time. `hmac.compare_digest` is the standard library's
    answer to exactly this, and costs nothing extra to use correctly.
    """
    return hmac.compare_digest(provided or "", expected or "")


def send_approval_request_email(settings: Settings, finding: dict[str, Any], function_base_url: str) -> None:
    control_id = finding.get("control_id", "")
    resource_label = _friendly_resource_label(finding.get("resource_id", ""))
    meta = _control_metadata(control_id)

    approve_url = build_decision_url(
        function_base_url, "approve",
        finding.get("finding_id", ""), control_id,
        finding.get("remediation_type", control_id),
        finding.get("resource_id", ""), settings.callback_shared_secret,
    )
    reject_url = build_decision_url(
        function_base_url, "reject",
        finding.get("finding_id", ""), control_id,
        finding.get("remediation_type", control_id),
        finding.get("resource_id", ""), settings.callback_shared_secret,
    )

    # Only show the LLM's plain-English summary (Week 2 pipeline) when
    # one was actually attached to the finding - otherwise this would
    # print a literal "n/a" line above the static summary block below,
    # which is redundant and looks unfinished.
    llm_summary = finding.get("plain_english_summary")
    llm_summary_html = (
        f'<p style="margin:8px 0 0 0;color:#555;"><b>CSPM plain-English note:</b> {llm_summary}</p>'
        if llm_summary else ""
    )

    html_body = f"""
    <p>A CloudGuardian finding requires your approval before automated remediation runs.</p>

    <table style="border-collapse:collapse;margin:12px 0;">
      <tr><td style="padding:2px 10px 2px 0;color:#888;">Finding ID</td><td style="padding:2px 0;">{finding.get('finding_id', 'n/a')}</td></tr>
      <tr><td style="padding:2px 10px 2px 0;color:#888;">Severity</td><td style="padding:2px 0;"><b>{finding.get('severity', 'n/a')}</b></td></tr>
      <tr><td style="padding:2px 10px 2px 0;color:#888;">Control</td><td style="padding:2px 0;">{control_id or 'n/a'}</td></tr>
      <tr><td style="padding:2px 10px 2px 0;color:#888;">Impacted CI</td><td style="padding:2px 0;">{resource_label}</td></tr>
    </table>

    <div style="margin:16px 0;padding:12px 16px;background:#F4F5F9;border-left:4px solid #1E2761;">
      <p style="margin:0 0 8px 0;"><b>What was found:</b> {meta['issue']}</p>
      <p style="margin:0 0 8px 0;"><b>Risk if left as-is:</b> {meta['risk']}</p>
      <p style="margin:0;"><b>What approving will do:</b> {meta['change']}</p>
      {llm_summary_html}
    </div>

    <p>
      <a href="{approve_url}" style="background:#1E2761;color:#fff;padding:10px 20px;text-decoration:none;border-radius:4px;">Approve</a>
      &nbsp;&nbsp;
      <a href="{reject_url}" style="background:#B8324A;color:#fff;padding:10px 20px;text-decoration:none;border-radius:4px;">Reject</a>
    </p>
    <p style="color:#888;font-size:12px;">Approving runs the remediation function described above automatically.
    Rejecting leaves the resource untouched and is recorded in the audit log either way.</p>
    """

    message = {
        "senderAddress": settings.acs_sender_address,
        "recipients": {"to": [{"address": settings.approver_email}]},
        "content": {
            "subject": f"[CloudGuardian] Approval needed: {control_id or 'unknown control'} on {resource_label} ({finding.get('severity', 'unknown severity')})",
            "html": html_body,
        },
    }

    client = _email_client(settings)
    poller = client.begin_send(message)
    poller.result()
    logger.info("Sent approval-request email for finding_id=%s to %s", finding.get("finding_id"), settings.approver_email)


def send_decision_confirmation_email(settings: Settings, finding: dict[str, Any], decision: str, outcome: dict[str, Any] | None) -> None:
    if decision == "approve":
        subject = f"[CloudGuardian] Approved & remediated: {finding.get('control_id', 'unknown control')}"
        body = f"<p>You approved this finding. Remediation result: <b>{(outcome or {}).get('status', 'unknown')}</b>.</p>"
    else:
        subject = f"[CloudGuardian] Rejected: {finding.get('control_id', 'unknown control')}"
        body = "<p>You rejected this finding. No changes were made. This decision is recorded in the Function's audit log.</p>"

    message = {
        "senderAddress": settings.acs_sender_address,
        "recipients": {"to": [{"address": settings.approver_email}]},
        "content": {"subject": subject, "html": body},
    }

    client = _email_client(settings)
    poller = client.begin_send(message)
    poller.result()
    logger.info("Sent %s confirmation email for finding_id=%s", decision, finding.get("finding_id"))
