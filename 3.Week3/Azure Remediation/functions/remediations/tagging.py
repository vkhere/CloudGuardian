"""
remediations/tagging.py

CONTROL: tagging
MAPS TO: Governance / cost-management hygiene, not a security
         control in the strict CIS sense, but explicitly listed in
         the Week 3 brief and directly supports MCSB governance
         guidance and Cloud Adoption Framework tagging standards.
MCSB:    GS-1 (Define asset management and data protection strategy) -
         tags are how you classify data sensitivity and ownership
         at scale.

WHAT THIS FIXES: MERGES a required tag set onto the target resource
         (Environment, Owner, DataClassification, CostCenter) using
         the dedicated Azure Tags resource provider, which supports
         tagging at ANY resource scope generically - this is why
         `tagging` doesn't need per-resource-type SDK clients like
         the other 5 controls.

WHY MERGE AND NOT OVERWRITE: `resources.begin_update` style patches
         can silently wipe existing tags that aren't in your update
         payload. This module reads current tags first and only
         ADDS missing required keys, preserving anything a human
         already set (e.g. a `Project=CloudGuardian` tag from
         Week 1's Terraform `tags` block) - the same "don't destroy
         data you don't own" principle applied to metadata.
"""

from __future__ import annotations

from typing import Any

from azure.mgmt.resource.resources.models import TagsPatchResource, Tags

from shared.audit_logger import audit_scope
from shared.azure_clients import get_resource_client
from shared.config import Settings

CONTROL_ID = "tagging"

REQUIRED_TAGS: dict[str, str] = {
    "Environment": "lab",
    "Owner": "cloudguardian-capstone",
    "DataClassification": "internal",
    "CostCenter": "iitr-capstone",
}


def remediate(
    settings: Settings,
    resource_id: str,
    dry_run: bool = False,
    finding_id: str | None = None,
    approved_by: str | None = None,
    required_tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    client = get_resource_client(settings.subscription_id)
    required_tags = required_tags or REQUIRED_TAGS

    with audit_scope(CONTROL_ID, resource_id, finding_id, approved_by, dry_run) as detail:
        current = client.tags.get_at_scope(scope=resource_id)
        current_tags = dict(current.properties.tags or {})
        detail["before"] = {"tags": current_tags}

        missing = {k: v for k, v in required_tags.items() if k not in current_tags}

        if not missing:
            detail["already_compliant"] = True
            return {"status": "no_change_needed", "control_id": CONTROL_ID, "detail": detail}

        if dry_run:
            detail["planned_change"] = {"tags_to_add": missing}
            return {"status": "dry_run", "control_id": CONTROL_ID, "detail": detail}

        merged = {**current_tags, **missing}
        client.tags.begin_update_at_scope(
            scope=resource_id,
            parameters=TagsPatchResource(operation="Merge", properties=Tags(tags=merged)),
        ).result()

        detail["after"] = {"tags_added": missing}
        return {"status": "remediated", "control_id": CONTROL_ID, "detail": detail}
