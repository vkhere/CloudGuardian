"""
shared/resource_id.py

WHAT: Parses a full Azure ARM resource ID into its parts.

WHY: Every finding CloudGuardian's CSPM pipeline produces (Week 2)
     carries a `resource_id` field in the standard ARM format:

       /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}

     Parsing it here (once) instead of string-splitting inline in
     every remediation module means: (1) one tested implementation,
     (2) remediation modules work correctly even if you point this
     engine at a resource in a different resource group than the
     one in TARGET_RESOURCE_GROUP - which matters the moment you
     add a second workload or a teammate's subscription.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ARM_ID_RE = re.compile(
    r"^/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/(?P<provider_namespace>[^/]+)"
    r"/(?P<resource_type>[^/]+)"
    r"/(?P<resource_name>[^/]+)"
    r"(?:/(?P<child_type>[^/]+)/(?P<child_name>[^/]+))?$",
    re.IGNORECASE,
)


class InvalidResourceIdError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedResourceId:
    subscription_id: str
    resource_group: str
    provider_namespace: str
    resource_type: str
    resource_name: str
    child_type: str | None = None
    child_name: str | None = None


def parse_resource_id(resource_id: str) -> ParsedResourceId:
    match = _ARM_ID_RE.match(resource_id.strip())
    if not match:
        raise InvalidResourceIdError(
            f"'{resource_id}' is not a well-formed ARM resource ID. "
            f"Expected /subscriptions/{{id}}/resourceGroups/{{rg}}/providers/{{ns}}/{{type}}/{{name}}"
        )
    parts = match.groupdict()
    return ParsedResourceId(**parts)
