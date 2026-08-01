"""
privacy_llm/tokenizer.py

WHAT: Pseudonymizes sensitive identifiers in a CSPM finding BEFORE
      it is sent to an external LLM API, and reverses the
      pseudonymization on the LLM's response before it is shown to
      a human or stored.

WHY THIS EXISTS: a CSPM finding routinely contains your Azure
      Subscription ID, Object IDs (GUIDs identifying real users or
      service principals), User Principal Names (UPNs - i.e. real
      email addresses), resource names, and principal display names.
      Sending that verbatim to a third-party LLM API means tenant-
      identifying and potentially personal data leaves your Azure
      boundary on every remediation-explanation call. Under the
      DPDP Act 2023 + DPDP Rules 2025 (notified 14 Nov 2025), a
      "Data Fiduciary" processing personal data must apply
      "reasonable security safeguards" - the Rules specifically list
      "encryption, obfuscation, masking, or the use of virtual
      tokens mapped to such personal data" as an example. This
      module IS that safeguard, implemented literally.

DESIGN CHOICE - STRUCTURED TOKENIZATION, NOT FREEFORM NER: a naive
      approach would run a Named-Entity-Recognition model over the
      finding's free text to guess what looks like a name. That is
      unreliable and impossible to verify. Instead, this module
      ONLY tokenizes values it receives in explicitly labeled fields
      of a structured finding dict (subscription_id, object_id,
      upn, resource_name, principal_name) - fields your Week 2
      normalized findings schema already produces. Regex scanning of
      free-text fields is used ONLY as a second-pass GUARDRAIL (see
      verify_no_leakage), not as the primary mechanism.

WHERE THIS RUNS: called by llm_client.py immediately before and
      after every LLM API call. Never call the LLM directly without
      going through this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Matches this project's own naming convention (see Week 1 locals.tf):
# prefix-project-environment[-suffix], e.g. st-cloudguardian-lab-a1b2c
RESOURCE_NAME_RE = re.compile(
    r"\b(?:rg|vnet|nsg|vm|st|sql|kv|func|logic|aa|evgt|asp|appi)-[a-z0-9-]+\b",
    re.IGNORECASE,
)


class PrivacyLeakError(RuntimeError):
    """Raised when text that is about to be sent to an external LLM
    still matches a sensitive pattern after tokenization. This is a
    hard stop, not a warning - the call must not proceed."""


@dataclass
class TokenMap:
    """The real-value <-> token mapping for ONE finding. Deliberately
    scoped to a single tokenize()/detokenize() round trip and never
    serialized to disk or sent anywhere.
    """

    token_to_real: dict[str, str] = field(default_factory=dict)
    real_to_token: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    def get_or_create_token(self, category: str, real_value: str) -> str:
        if real_value in self.real_to_token:
            return self.real_to_token[real_value]

        self._counters[category] = self._counters.get(category, 0) + 1
        token = f"<<{category.upper()}_{self._counters[category]}>>"
        self.token_to_real[token] = real_value
        self.real_to_token[real_value] = token
        return token

    def restore(self, real_value: str) -> str:
        return self.real_to_token.get(real_value, real_value)


# Structured fields eligible for tokenization, mapped to a token
# category name. Extend this dict if your Week 2 schema adds fields -
# do NOT add ad-hoc regex scanning instead, per the design note above.
SENSITIVE_FIELDS: dict[str, str] = {
    "subscription_id": "subscription",
    "tenant_id": "tenant",
    "object_id": "object_id",
    "upn": "upn",
    "principal_name": "principal",
    "resource_name": "resource",
    "resource_id": "resource_id",
}


def tokenize_finding(finding: dict, token_map: TokenMap | None = None) -> tuple[dict, TokenMap]:
    """Return a copy of `finding` with every value in SENSITIVE_FIELDS
    replaced by a deterministic token, plus the TokenMap needed to
    reverse it. Non-sensitive fields (severity, control_id, CVSS
    score, timestamps) pass through unchanged.

    LESSON FROM TESTING THIS MODULE: an earlier version relied only
    on RESOURCE_NAME_RE to catch resource names inside free-text
    fields (e.g. "storage account stcloudguardianab12c allows...").
    That regex requires a hyphen after the prefix (rg-, vnet-, st-),
    but Azure Storage Account and Key Vault names frequently contain
    NO hyphens at all - so a real name like "stcloudguardianab12c"
    silently passed the regex uncaught. The fix: once a real value
    has been tokenized from a STRUCTURED field, this function also
    does an exact literal-substring replace of that same real value
    anywhere it appears in free text - no guessing required, because
    we already know precisely what to look for. Regex is now only a
    last-resort net for values we were never told about structurally.
    """
    token_map = token_map or TokenMap()
    sanitized = dict(finding)

    for field_name, category in SENSITIVE_FIELDS.items():
        value = sanitized.get(field_name)
        if value:
            sanitized[field_name] = token_map.get_or_create_token(category, str(value))

    # Also register the bare resource NAME (last path segment of an
    # ARM resource ID) as its own tokenizable literal - this is the
    # value most likely to be quoted inline inside free text, and it
    # is NOT reliably catchable by a hyphen-based regex.
    raw_resource_id = finding.get("resource_id")
    if raw_resource_id:
        bare_name = str(raw_resource_id).rstrip("/").split("/")[-1]
        if bare_name and bare_name not in token_map.real_to_token:
            token_map.real_to_token[bare_name] = token_map.get_or_create_token("resource", bare_name)

    for text_field in ("plain_english_summary", "raw_finding_text"):
        text = sanitized.get(text_field)
        if not text:
            continue

        # Pass 1: exact literal replacement of every real value we
        # already know about (longest first, so a short substring
        # can't shadow a longer value that contains it).
        known_values = sorted(token_map.real_to_token, key=len, reverse=True)
        for real_value in known_values:
            if real_value and real_value in text:
                text = text.replace(real_value, token_map.real_to_token[real_value])

        # Pass 2: regex last-resort net for anything not already
        # known structurally.
        text = GUID_RE.sub(lambda m: token_map.get_or_create_token("guid", m.group(0)), text)
        text = EMAIL_RE.sub(lambda m: token_map.get_or_create_token("upn", m.group(0)), text)
        text = RESOURCE_NAME_RE.sub(lambda m: token_map.get_or_create_token("resource", m.group(0)), text)
        sanitized[text_field] = text

    return sanitized, token_map


def verify_no_leakage(payload_text: str) -> None:
    """Guardrail run immediately before the outbound API call, on the
    FINAL serialized request body (not the pre-tokenization dict).
    Raises PrivacyLeakError and blocks the call if anything slipped
    through tokenize_finding().
    """
    leaks: list[str] = []
    if GUID_RE.search(payload_text):
        leaks.append("GUID pattern")
    if EMAIL_RE.search(payload_text):
        leaks.append("email/UPN pattern")
    if RESOURCE_NAME_RE.search(payload_text):
        leaks.append("CloudGuardian resource-name pattern")

    if leaks:
        raise PrivacyLeakError(
            f"Outbound LLM payload still contains: {', '.join(leaks)}. "
            f"Blocking the call. Check that every sensitive field went "
            f"through tokenize_finding() before this point."
        )


def detokenize(text: str, token_map: TokenMap) -> str:
    """Reverse tokenization on the LLM's response. Real values are
    restored ONLY here, inside your Azure boundary.
    """
    for token, real_value in token_map.token_to_real.items():
        text = text.replace(token, real_value)
    return text
