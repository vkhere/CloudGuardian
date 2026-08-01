"""
core/redaction.py
=================
A real, working tokeniser for the privacy-preserving LLM pipeline.

WHY THIS EXISTS
    Your capstone requires that no cloud identifier reaches the LLM in
    plaintext: subscription IDs, object IDs, UPNs, resource names, account
    numbers, public IPs. This module replaces each with a stable token
    (<SUB_001>, <UPN_002> ...) before the prompt leaves the machine, and can
    restore the originals afterwards, locally.

    It is deterministic: the same input value always maps to the same token
    within a session, so the LLM can reason about "the same resource" without
    ever seeing its name.

HOW IT WORKS
    Ordered regex passes, most specific first. Order matters: a UPN contains
    an @ and dots, and would be partly eaten by a looser hostname rule if that
    ran first. Resource names supplied by the caller (from your findings data)
    are matched literally, longest first, so 'stcloudguardianlab' is replaced
    before a shorter overlapping name.

USAGE
    r = Redactor(resource_names=["stcloudguardianlab", "vm-web-cloudguardian"])
    safe, mapping = r.redact(prompt_text)
    original = r.restore(llm_response)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Order is significant. Each entry: (token prefix, compiled pattern).
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # GUIDs cover Azure subscription IDs, tenant IDs and Entra object IDs.
    ("GUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # ARNs first: they embed an account number, and tokenising the account
    # number first would break this pattern into fragments.
    ("ARN", re.compile(r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"',]+")),
    # AWS 12-digit account numbers.
    ("ACCT", re.compile(r"\b\d{12}\b")),
    # AWS access key IDs.
    ("AKID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # Email addresses / user principal names.
    ("UPN", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # IPv4 addresses, optionally with a CIDR suffix.
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")),
    # Azure resource FQDNs (storage, sql, vault, blob ...).
    ("HOST", re.compile(r"\b[a-z0-9-]+\.(?:blob|file|queue|table)\.core\.windows\.net\b"
                        r"|\b[a-z0-9-]+\.database\.windows\.net\b"
                        r"|\b[a-z0-9-]+\.vault\.azure\.net\b")),
]


@dataclass
class Redactor:
    """Deterministic, reversible tokeniser. One instance per session."""

    resource_names: list[str] = field(default_factory=list)
    _forward: dict[str, str] = field(default_factory=dict, init=False)  # original -> token
    _reverse: dict[str, str] = field(default_factory=dict, init=False)  # token -> original
    _counters: dict[str, int] = field(default_factory=dict, init=False)

    def _token_for(self, prefix: str, value: str) -> str:
        """Return the existing token for a value, or mint a new one."""
        if value in self._forward:
            return self._forward[value]
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        token = f"<{prefix}_{self._counters[prefix]:03d}>"
        self._forward[value] = token
        self._reverse[token] = value
        return token

    def redact(self, text: str) -> tuple[str, list[dict]]:
        """
        Replace every sensitive value with a token.
        Returns the safe text and a list of {token, kind, original} entries
        describing what was replaced, for display in the UI.
        """
        if not isinstance(text, str) or not text:
            return "", []

        hits: list[dict] = []
        out = text

        # 1. Caller-supplied resource names, longest first so that overlapping
        #    names cannot be partially replaced.
        for name in sorted({n for n in self.resource_names if n}, key=len, reverse=True):
            if name and name in out:
                token = self._token_for("RES", name)
                out = out.replace(name, token)
                hits.append({"token": token, "kind": "Resource name", "original": name})

        # 2. Pattern passes, in the fixed order defined above.
        for prefix, pattern in _PATTERNS:
            def _sub(match: re.Match) -> str:
                value = match.group(0)
                token = self._token_for(prefix, value)
                hits.append({"token": token, "kind": _KIND_LABELS[prefix], "original": value})
                return token
            out = pattern.sub(_sub, out)

        # De-duplicate while preserving first-seen order.
        seen, unique = set(), []
        for h in hits:
            if h["token"] not in seen:
                seen.add(h["token"])
                unique.append(h)
        return out, unique

    def restore(self, text: str) -> str:
        """Put the original values back. Run this only on your own machine."""
        if not isinstance(text, str):
            return ""
        out = text
        for token, original in self._reverse.items():
            out = out.replace(token, original)
        return out

    @property
    def mapping(self) -> dict[str, str]:
        """token -> original. Never send this anywhere."""
        return dict(self._reverse)


_KIND_LABELS = {
    "GUID": "Subscription / object ID",
    "ACCT": "AWS account number",
    "AKID": "AWS access key ID",
    "ARN": "AWS ARN",
    "UPN": "User principal name",
    "IP": "IP address",
    "HOST": "Resource hostname",
}


def leak_check(redacted_text: str, originals: list[str]) -> list[str]:
    """
    Safety net: confirm no original value survived into the redacted text.
    Returns the list of values that leaked (empty list means clean).
    """
    return [o for o in originals if o and o in redacted_text]
