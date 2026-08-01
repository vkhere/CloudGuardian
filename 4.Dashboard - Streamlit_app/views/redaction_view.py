"""views/redaction_view.py - live privacy-preserving redaction demonstration."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from core.redaction import Redactor, leak_check


def _default_prompt(current) -> str:
    """Build a realistic prompt from a real finding, so the demo is not synthetic."""
    if current.empty:
        return ("Subscription 010fdff4-2484-41a0-be8b-fccd3e3af6da: storage account "
                "stcloudguardianlab is publicly readable. Owner alice@contoso.com, "
                "allowed CIDR 0.0.0.0/0.")
    fails = current[current["status"] == "FAIL"]
    row = (fails if not fails.empty else current).iloc[0]
    return (
        f"You are a cloud security assistant. Explain this finding in two plain-English "
        f"lines and give a remediation.\n\n"
        f"Subscription: {row['account_id']}\n"
        f"Cloud: {row['cloud']}\n"
        f"Resource: {row['resource_name']}\n"
        f"Region: {row['region']}\n"
        f"Check: {row['check_id']}\n"
        f"Title: {row['title']}\n"
        f"Detail: {row['description']}\n"
        f"Reported by: kedar.pavaskar@techm.com\n"
        f"Exposed CIDR: 0.0.0.0/0"
    )


def render(current) -> None:
    st.title("Privacy-preserving redaction")
    st.caption("Cloud identifiers are tokenised before any prompt leaves this machine, "
               "and restored only locally.")

    resource_names = []
    if not current.empty:
        resource_names = [n for n in current["resource_name"].unique() if str(n).strip()]

    st.subheader("Prompt to be sent")
    text = st.text_area(
        "Edit this to test the tokeniser against your own text",
        value=st.session_state.get("redact_text", _default_prompt(current)),
        height=220, key="redact_text",
    )

    redactor = Redactor(resource_names=list(resource_names))
    safe, hits = redactor.redact(text)
    originals = [h["original"] for h in hits]
    leaks = leak_check(safe, originals)

    c1, c2, c3 = st.columns(3)
    c1.metric("Identifiers tokenised", len(hits))
    c2.metric("Leaked into output", len(leaks))
    c3.metric("Distinct token types", len({h["kind"] for h in hits}))

    if leaks:
        st.error(f"Leak detected - these values survived redaction: {', '.join(leaks)}")
    else:
        st.success("No original identifier survives in the redacted prompt.")

    st.divider()
    left, right = st.columns(2)
    with left:
        st.subheader("Before - stays local")
        st.code(text, language="text")
    with right:
        st.subheader("After - sent to the model")
        st.code(safe, language="text")

    st.subheader("Token mapping")
    st.caption("Held in memory for the session and used to restore the response locally. "
               "This table is never transmitted.")
    if hits:
        st.dataframe(
            pd.DataFrame(hits)[["token", "kind", "original"]],
            use_container_width=True, hide_index=True,
            column_config={"token": "Token", "kind": "Identifier type", "original": "Original value"},
        )
    else:
        st.info("Nothing matched the redaction rules in this text.")

    with st.expander("Restore a model response locally"):
        st.caption("Paste the model's reply containing tokens; the originals are put back here, "
                   "on your machine only.")
        reply = st.text_area(
            "Model response",
            value="Restrict public access on <RES_001> and review the owner <UPN_001>.",
            height=110, key="restore_text",
        )
        st.code(redactor.restore(reply), language="text")

    with st.expander("What gets tokenised"):
        st.markdown(
            "- Subscription, tenant and Entra object IDs (GUIDs)\n"
            "- AWS account numbers, ARNs and access key IDs\n"
            "- User principal names and email addresses\n"
            "- IP addresses and CIDR ranges\n"
            "- Resource names drawn from the loaded findings\n"
            "- Storage, SQL and Key Vault hostnames"
        )
        st.caption("Rules live in core/redaction.py and are applied most-specific first, "
                   "so overlapping values cannot be partially replaced.")
