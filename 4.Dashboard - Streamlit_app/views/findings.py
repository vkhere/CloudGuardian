"""views/findings.py - findings table + review/approval gate."""

from __future__ import annotations

import streamlit as st

from core.database import record_decision
from core.loader import SEV_COLORS, STATUS_COLORS


def _badge(text, color):
    return (f"<span style='background:{color};color:#fff;padding:2px 10px;border-radius:10px;"
            f"font-size:0.8rem;font-weight:600'>{text}</span>")


def render(open_dec, approver: str) -> None:
    st.title("Findings & approvals")
    st.caption(f"{len(open_dec)} open finding(s) in this view. Sorted by severity, then risk.")

    if open_dec.empty:
        st.success("No open findings to review in this view.")
        return

    cols = ["finding_id", "cloud", "service", "severity", "risk_score", "title",
            "decision_status", "verification_status"]
    st.dataframe(
        open_dec[cols], use_container_width=True, hide_index=True,
        column_config={
            "finding_id": "ID",
            "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
            "decision_status": "Decision",
            "verification_status": "LLM check",
        },
    )

    st.divider()
    st.subheader("Review a finding")
    ids = open_dec["finding_id"].tolist()
    chosen = st.selectbox("Pick a finding", ids, key="chosen_finding")
    row = open_dec[open_dec["finding_id"] == chosen].iloc[0]

    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"### {row['title']} &nbsp; {_badge(row['severity'], SEV_COLORS.get(row['severity'], '#888'))}",
                    unsafe_allow_html=True)
        st.markdown(f"**{row['cloud']}** · {row['service']} · `{row['resource_name']}` · {row['region']}")
        st.write(row["description"])
        st.markdown("**Suggested remediation (LLM):**")
        st.info(row["remediation"] or "_No remediation text provided._")
    with right:
        st.markdown("**Details**")
        st.markdown(f"- Status: {_badge(row['decision_status'], STATUS_COLORS.get(row['decision_status'], '#888'))}",
                    unsafe_allow_html=True)
        st.write({
            "Risk score": int(row["risk_score"]),
            "CVSS": row["cvss"] or "-",
            "Exposure": row["exposure"] or "-",
            "Source tool": row["source_tool"] or "-",
            "LLM confidence": row["llm_confidence"] or "-",
            "LLM verification": row["verification_status"] or "-",
            "ISO 27001": row["iso_27001"] or "-",
            "CIS": row["cis_control"] or "-",
            "MITRE": row["mitre_attck"] or "-",
            "Deliberate misconfig": row["is_catalogued_misconfig"] or "-",
        })
        if row["approver"]:
            st.caption(f"Last actioned by {row['approver']} at {row['decided_at']}")

    st.markdown("#### Decision")
    if str(row["verification_status"]).strip().lower() == "flagged":
        st.warning("⚠️ LLM remediation is **Flagged** by verification - check it against the raw scanner data before approving.")

    note = st.text_input("Note (optional)", key=f"note_{chosen}")
    disabled = not approver.strip()
    b1, b2, b3, _ = st.columns([1, 1, 1.4, 3])
    if b1.button("✅ Approve", type="primary", disabled=disabled, use_container_width=True):
        record_decision(chosen, "Approved", approver, note); st.rerun()
    if b2.button("❌ Reject", disabled=disabled, use_container_width=True):
        record_decision(chosen, "Rejected", approver, note); st.rerun()
    if b3.button("🛠️ Mark remediated", disabled=disabled, use_container_width=True):
        record_decision(chosen, "Remediated", approver, note); st.rerun()
    if disabled:
        st.caption("Enter your name in the sidebar to enable the decision buttons.")
