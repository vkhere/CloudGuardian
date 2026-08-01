"""views/audit.py - full history of reviewer decisions."""

from __future__ import annotations

import streamlit as st

from core.database import get_audit_df


def render() -> None:
    st.title("Audit trail")
    st.caption("Every approve / reject / remediate action, newest first.")

    audit = get_audit_df()
    if audit.empty:
        st.info("No actions recorded yet. Approve or reject a finding to populate this.")
        return

    audit = audit.rename(columns={"timestamp": "When", "finding_id": "Finding",
                                  "action": "Action", "actor": "By", "detail": "Note"})
    st.dataframe(audit, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇️ Download audit trail (CSV)",
        audit.to_csv(index=False).encode("utf-8"),
        file_name="cloudguardian_audit_trail.csv", mime="text/csv",
    )
