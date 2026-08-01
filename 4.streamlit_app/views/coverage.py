"""views/coverage.py — did the pipeline catch every deliberate misconfiguration?"""

from __future__ import annotations

import streamlit as st

from core import metrics
from core.catalogue import load_toggles


def render(df_all, current) -> None:
    st.title("Detection coverage")
    st.caption("Every misconfiguration you deliberately introduced, traced to the scanner that caught it.")

    toggles = load_toggles()
    if toggles.empty:
        st.info(
            "No toggle catalogue found. Create **catalogue/toggles.csv** listing each "
            "deliberate misconfiguration and the finding it should raise. "
            "See catalogue/README_catalogue.md for the columns."
        )
        return

    # Coverage is judged against the worst-case scan (after misconfig), because
    # that is the scan in which every toggle was switched on.
    misconfig_scan = df_all[df_all["scan_stage"] == "After misconfig"]
    basis = misconfig_scan if not misconfig_scan.empty else current
    fails = basis[basis["status"] == "FAIL"]

    cov = metrics.coverage_table(toggles, fails)
    s = metrics.coverage_summary(cov)

    c1, c2, c3 = st.columns([1, 1, 2])
    c1.metric("Toggles detected", f"{s['detected']} / {s['total']}")
    c2.metric("Not detected", s["missed"])
    c3.progress(s["pct"] / 100, text=f"{s['pct']}% coverage")

    st.caption("Measured against the *after misconfig* scan, when every toggle was switched on.")
    st.divider()

    detected = cov[cov["detected"]]
    missed = cov[~cov["detected"]]

    st.subheader(f"Detected ({len(detected)})")
    if detected.empty:
        st.info("Nothing detected yet.")
    else:
        st.dataframe(
            detected[["toggle_id", "cloud", "toggle_name", "category",
                      "expected_finding", "detected_by", "severity"]],
            use_container_width=True, hide_index=True,
            column_config={
                "toggle_id": "ID", "toggle_name": "Terraform toggle",
                "expected_finding": "Finding raised", "detected_by": "Detected by",
            },
        )

    st.subheader(f"Not detected ({len(missed)})")
    if missed.empty:
        st.success("Every catalogued misconfiguration was detected by at least one tool.")
    else:
        st.warning(
            "These were introduced but no scanner raised them. Absence-of-control "
            "issues are the usual cause — CSPM rules assert on what exists, not on "
            "what is missing."
        )
        st.dataframe(
            missed[["toggle_id", "cloud", "toggle_name", "category",
                    "expected_finding", "severity"]],
            use_container_width=True, hide_index=True,
            column_config={
                "toggle_id": "ID", "toggle_name": "Terraform toggle",
                "expected_finding": "Expected finding",
            },
        )

    with st.expander("Full catalogue with rationale and revert steps"):
        st.dataframe(
            cov[["toggle_id", "cloud", "toggle_name", "category", "severity",
                 "rationale", "revert", "detected"]],
            use_container_width=True, hide_index=True,
            column_config={
                "toggle_id": "ID", "toggle_name": "Toggle",
                "rationale": "Why introduced", "revert": "How to revert",
                "detected": st.column_config.CheckboxColumn("Detected", disabled=True),
            },
        )
