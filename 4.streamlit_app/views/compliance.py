"""views/compliance.py — control posture and the ISO x CIS x DPDP crosswalk."""

from __future__ import annotations

import streamlit as st

from core import metrics
from core.catalogue import load_dpdp_map


def _framework_tab(current, framework, label):
    tbl = metrics.compliance_by_control(current, framework)
    score = metrics.compliance_score(current, framework)
    c1, c2 = st.columns([1, 3])
    c1.metric(f"{label} passing", f"{score}%")
    if tbl.empty:
        st.info("No controls mapped in this view.")
        return
    c2.progress(score / 100, text=f"{int((tbl['result'] == 'Pass').sum())} of {len(tbl)} controls passing")
    tbl = tbl.rename(columns={framework: "Control", "result": "Result",
                              "failing": "Failing checks", "total": "Mapped checks"})
    st.dataframe(tbl, use_container_width=True, hide_index=True)


def render(current, view_label: str) -> None:
    st.title("Compliance posture")
    st.caption(f"Control rollup for **{view_label}**. A control fails if any mapped check is failing.")

    if current.empty:
        st.info("No data in this view.")
        return

    tab1, tab2, tab3 = st.tabs(["ISO 27001 Annex A", "CIS Benchmark", "Crosswalk (ISO × CIS × DPDP)"])

    with tab1:
        _framework_tab(current, "iso_27001", "ISO 27001 controls")

    with tab2:
        _framework_tab(current, "cis_control", "CIS controls")

    with tab3:
        st.caption("One row per ISO control, with the CIS controls that share the same "
                   "checks and the DPDP Act 2023 obligation it supports.")
        dpdp = load_dpdp_map()
        cw = metrics.crosswalk(current, dpdp)
        if cw.empty:
            st.info("No mapped controls in this view.")
        else:
            failing = int((cw["result"] == "Fail").sum())
            c1, c2, c3 = st.columns(3)
            c1.metric("Controls mapped", len(cw))
            c2.metric("Failing", failing)
            c3.metric("DPDP obligations touched",
                      int((cw["dpdp_section"] != "-").sum()))

            if dpdp.empty:
                st.warning(
                    "No DPDP mapping file found — the DPDP columns will show as '-'. "
                    "Create **catalogue/dpdp_map.csv** mapping each ISO control to a "
                    "DPDP Act section."
                )

            st.dataframe(
                cw.rename(columns={
                    "iso_27001": "ISO 27001 Annex A",
                    "cis_control": "CIS control",
                    "dpdp_section": "DPDP section",
                    "dpdp_obligation": "DPDP obligation",
                    "checks": "Checks",
                    "failing": "Failing",
                    "result": "Result",
                }),
                use_container_width=True, hide_index=True,
            )

            st.download_button(
                "Download crosswalk (CSV)",
                cw.to_csv(index=False).encode("utf-8"),
                file_name="cloudguardian_compliance_crosswalk.csv", mime="text/csv",
            )

            st.caption(
                "DPDP note: the Act does not enumerate technical controls. Section 8(5) "
                "requires a Data Fiduciary to take reasonable security safeguards to "
                "prevent a personal data breach; the mapping shown here is the argued "
                "link between each technical control and that obligation, and should be "
                "presented as such rather than as a certified mapping."
            )
