"""views/export.py — one-click executive PDF and CSV exports."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from core import metrics
from core.catalogue import load_toggles
from core.database import get_audit_df
from core.pdfreport import build_pdf


def render(current, open_dec, df_all, view_label: str) -> None:
    st.title("Export")
    st.caption("Generate the management summary and the raw data behind it.")

    if current.empty:
        st.info("No data in this view to export.")
        return

    fails = current[current["status"] == "FAIL"].sort_values(
        ["severity_rank", "risk_score"], ascending=[True, False])

    posture = metrics.posture_summary(current)
    iso = metrics.compliance_score(current, "iso_27001")
    cis = metrics.compliance_score(current, "cis_control")
    funnel = metrics.remediation_funnel(open_dec)
    llm = metrics.llm_stats(current)

    toggles = load_toggles()
    misconfig_scan = df_all[df_all["scan_stage"] == "After misconfig"]
    basis = misconfig_scan if not misconfig_scan.empty else current
    cov = metrics.coverage_summary(
        metrics.coverage_table(toggles, basis[basis["status"] == "FAIL"]))

    st.subheader("What the report contains")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Open findings", posture["fails"])
    c2.metric("ISO 27001", f"{iso}%")
    c3.metric("Coverage", f"{cov['pct']}%")
    c4.metric("Pending review", funnel["Pending"])

    st.markdown(
        "- Posture headline and scope\n"
        "- Severity distribution\n"
        "- Ten highest open risks\n"
        "- ISO 27001 and CIS position\n"
        "- Detection coverage against the deliberate misconfigurations\n"
        "- Remediation gate status and LLM verification summary"
    )

    st.divider()
    st.subheader("Executive PDF")

    if st.button("Generate PDF", type="primary"):
        with st.spinner("Building report..."):
            try:
                pdf = build_pdf(current, fails, posture, iso, cis, cov, funnel, llm, view_label)
                st.session_state["pdf_bytes"] = pdf
                st.session_state["pdf_name"] = (
                    f"cloudguardian_summary_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
                st.success("Report ready.")
            except Exception as exc:  # noqa: BLE001 - surface any render failure to the user
                st.error(f"Could not build the PDF: {exc}")

    if st.session_state.get("pdf_bytes"):
        st.download_button(
            "Download executive summary (PDF)",
            st.session_state["pdf_bytes"],
            file_name=st.session_state.get("pdf_name", "cloudguardian_summary.pdf"),
            mime="application/pdf",
        )

    st.divider()
    st.subheader("Raw data")
    d1, d2, d3 = st.columns(3)
    with d1:
        st.download_button(
            "Current view (CSV)",
            current.drop(columns=["severity_rank", "stage_rank"], errors="ignore")
            .to_csv(index=False).encode("utf-8"),
            file_name="cloudguardian_current_view.csv", mime="text/csv",
        )
    with d2:
        st.download_button(
            "Open findings + decisions (CSV)",
            open_dec.drop(columns=["severity_rank", "stage_rank"], errors="ignore")
            .to_csv(index=False).encode("utf-8"),
            file_name="cloudguardian_open_findings.csv", mime="text/csv",
        )
    with d3:
        audit = get_audit_df()
        st.download_button(
            "Audit trail (CSV)",
            audit.to_csv(index=False).encode("utf-8"),
            file_name="cloudguardian_audit_trail.csv", mime="text/csv",
            disabled=audit.empty,
        )
