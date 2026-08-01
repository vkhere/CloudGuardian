"""views/trend.py - scan history: the Week 1 -> Week 3 story per cloud."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from core import loader, metrics


def render(df_all) -> None:
    st.title("Scan history & trend")
    st.caption("Open findings over time - baseline, after the deliberate misconfigs, and after remediation.")

    if df_all.empty:
        st.info("No reports loaded.")
        return

    cat = loader.scan_catalogue(df_all)
    trend = metrics.trend_data(df_all)

    st.subheader("Failing checks over time")
    if trend.empty:
        st.info("No failing checks recorded.")
    else:
        fig = px.line(
            trend.sort_values("captured_at"),
            x="captured_at", y="fails", color="cloud", markers=True,
            text="fails",
        )
        fig.update_traces(textposition="top center")
        fig.update_layout(height=360, margin=dict(t=10, b=10, l=10, r=10),
                          xaxis_title="", yaxis_title="failing checks")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("The spike is Week 1 'build & break'; the drop is Week 3 remediation. "
                   "Anything still elevated is your open backlog.")

    st.subheader("Every scan run")
    show = cat[["cloud", "scan_stage", "week", "captured_at", "checks", "passes", "fails"]] \
        .sort_values(["cloud", "captured_at"])
    st.dataframe(
        show, use_container_width=True, hide_index=True,
        column_config={
            "scan_stage": "Stage", "captured_at": st.column_config.DatetimeColumn("Captured", format="YYYY-MM-DD"),
            "checks": "Checks", "passes": "Pass", "fails": "Fail",
        },
    )

    st.subheader("Deliberate misconfig catalogue (Week 1)")
    catrows = df_all[(df_all["is_catalogued_misconfig"] == "Yes")].copy()
    catrows = catrows.drop_duplicates(subset=["finding_id"])
    if catrows.empty:
        st.info("No catalogued misconfigurations flagged in the reports.")
    else:
        catrows = catrows.sort_values(["cloud", "severity_rank"])
        st.dataframe(
            catrows[["finding_id", "cloud", "service", "severity", "title",
                     "iso_27001", "cis_control", "mitre_attck"]],
            use_container_width=True, hide_index=True,
            column_config={"finding_id": "ID", "iso_27001": "ISO 27001",
                           "cis_control": "CIS", "mitre_attck": "MITRE"},
        )
