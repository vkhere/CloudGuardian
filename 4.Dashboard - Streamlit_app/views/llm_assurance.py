"""views/llm_assurance.py - verification of LLM-generated remediation guidance."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from core import metrics


def render(current, view_label: str) -> None:
    st.title("LLM verification")
    st.caption(f"Was every generated remediation substantiated by the raw scanner data? · {view_label}")

    if current.empty:
        st.info("No data in this view.")
        return

    s = metrics.llm_stats(current)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verified", s["verified"])
    c2.metric("Needs review", s["needs_review"])
    c3.metric("Flagged", s["flagged"])
    c4.metric("Flagged rate", f"{s['hallucination_rate']}%")

    st.divider()
    left, right = st.columns(2)

    with left:
        st.subheader("Verification outcome")
        data = [
            {"status": "Verified", "count": s["verified"]},
            {"status": "Needs review", "count": s["needs_review"]},
            {"status": "Flagged", "count": s["flagged"]},
        ]
        import pandas as pd
        d = pd.DataFrame([r for r in data if r["count"]])
        if d.empty:
            st.info("No verification statuses recorded.")
        else:
            fig = px.pie(d, names="status", values="count", hole=0.55,
                         color="status",
                         color_discrete_map={"Verified": "#2f9e44",
                                             "Needs review": "#f0a202",
                                             "Flagged": "#b3261e"})
            fig.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Stated confidence")
        conf = metrics.llm_confidence_breakdown(current)
        if conf.empty:
            st.info("No confidence values recorded.")
        else:
            fig2 = px.bar(conf, x="llm_confidence", y="count", text="count",
                          color="llm_confidence",
                          color_discrete_map={"High": "#2f9e44", "Medium": "#f0a202",
                                              "Low": "#b3261e", "Unstated": "#8a8f98"})
            fig2.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10),
                               showlegend=False, xaxis_title="", yaxis_title="findings")
            st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Items requiring attention")
    attention = current[
        current["verification_status"].astype(str).str.strip().str.lower()
        .isin(["flagged", "needs review"])
    ]
    if attention.empty:
        st.success("Every remediation in this view was verified against the raw findings.")
    else:
        st.dataframe(
            attention[["finding_id", "cloud", "severity", "verification_status",
                       "llm_confidence", "title", "remediation"]],
            use_container_width=True, hide_index=True,
            column_config={
                "finding_id": "ID", "verification_status": "Verification",
                "llm_confidence": "Confidence", "title": "Finding",
                "remediation": "Generated guidance",
            },
        )

    st.caption(
        "Verification methodology: each generated remediation is checked against the "
        "raw scanner record for the same finding. Guidance that references a resource, "
        "setting or control absent from the raw data is marked **Flagged** and excluded "
        "from auto-approval. Findings the scanner returned as MANUAL cannot be verified "
        "automatically and are marked **Needs review**."
    )
