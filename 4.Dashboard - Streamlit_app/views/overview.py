"""views/overview.py - executive single-pane summary."""

from __future__ import annotations

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core import metrics
from core.loader import SEV_COLORS


def _gauge(value: float, title: str) -> go.Figure:
    color = "#2f9e44" if value >= 80 else ("#f0a202" if value >= 50 else "#b3261e")
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            number={"suffix": "%", "font": {"size": 26}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 50], "color": "rgba(179,38,30,0.15)"},
                    {"range": [50, 80], "color": "rgba(240,162,2,0.15)"},
                    {"range": [80, 100], "color": "rgba(47,158,68,0.15)"},
                ],
            },
        )
    )
    fig.update_layout(height=200, margin=dict(t=30, b=0, l=20, r=20), title=dict(text=title, font=dict(size=13)))
    return fig


def render(current, open_dec, df_all, view_label: str) -> None:
    st.title("Executive overview")
    st.caption(f"Posture across all clouds · showing **{view_label}** · {', '.join(sorted(current['cloud'].unique()))}")

    p = metrics.posture_summary(current)
    funnel = metrics.remediation_funnel(open_dec)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Open findings", p["fails"])
    c2.metric("Critical + high", p["crit_high"])
    c3.metric("Checks passing", f"{p['pass_rate']}%")
    c4.metric("Pending review", funnel["Pending"])
    c5.metric("Remediated", funnel["Remediated"])

    st.divider()
    g1, g2, g3 = st.columns([1, 1, 1])
    with g1:
        st.plotly_chart(_gauge(metrics.compliance_score(current, "iso_27001"), "ISO 27001 controls passing"),
                        use_container_width=True)
    with g2:
        st.plotly_chart(_gauge(metrics.compliance_score(current, "cis_control"), "CIS controls passing"),
                        use_container_width=True)
    with g3:
        st.markdown("**Remediation gate**")
        for k, v in funnel.items():
            st.markdown(f"{k}&nbsp;&nbsp;**{v}**", unsafe_allow_html=True)

    st.divider()
    col_a, col_b = st.columns(2)
    fails = current[current["status"] == "FAIL"]
    with col_a:
        st.subheader("Open findings by severity")
        sc = metrics.severity_counts(fails)
        if sc.empty:
            st.success("No open findings in this view.")
        else:
            fig = px.pie(sc, names="severity", values="count", hole=0.55,
                         color="severity", color_discrete_map=SEV_COLORS)
            fig.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True)
    with col_b:
        st.subheader("Open findings by cloud")
        bc = metrics.by_cloud(fails)
        if bc.empty:
            st.info("Nothing to show.")
        else:
            fig2 = px.bar(bc, x="cloud", y="count", color="cloud", text="count")
            fig2.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10), showlegend=False,
                               xaxis_title="", yaxis_title="findings")
            st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Top open risks")
    top = fails.sort_values(["severity_rank", "risk_score"], ascending=[True, False]).head(8)
    if top.empty:
        st.info("No open risks in this view.")
    else:
        st.dataframe(
            top[["finding_id", "cloud", "service", "severity", "risk_score", "title"]],
            use_container_width=True, hide_index=True,
            column_config={
                "finding_id": "ID",
                "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
            },
        )
