"""views/mitre.py - ATT&CK technique coverage for open findings."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from core import metrics


def render(current, view_label: str) -> None:
    st.title("ATT&CK coverage")
    st.caption(f"Open findings mapped to adversary techniques · {view_label}")

    fails = current[current["status"] == "FAIL"]
    mat = metrics.attck_matrix(fails)

    if mat.empty:
        st.info("No failing findings with an ATT&CK mapping in this view.")
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("Techniques observed", len(mat))
    c2.metric("Tactics covered", mat["tactic"].nunique())
    c3.metric("Findings mapped", int(mat["count"].sum()))

    st.divider()
    st.subheader("Technique heatmap")
    fig = px.treemap(
        mat, path=["tactic", "technique"], values="count", color="count",
        color_continuous_scale=["#3a2018", "#8a4b12", "#c2571a", "#b3261e"],
        custom_data=["name"],
    )
    fig.update_traces(hovertemplate="<b>%{label}</b><br>%{customdata[0]}<br>%{value} findings<extra></extra>")
    fig.update_layout(height=420, margin=dict(t=10, b=10, l=10, r=10))
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("By tactic")
    by_tactic = mat.groupby("tactic", as_index=False)["count"].sum()
    by_tactic["rank"] = by_tactic["tactic"].apply(
        lambda t: metrics.TACTIC_ORDER.index(t) if t in metrics.TACTIC_ORDER else 99)
    by_tactic = by_tactic.sort_values("rank")
    fig2 = px.bar(by_tactic, x="tactic", y="count", text="count",
                  color_discrete_sequence=["#c2571a"])
    fig2.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10),
                       xaxis_title="", yaxis_title="findings")
    st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Technique detail")
    st.dataframe(
        mat[["technique", "name", "tactic", "count", "findings"]],
        use_container_width=True, hide_index=True,
        column_config={
            "technique": "ID", "name": "Technique", "tactic": "Tactic",
            "count": "Findings", "findings": "Finding IDs",
        },
    )
    st.caption("Techniques appearing in both clouds indicate an architectural weakness "
               "rather than a provider-specific one.")
