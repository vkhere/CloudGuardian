"""views/planner.py - what-if remediation simulator."""

from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from core import metrics
from core.loader import SEV_COLORS


def _delta_gauge(before: float, after: float) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=after,
        delta={"reference": before, "increasing": {"color": "#2f9e44"}},
        number={"suffix": "%", "font": {"size": 30}},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#2f9e44" if after >= before else "#b3261e"},
            "threshold": {"line": {"color": "#8a8f98", "width": 3},
                          "thickness": 0.8, "value": before},
            "steps": [
                {"range": [0, 50], "color": "rgba(179,38,30,0.15)"},
                {"range": [50, 80], "color": "rgba(240,162,2,0.15)"},
                {"range": [80, 100], "color": "rgba(47,158,68,0.15)"},
            ],
        },
    ))
    fig.update_layout(height=240, margin=dict(t=20, b=10, l=20, r=20))
    return fig


def render(current, view_label: str) -> None:
    st.title("Remediation planner")
    st.caption(f"Model the effect of fixes before you make them · {view_label}")

    fails = current[current["status"] == "FAIL"].copy()
    if fails.empty:
        st.success("No open findings to plan against in this view.")
        return

    gains = metrics.marginal_gain(current, fails, "iso_27001")

    left, right = st.columns([1.15, 1])

    with left:
        st.subheader("Select fixes to model")
        st.caption("Ranked by compliance points gained per finding fixed.")
        selected = []
        for _, r in gains.iterrows():
            label = (f"{r['finding_id']} · {r['severity']} · "
                     f"+{r['gain']} pts - {r['title']}")
            if st.checkbox(label, key=f"fix_{r['finding_id']}"):
                selected.append(r["finding_id"])

    with right:
        base_iso = metrics.compliance_score(current, "iso_27001")
        base_cis = metrics.compliance_score(current, "cis_control")
        proj_iso = metrics.project_compliance(current, selected, "iso_27001")
        proj_cis = metrics.project_compliance(current, selected, "cis_control")

        st.subheader("Projected ISO 27001")
        st.plotly_chart(_delta_gauge(base_iso, proj_iso), use_container_width=True)

        m1, m2 = st.columns(2)
        m1.metric("CIS controls", f"{proj_cis}%", f"{round(proj_cis - base_cis, 1)}")
        m2.metric("Fixes selected", len(selected))

        st.subheader("Residual open findings")
        residual = metrics.project_severity(fails, selected)
        order = ["Critical", "High", "Medium", "Low", "Informational"]
        before = fails["severity"].value_counts().to_dict()
        rows = []
        for sev in order:
            b, a = before.get(sev, 0), residual.get(sev, 0)
            if b or a:
                rows.append((sev, b, a))
        if not rows:
            st.success("Nothing left open.")
        else:
            for sev, b, a in rows:
                colour = SEV_COLORS.get(sev, "#8a8f98")
                cleared = b - a
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;"
                    f"padding:4px 0'><span><span style='color:{colour};"
                    f"font-weight:600'>{sev}</span></span>"
                    f"<span>{b} &rarr; <b>{a}</b>"
                    + (f" <span style='color:#2f9e44'>(-{cleared})</span>" if cleared else "")
                    + "</span></div>",
                    unsafe_allow_html=True,
                )

    if selected:
        st.divider()
        st.info(
            f"**Plan summary.** Fixing {len(selected)} finding(s) moves ISO 27001 from "
            f"{base_iso}% to {proj_iso}% and CIS from {base_cis}% to {proj_cis}%. "
            "Approve these on the Findings & approvals page to record the decision."
        )
