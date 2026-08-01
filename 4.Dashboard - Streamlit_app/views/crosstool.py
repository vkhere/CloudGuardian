"""views/crosstool.py - which scanner caught what."""

from __future__ import annotations

import plotly.express as px
import streamlit as st

from core import metrics


def render(current, view_label: str) -> None:
    st.title("Cross-tool agreement")
    st.caption(f"Detection overlap between Prowler, ScoutSuite and Steampipe · {view_label}")

    fails = current[current["status"] == "FAIL"]
    mat = metrics.crosstool_matrix(fails)

    if mat.empty:
        st.info("No failing findings in this view.")
        return

    s = metrics.crosstool_summary(mat)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("All three agree", s["all_three"])
    c2.metric("Two of three", s["two"])
    c3.metric("Single tool only", s["single"])
    c4.metric("Mean agreement", f"{s['mean']} / 3")

    st.divider()
    st.subheader("Detection matrix")
    show = mat.copy()
    show["Agreement"] = show["agreement"].astype(str) + " of 3"
    st.dataframe(
        show[["finding_id", "cloud", "severity", "Prowler", "ScoutSuite",
              "Steampipe", "Agreement", "title"]],
        use_container_width=True, hide_index=True,
        column_config={
            "finding_id": "ID",
            "Prowler": st.column_config.CheckboxColumn("Prowler", disabled=True),
            "ScoutSuite": st.column_config.CheckboxColumn("ScoutSuite", disabled=True),
            "Steampipe": st.column_config.CheckboxColumn("Steampipe", disabled=True),
            "title": "Finding",
        },
    )

    st.subheader("Findings raised per tool")
    counts = []
    for tool in metrics.TOOLS:
        counts.append({"tool": tool, "findings": int(mat[tool].sum())})
    import pandas as pd
    fig = px.bar(pd.DataFrame(counts), x="tool", y="findings", text="findings",
                 color="tool", color_discrete_sequence=["#2563eb", "#e8590c", "#2f9e44"])
    fig.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10),
                      showlegend=False, xaxis_title="", yaxis_title="findings raised")
    st.plotly_chart(fig, use_container_width=True)

    singles = mat[mat["agreement"] == 1]
    if not singles.empty:
        st.warning(
            f"**{len(singles)} finding(s) were caught by exactly one scanner.** "
            "Running a single tool would have missed them entirely - this is the "
            "evidence for a multi-tool pipeline."
        )
        st.dataframe(
            singles[["finding_id", "cloud", "severity", "title"]],
            use_container_width=True, hide_index=True,
            column_config={"finding_id": "ID", "title": "Finding"},
        )
