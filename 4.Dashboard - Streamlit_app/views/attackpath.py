"""views/attackpath.py - blast radius and attack-path chains."""

from __future__ import annotations

import streamlit as st

from core.catalogue import load_attack_paths
from core.loader import SEV_COLORS

_NODE_STYLE = {
    "entry":  ("#b3261e", "#ffffff"),
    "pivot":  ("#e8590c", "#ffffff"),
    "target": ("#7a1fa2", "#ffffff"),
}


def _dot(steps, open_ids: set) -> str:
    """
    Build a Graphviz DOT string for one attack path.
    Rendered client-side by Streamlit, so no graphviz binary is needed.
    """
    lines = [
        "digraph G {",
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [shape=box style="filled,rounded" fontname="Helvetica" '
        'fontsize=11 margin="0.22,0.14" penwidth=0];',
        '  edge [color="#8a8f98" penwidth=1.4 arrowsize=0.8];',
    ]
    prev = None
    for i, s in enumerate(steps.itertuples()):
        fill, fg = _NODE_STYLE.get(str(s.node_type).strip().lower(), ("#3d8bfd", "#ffffff"))
        live = str(s.finding_id).strip() in open_ids
        # Findings that are still open get a solid node; remediated ones are dimmed.
        if not live and str(s.finding_id).strip():
            fill, fg = "#2a2e37", "#8a8f98"
        label = str(s.node_label).replace('"', "'")
        fid = str(s.finding_id).strip()
        sub = f"\\n{fid}" if fid else ""
        nid = f"n{i}"
        lines.append(f'  {nid} [label="{label}{sub}" fillcolor="{fill}" fontcolor="{fg}"];')
        if prev is not None:
            lines.append(f"  {prev} -> {nid};")
        prev = nid
    lines.append("}")
    return "\n".join(lines)


def render(current) -> None:
    st.title("Attack paths")
    st.caption("How individual findings chain together into an exploitable route.")

    paths = load_attack_paths()
    if paths.empty:
        st.info(
            "No attack-path catalogue found. Create **catalogue/attack_paths.csv** "
            "describing each chain as ordered steps. "
            "See catalogue/README_catalogue.md for the columns."
        )
        return

    fails = current[current["status"] == "FAIL"] if not current.empty else current
    open_ids = set(fails["finding_id"].tolist()) if not fails.empty else set()

    # A path is "live" when every step that references a finding is still failing.
    summary = []
    for pid, grp in paths.groupby("path_id"):
        needed = {f for f in grp["finding_id"] if str(f).strip()}
        live_steps = len(needed & open_ids)
        summary.append({
            "path_id": pid,
            "path_name": grp["path_name"].iloc[0],
            "cloud": grp["cloud"].iloc[0],
            "severity": grp["severity"].iloc[0],
            "steps": len(grp),
            "live_steps": live_steps,
            "required": len(needed),
            "status": "Live" if needed and live_steps == len(needed) else "Broken",
        })

    import pandas as pd
    sm = pd.DataFrame(summary)
    live_count = int((sm["status"] == "Live").sum())

    c1, c2, c3 = st.columns(3)
    c1.metric("Paths catalogued", len(sm))
    c2.metric("Currently exploitable", live_count)
    c3.metric("Broken by remediation", len(sm) - live_count)

    if live_count:
        st.error(f"{live_count} attack path(s) are fully open right now - every step in "
                 "the chain has a failing finding behind it.")
    else:
        st.success("No path is fully open - at least one step in every chain is remediated.")

    st.divider()
    st.subheader("Path summary")
    st.dataframe(
        sm[["path_id", "path_name", "cloud", "severity", "steps", "live_steps",
            "required", "status"]],
        use_container_width=True, hide_index=True,
        column_config={
            "path_id": "ID", "path_name": "Attack path", "steps": "Steps",
            "live_steps": "Open steps", "required": "Steps needing a finding",
        },
    )

    st.subheader("Path detail")
    choice = st.selectbox(
        "Choose a path",
        sm["path_id"].tolist(),
        format_func=lambda p: f"{p} - {sm[sm['path_id'] == p]['path_name'].iloc[0]}",
    )
    steps = paths[paths["path_id"] == choice]
    row = sm[sm["path_id"] == choice].iloc[0]

    colour = SEV_COLORS.get(row["severity"], "#8a8f98")
    st.markdown(
        f"### {row['path_name']} "
        f"<span style='background:{colour};color:#fff;padding:2px 10px;"
        f"border-radius:10px;font-size:0.8rem'>{row['severity']}</span> "
        f"<span style='background:{'#b3261e' if row['status'] == 'Live' else '#2f9e44'};"
        f"color:#fff;padding:2px 10px;border-radius:10px;font-size:0.8rem'>{row['status']}</span>",
        unsafe_allow_html=True,
    )

    st.graphviz_chart(_dot(steps, open_ids), use_container_width=True)
    st.caption("Solid nodes are steps whose underlying finding is still failing. "
               "Dimmed nodes are already remediated - breaking any one of them breaks the chain.")

    st.markdown("**Steps**")
    for s in steps.itertuples():
        fid = str(s.finding_id).strip()
        live = fid in open_ids
        icon = "🔴" if live else ("⚪" if fid else "▫️")
        with st.container(border=True):
            st.markdown(f"{icon} **Step {s.step_order} · {s.node_label}**"
                        + (f" · `{fid}`" if fid else ""))
            st.caption(s.note)

    st.info(
        "**How to read this.** Each chain is only as strong as its weakest link - "
        "remediating any single step breaks the whole path. That makes shared steps "
        "the highest-value fixes in the backlog."
    )
