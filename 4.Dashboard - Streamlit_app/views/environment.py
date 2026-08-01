"""views/environment.py — resource inventory, health, drift and live toggles."""

from __future__ import annotations

import streamlit as st

from core import environment as env


def render() -> None:
    st.title("Environment")
    st.caption("Deployed resources, health, configuration drift and live misconfiguration toggles.")

    snaps = env.load_snapshots()
    if not snaps:
        st.info(
            "No environment snapshot found.\n\n"
            "Run **`python tools/snapshot_azure.py`** to capture your Azure "
            "environment to `data/azure_snapshot.json`, then click **Reload** in the "
            "sidebar. Your AWS teammate produces `data/aws_snapshot.json` in the same "
            "shape."
        )
        return

    s = env.summary(snaps)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Resources deployed", s["resources"])
    c2.metric("Healthy", s["healthy"])
    c3.metric("Drifted from code", s["drift_count"])
    c4.metric("Est. spend today", f"{s['currency']} {s['cost_today']:.0f}")
    if s["captured_at"]:
        st.caption(f"Snapshot captured {s['captured_at']} · re-run the snapshot script to refresh.")

    st.divider()
    left, right = st.columns([1.2, 1])

    with left:
        st.subheader("Resource inventory")
        res = env.resources_df(snaps)
        if res.empty:
            st.info("No resources in the snapshot.")
        else:
            st.dataframe(
                res[["cloud", "name", "type", "location", "state", "healthy", "tags"]],
                use_container_width=True, hide_index=True,
                column_config={
                    "healthy": st.column_config.CheckboxColumn("Healthy", disabled=True),
                    "location": "Region",
                },
            )

    with right:
        st.subheader("Configuration drift")
        dr = env.drift_df(snaps)
        if dr.empty:
            st.success("No drift detected — deployed state matches Terraform.")
        else:
            st.warning(f"{len(dr)} resource(s) changed outside Terraform.")
            for _, r in dr.iterrows():
                with st.container(border=True):
                    st.markdown(f"**{r['resource']}** · {r['cloud']}")
                    st.caption(f"{r['change']} — {r['detail']}")

        st.subheader("Misconfig toggles live now")
        tg = env.toggles_state(snaps)
        if tg.empty:
            st.info("No toggle state in the snapshot.")
        else:
            on_count = int(tg["on"].sum())
            st.caption(f"{on_count} of {len(tg)} toggles currently switched on.")
            st.dataframe(
                tg[["cloud", "toggle", "state"]],
                use_container_width=True, hide_index=True,
                column_config={"toggle": "Terraform variable", "state": "State"},
            )
