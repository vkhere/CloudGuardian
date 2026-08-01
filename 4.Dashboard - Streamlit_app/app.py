"""
CloudGuardian Console - single pane of glass for Azure + AWS
============================================================
Runs locally on your laptop. Reads normalized scan reports from reports/,
reference data from catalogue/, environment snapshots from data/, and stores
reviewer decisions in data/console.db.

    HTTP :  streamlit run app.py
    HTTPS:  .\\run_https.ps1        (see the setup guide, HTTPS chapter)
"""

from __future__ import annotations

import streamlit as st

from core import loader
from core.database import attach_decisions, init_db
from views import (
    attackpath, audit, compliance, coverage, crosstool, environment, export,
    findings, llm_assurance, mitre, overview, planner, redaction_view, trend,
)

st.set_page_config(page_title="CloudGuardian Console", page_icon="🛡️", layout="wide")
init_db()

# Pages are grouped so the sidebar stays readable as the console grows.
PAGES = {
    "Posture": ["Executive overview", "Findings & approvals", "Environment"],
    "Analysis": ["Scan history & trend", "ATT&CK coverage", "Cross-tool agreement",
                 "Detection coverage", "Attack paths"],
    "Decide": ["Remediation planner"],
    "Assurance": ["Compliance posture", "LLM verification", "Privacy & redaction"],
    "Records": ["Audit trail", "Export"],
}


@st.cache_data(show_spinner=False)
def _load():
    return loader.load_reports()


# ---------------------------------------------------------------- sidebar
st.sidebar.title("🛡️ CloudGuardian")
st.sidebar.caption("Single pane of glass · Azure + AWS")

group = st.sidebar.selectbox("Section", list(PAGES.keys()), label_visibility="collapsed")
page = st.sidebar.radio("Page", PAGES[group], label_visibility="collapsed")

st.sidebar.divider()
approver = st.sidebar.text_input("Your name (reviewer)", value=st.session_state.get("approver", ""))
st.session_state["approver"] = approver

if st.sidebar.button("🔄 Reload data"):
    _load.clear()
    st.rerun()

df_all = _load()

if df_all.empty:
    st.warning(
        "No reports found. Drop normalized scan CSVs into the **reports/** folder "
        "(see reports/README_reports.md), or run "
        "`python tools/generate_sample_reports.py` to load the sample data, then "
        "click **Reload data**."
    )
    st.stop()

# --- point-in-time selector: flip the whole console to any stage of the story ---
st.sidebar.divider()
st.sidebar.subheader("Point in time")
stage = st.sidebar.radio(
    "Scan stage",
    ["Latest", "Baseline", "After misconfig", "After remediation"],
    help="Latest = newest scan per cloud. Pick a stage to view that moment across all clouds.",
    label_visibility="collapsed",
)

current = loader.select_view(df_all, stage)

# --- filters ---
st.sidebar.subheader("Filters")
clouds = sorted([c for c in current["cloud"].unique() if c])
sel_cloud = st.sidebar.multiselect("Cloud", clouds, default=clouds)
services = sorted([s for s in current["service"].unique() if s])
sel_service = st.sidebar.multiselect("Service", services, default=services)

current = current[current["cloud"].isin(sel_cloud) & current["service"].isin(sel_service)].copy()

open_f = loader.open_findings(current)
open_dec = attach_decisions(open_f)
view_label = "Latest scan per cloud" if stage == "Latest" else stage

# ---------------------------------------------------------------- routing
if page == "Executive overview":
    overview.render(current, open_dec, df_all, view_label)
elif page == "Findings & approvals":
    findings.render(open_dec, approver)
elif page == "Environment":
    environment.render()
elif page == "Scan history & trend":
    trend.render(df_all)
elif page == "ATT&CK coverage":
    mitre.render(current, view_label)
elif page == "Cross-tool agreement":
    crosstool.render(current, view_label)
elif page == "Detection coverage":
    coverage.render(df_all, current)
elif page == "Attack paths":
    attackpath.render(current)
elif page == "Remediation planner":
    planner.render(current, view_label)
elif page == "Compliance posture":
    compliance.render(current, view_label)
elif page == "LLM verification":
    llm_assurance.render(current, view_label)
elif page == "Privacy & redaction":
    redaction_view.render(current)
elif page == "Audit trail":
    audit.render()
elif page == "Export":
    export.render(current, open_dec, df_all, view_label)

st.sidebar.divider()
st.sidebar.caption("Reports and catalogue are read-only input. "
                   "Decisions persist in data/console.db.")
