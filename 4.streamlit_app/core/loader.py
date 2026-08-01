"""
core/loader.py
==============
Ingests every scan report you drop into the reports/ folder and normalizes
them into ONE cloud-agnostic table, so Azure and AWS findings from Week 1,
Week 2 and Week 3 all sit side by side in a single pane of glass.

MENTAL MODEL
------------
* A "report" = one CSV = one scan run, for one cloud, at one stage.
    e.g. azure Week-1 baseline, azure Week-1 after-misconfig, aws Week-3
    after-remediation, and so on. Drop as many as you like in reports/.
* Every row in a report is one check result (PASS / FAIL / MANUAL).
* The dashboard NEVER reads raw Prowler/ScoutSuite/Steampipe output. It reads
    this normalized schema. Your Week 2 "normalize into a schema" step is what
    produces these CSVs (your PowerShell catalogue generator already does this
    for Azure; the AWS teammate produces the same shape).

To add a cloud or a scan, you add a CSV — no dashboard code changes.
See reports/README_reports.md for the exact column contract.
"""

from __future__ import annotations

import glob
import os

import pandas as pd

# ---- scan-level metadata (describes the whole report) ----------------------
SCAN_COLUMNS = ["cloud", "week", "scan_stage", "scan_id", "captured_at"]

# ---- finding-level columns (one row = one check result) --------------------
FINDING_COLUMNS = [
    "finding_id",            # STABLE id for an issue, reused across scans
    "account_id",            # subscription id (Azure) / account id (AWS)
    "service",               # Storage, SQL, Network, IAM, KeyVault, S3, ...
    "resource_name",         # friendly resource name
    "region",                # location / region
    "check_id",              # scanner check id
    "title",                 # short human title
    "description",           # what the check evaluates
    "severity",              # Critical / High / Medium / Low / Informational
    "status",                # PASS / FAIL / MANUAL
    "source_tool",           # primary tool that raised it
    "detected_by",           # pipe-separated list, e.g. "Prowler|Steampipe"
    "risk_score",            # 0-100 from your Week 2 prioritization model
    "cvss",                  # optional numeric CVSS
    "exposure",              # optional: Public / Internal / Private
    "blast_radius",          # optional
    "remediation",           # plain-English remediation (LLM output)
    "llm_confidence",        # High / Medium / Low
    "verification_status",   # Verified / Needs Review / Flagged
    "iso_27001",             # ISO 27001 Annex A control
    "cis_control",           # CIS benchmark control
    "mitre_attck",           # MITRE ATT&CK technique
    "is_catalogued_misconfig",  # Yes = one of the deliberate Week-1 toggles
]

ALL_COLUMNS = SCAN_COLUMNS + FINDING_COLUMNS

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# Shared palette so every view colours things identically.
SEV_COLORS = {
    "Critical": "#b3261e",
    "High": "#e8590c",
    "Medium": "#f0a202",
    "Low": "#3d8bfd",
    "Informational": "#8a8f98",
}
STATUS_COLORS = {
    "Pending": "#8a8f98",
    "Approved": "#2f9e44",
    "Rejected": "#b3261e",
    "Remediated": "#3d8bfd",
}
STAGE_ORDER = {"Baseline": 0, "After misconfig": 1, "After remediation": 2}


def _std_cloud(v) -> str:
    if not isinstance(v, str):
        return ""
    return {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "oci": "OCI"}.get(
        v.strip().lower(), v.strip()
    )


def _std_severity(v) -> str:
    if not isinstance(v, str) or not v.strip():
        return "Informational"
    return {
        "critical": "Critical", "crit": "Critical",
        "high": "High",
        "medium": "Medium", "med": "Medium", "moderate": "Medium",
        "low": "Low",
        "informational": "Informational", "info": "Informational",
    }.get(v.strip().lower(), v.strip().title())


def _std_status(v) -> str:
    if not isinstance(v, str) or not v.strip():
        return "MANUAL"
    return {"pass": "PASS", "fail": "FAIL", "manual": "MANUAL", "info": "MANUAL"}.get(
        v.strip().lower(), v.strip().upper()
    )


def load_reports(reports_dir: str = "reports", pattern: str = "*.csv") -> pd.DataFrame:
    """Read + combine + normalize every report CSV. Empty frame if none found."""
    files = sorted(glob.glob(os.path.join(reports_dir, pattern)))
    if not files:
        return pd.DataFrame(columns=ALL_COLUMNS)

    frames = []
    for f in files:
        df = pd.read_csv(f, dtype=str, keep_default_na=False)
        df.columns = [c.strip() for c in df.columns]
        # If a report omitted scan metadata, infer cloud/stage from the filename.
        base = os.path.basename(f).lower()
        if "cloud" not in df.columns or (df.get("cloud", pd.Series()).eq("").all()):
            df["cloud"] = "AWS" if "aws" in base else ("Azure" if "azure" in base else "")
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)

    for col in ALL_COLUMNS:
        if col not in data.columns:
            data[col] = ""
    data = data[ALL_COLUMNS].copy()

    data["cloud"] = data["cloud"].apply(_std_cloud)
    data["severity"] = data["severity"].apply(_std_severity)
    data["status"] = data["status"].apply(_std_status)
    data["risk_score"] = pd.to_numeric(data["risk_score"], errors="coerce").fillna(0).astype(int)
    data["week"] = pd.to_numeric(data["week"], errors="coerce").fillna(0).astype(int)
    data["captured_at"] = pd.to_datetime(data["captured_at"], errors="coerce")
    data["severity_rank"] = data["severity"].map(SEVERITY_ORDER).fillna(9).astype(int)
    data["stage_rank"] = data["scan_stage"].map(STAGE_ORDER).fillna(9).astype(int)
    return data


def scan_catalogue(df: pd.DataFrame) -> pd.DataFrame:
    """One row per scan run: cloud, stage, when, and pass/fail counts."""
    if df.empty:
        return df
    d = df.copy()
    d["_fail"] = (d["status"] == "FAIL").astype(int)
    d["_pass"] = (d["status"] == "PASS").astype(int)
    g = d.groupby(
        ["cloud", "scan_id", "scan_stage", "week", "captured_at", "stage_rank"],
        as_index=False,
    ).agg(checks=("finding_id", "size"), fails=("_fail", "sum"), passes=("_pass", "sum"))
    return g.sort_values(["cloud", "captured_at"])


def latest_scan_ids(df: pd.DataFrame) -> dict:
    """Newest scan_id per cloud (by capture date)."""
    if df.empty:
        return {}
    idx = df.groupby("cloud")["captured_at"].idxmax()
    return df.loc[idx].set_index("cloud")["scan_id"].to_dict()


def select_view(df: pd.DataFrame, stage: str = "Latest") -> pd.DataFrame:
    """
    Return the rows the dashboard should treat as 'current'.

    stage = "Latest"  -> newest scan per cloud (default)
    stage = a name    -> that stage per cloud (Baseline / After misconfig /
                          After remediation), so you can flip the whole
                          console to any point in the story.
    """
    if df.empty:
        return df
    if stage == "Latest":
        keep = latest_scan_ids(df).values()
        return df[df["scan_id"].isin(keep)].copy()
    sub = df[df["scan_stage"] == stage]
    if sub.empty:  # fall back to latest if that stage doesn't exist
        return select_view(df, "Latest")
    # newest scan of that stage per cloud
    idx = sub.groupby("cloud")["captured_at"].idxmax()
    keep = sub.loc[idx, "scan_id"].tolist()
    return df[df["scan_id"].isin(keep)].copy()


def open_findings(current: pd.DataFrame) -> pd.DataFrame:
    """FAIL rows only — the issues that actually need review/remediation."""
    if current.empty:
        return current
    return (
        current[current["status"] == "FAIL"]
        .sort_values(["severity_rank", "risk_score"], ascending=[True, False])
        .copy()
    )
