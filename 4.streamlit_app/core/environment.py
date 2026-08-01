"""
core/environment.py
===================
Reads environment snapshots produced by tools/snapshot_azure.py (and the
equivalent file your AWS teammate exports).

WHY A SNAPSHOT FILE INSTEAD OF LIVE CALLS
    Streamlit re-runs the whole script on every interaction. Calling Azure on
    each rerun would make the UI slow, hammer the API, and break entirely if
    the network is unavailable during a demo. So a helper script captures the
    environment to JSON, and the console reads that file - exactly the same
    pattern as the scan reports.

    Refresh the data by re-running the snapshot script, then clicking Reload
    in the sidebar.

Expected file shape (data/azure_snapshot.json):
{
  "cloud": "Azure",
  "captured_at": "2026-07-18 14:02:11",
  "subscription": "sub-0f3a2b",
  "estimated_cost": {"currency": "INR", "today": 74, "month_to_date": 1180},
  "resources": [
      {"name": "...", "type": "...", "location": "...",
       "state": "Running", "healthy": true, "tags": {"env": "lab"}}
  ],
  "drift": {"status": "drifted", "checked_at": "...",
            "changes": [{"resource": "...", "change": "...", "detail": "..."}]},
  "toggles": {"misconfig_storage_public_container": true, ...}
}
"""

from __future__ import annotations

import glob
import json
import os

import pandas as pd


def load_snapshots(data_dir: str = "data", pattern: str = "*_snapshot.json") -> list[dict]:
    """Load every environment snapshot found. Returns [] if none exist."""
    out = []
    for path in sorted(glob.glob(os.path.join(data_dir, pattern))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                snap = json.load(fh)
            snap["_file"] = os.path.basename(path)
            out.append(snap)
        except (json.JSONDecodeError, OSError):
            # A malformed snapshot should never take the dashboard down.
            continue
    return out


def resources_df(snapshots: list[dict]) -> pd.DataFrame:
    """Flatten all snapshots into one resource inventory table."""
    rows = []
    for snap in snapshots:
        for r in snap.get("resources", []):
            tags = r.get("tags") or {}
            rows.append({
                "cloud": snap.get("cloud", ""),
                "name": r.get("name", ""),
                "type": r.get("type", ""),
                "location": r.get("location", ""),
                "state": r.get("state", ""),
                "healthy": bool(r.get("healthy", True)),
                "tags": ", ".join(f"{k}={v}" for k, v in tags.items()),
            })
    return pd.DataFrame(rows)


def drift_df(snapshots: list[dict]) -> pd.DataFrame:
    """Flatten drift findings across snapshots."""
    rows = []
    for snap in snapshots:
        drift = snap.get("drift") or {}
        for c in drift.get("changes", []):
            rows.append({
                "cloud": snap.get("cloud", ""),
                "resource": c.get("resource", ""),
                "change": c.get("change", ""),
                "detail": c.get("detail", ""),
            })
    return pd.DataFrame(rows)


def toggles_state(snapshots: list[dict]) -> pd.DataFrame:
    """Current on/off state of every misconfiguration toggle."""
    rows = []
    for snap in snapshots:
        for name, on in (snap.get("toggles") or {}).items():
            rows.append({
                "cloud": snap.get("cloud", ""),
                "toggle": name,
                "state": "ON" if on else "off",
                "on": bool(on),
            })
    return pd.DataFrame(rows)


def summary(snapshots: list[dict]) -> dict:
    """Headline counts for the environment page."""
    res = resources_df(snapshots)
    dr = drift_df(snapshots)
    cost_today, currency = 0, "INR"
    for snap in snapshots:
        c = snap.get("estimated_cost") or {}
        cost_today += float(c.get("today", 0) or 0)
        currency = c.get("currency", currency)
    return {
        "resources": len(res),
        "healthy": int(res["healthy"].sum()) if not res.empty else 0,
        "unhealthy": int((~res["healthy"]).sum()) if not res.empty else 0,
        "drift_count": len(dr),
        "cost_today": cost_today,
        "currency": currency,
        "captured_at": snapshots[0].get("captured_at", "") if snapshots else "",
    }
