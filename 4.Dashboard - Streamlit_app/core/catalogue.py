"""
core/catalogue.py
=================
Loads the three reference tables that sit alongside the scan reports:

  catalogue/toggles.csv       the deliberate misconfigurations you introduced
  catalogue/attack_paths.csv  ordered chains of findings (blast radius)
  catalogue/dpdp_map.csv      ISO 27001 control -> DPDP Act 2023 obligation

These are hand-maintained reference data, not scanner output. They are what
let the console answer questions the scanners cannot: "did we detect every
misconfiguration we introduced?", "what can an attacker chain together?", and
"which Indian data-protection obligation does this control support?".

All three are optional. If a file is missing the relevant page shows an
explanatory message instead of failing.
"""

from __future__ import annotations

import os

import pandas as pd

TOGGLE_COLUMNS = [
    "toggle_id",         # e.g. AZ-T01
    "cloud",             # Azure / AWS
    "toggle_name",       # terraform variable name, or "(no toggle)"
    "category",          # Identity / Storage / Network / Logging / Encryption
    "expected_finding",  # finding_id the scanners should raise
    "severity",
    "rationale",         # why this misconfiguration was introduced
    "revert",            # how to put it back
]

PATH_COLUMNS = [
    "path_id",       # e.g. AP-01
    "path_name",     # human name of the attack path
    "cloud",
    "severity",
    "step_order",    # 1, 2, 3 ...
    "node_label",    # what the node is called on the graph
    "node_type",     # entry / pivot / target
    "finding_id",    # the finding that enables this step (may be blank)
    "note",          # what the attacker does at this step
]

DPDP_COLUMNS = ["iso_27001", "dpdp_section", "dpdp_obligation"]


def _load(path: str, columns: list[str]) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame(columns=columns)
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df.columns = [c.strip() for c in df.columns]
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    return df[columns].copy()


def load_toggles(catalogue_dir: str = "catalogue") -> pd.DataFrame:
    return _load(os.path.join(catalogue_dir, "toggles.csv"), TOGGLE_COLUMNS)


def load_attack_paths(catalogue_dir: str = "catalogue") -> pd.DataFrame:
    df = _load(os.path.join(catalogue_dir, "attack_paths.csv"), PATH_COLUMNS)
    if not df.empty:
        df["step_order"] = pd.to_numeric(df["step_order"], errors="coerce").fillna(0).astype(int)
        df = df.sort_values(["path_id", "step_order"])
    return df


def load_dpdp_map(catalogue_dir: str = "catalogue") -> pd.DataFrame:
    return _load(os.path.join(catalogue_dir, "dpdp_map.csv"), DPDP_COLUMNS)
