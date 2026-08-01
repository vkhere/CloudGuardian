"""
core/metrics.py
===============
Pure calculation helpers. No Streamlit, no I/O — just DataFrame in, numbers
out. Keeping the maths here (instead of inside the pages) means each figure
can be unit-tested and reused across views.
"""

from __future__ import annotations

import pandas as pd


def posture_summary(current: pd.DataFrame) -> dict:
    """Headline numbers for the current view (one scan per cloud)."""
    if current.empty:
        return {"checks": 0, "fails": 0, "pass_rate": 0.0, "crit_high": 0}
    scored = current[current["status"].isin(["PASS", "FAIL"])]
    checks = len(scored)
    fails = int((scored["status"] == "FAIL").sum())
    passes = checks - fails
    pass_rate = round(100 * passes / checks, 1) if checks else 0.0
    fdf = current[current["status"] == "FAIL"]
    crit_high = int(fdf["severity"].isin(["Critical", "High"]).sum())
    return {"checks": checks, "fails": fails, "passes": passes,
            "pass_rate": pass_rate, "crit_high": crit_high}


def severity_counts(fails: pd.DataFrame) -> pd.DataFrame:
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    if fails.empty:
        return pd.DataFrame(columns=["severity", "count"])
    s = fails["severity"].value_counts()
    s = s.reindex([o for o in order if o in s.index])
    return s.rename_axis("severity").reset_index(name="count")


def by_cloud(fails: pd.DataFrame) -> pd.DataFrame:
    s = fails["cloud"].value_counts()
    return s.rename_axis("cloud").reset_index(name="count")


def by_service(fails: pd.DataFrame) -> pd.DataFrame:
    g = fails.groupby(["service", "severity"]).size().reset_index(name="count")
    return g


def remediation_funnel(open_with_decisions: pd.DataFrame) -> dict:
    """How the open findings are moving through the approval gate."""
    if open_with_decisions.empty:
        return {"Pending": 0, "Approved": 0, "Rejected": 0, "Remediated": 0}
    counts = open_with_decisions["decision_status"].value_counts().to_dict()
    return {k: int(counts.get(k, 0)) for k in ["Pending", "Approved", "Rejected", "Remediated"]}


def trend_data(df: pd.DataFrame) -> pd.DataFrame:
    """FAIL counts per scan over time, per cloud — the Week 1->3 story."""
    if df.empty:
        return df
    fails = df[df["status"] == "FAIL"]
    g = (
        fails.groupby(["cloud", "scan_id", "scan_stage", "captured_at", "stage_rank"])
        .size()
        .reset_index(name="fails")
        .sort_values(["cloud", "captured_at"])
    )
    return g


def compliance_by_control(current: pd.DataFrame, framework: str = "iso_27001") -> pd.DataFrame:
    """
    For the current view, roll up pass/fail by control of a framework.
    A control is 'Fail' if ANY mapped check is failing (worst-case rollup).
    """
    if current.empty:
        return pd.DataFrame(columns=[framework, "result", "failing", "total"])
    scored = current[current["status"].isin(["PASS", "FAIL"])].copy()
    scored = scored[scored[framework].astype(str).str.strip() != ""]
    rows = []
    for ctrl, grp in scored.groupby(framework):
        total = len(grp)
        failing = int((grp["status"] == "FAIL").sum())
        rows.append(
            {framework: ctrl, "result": "Fail" if failing else "Pass",
             "failing": failing, "total": total}
        )
    out = pd.DataFrame(rows)
    return out.sort_values(["result", framework], ascending=[True, True])


def compliance_score(current: pd.DataFrame, framework: str = "iso_27001") -> float:
    """% of mapped controls currently passing."""
    tbl = compliance_by_control(current, framework)
    if tbl.empty:
        return 0.0
    passing = int((tbl["result"] == "Pass").sum())
    return round(100 * passing / len(tbl), 1)


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------

# Technique -> (tactic, readable name). Extend as your catalogue grows.
ATTCK_REFERENCE = {
    "T1190": ("Initial access", "Exploit public-facing application"),
    "T1110": ("Credential access", "Brute force"),
    "T1552": ("Credential access", "Unsecured credentials"),
    "T1078": ("Privilege escalation", "Valid accounts"),
    "T1530": ("Collection", "Data from cloud storage"),
    "T1005": ("Collection", "Data from local system"),
    "T1562": ("Defense evasion", "Impair defenses"),
    "T1486": ("Impact", "Data encrypted for impact"),
    "T1098": ("Persistence", "Account manipulation"),
}

TACTIC_ORDER = [
    "Initial access", "Credential access", "Privilege escalation",
    "Persistence", "Defense evasion", "Collection", "Impact",
]


def attck_matrix(fails: pd.DataFrame) -> pd.DataFrame:
    """
    One row per ATT&CK technique seen in the failing findings, with the tactic
    it belongs to and how many findings map to it.
    """
    if fails.empty:
        return pd.DataFrame(columns=["technique", "tactic", "name", "count", "findings"])
    rows = []
    for tech, grp in fails.groupby("mitre_attck"):
        code = str(tech).strip().split()[0] if str(tech).strip() else ""
        if not code:
            continue
        tactic, name = ATTCK_REFERENCE.get(code, ("Uncategorised", code))
        rows.append({
            "technique": code,
            "tactic": tactic,
            "name": name,
            "count": len(grp),
            "findings": ", ".join(grp["finding_id"].tolist()),
        })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    out["tactic_rank"] = out["tactic"].apply(
        lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
    return out.sort_values(["tactic_rank", "count"], ascending=[True, False])


# ---------------------------------------------------------------------------
# Cross-tool agreement
# ---------------------------------------------------------------------------

TOOLS = ["Prowler", "ScoutSuite", "Steampipe"]


def _tools_for_row(row) -> list[str]:
    """
    Which scanners detected this finding. Prefers the 'detected_by' column
    (pipe-separated); falls back to the single 'source_tool' value.
    """
    raw = str(row.get("detected_by", "") or "").strip()
    if raw:
        return [t.strip() for t in raw.split("|") if t.strip()]
    single = str(row.get("source_tool", "") or "").strip()
    return [single] if single else []


def crosstool_matrix(fails: pd.DataFrame) -> pd.DataFrame:
    """One row per finding with a boolean column per scanner and an agreement count."""
    if fails.empty:
        return pd.DataFrame(columns=["finding_id", "cloud", "title"] + TOOLS + ["agreement"])
    rows = []
    for _, r in fails.iterrows():
        detected = _tools_for_row(r)
        row = {
            "finding_id": r["finding_id"],
            "cloud": r["cloud"],
            "title": r["title"],
            "severity": r["severity"],
        }
        for t in TOOLS:
            row[t] = t in detected
        row["agreement"] = sum(1 for t in TOOLS if t in detected)
        rows.append(row)
    out = pd.DataFrame(rows)
    return out.sort_values(["agreement", "finding_id"], ascending=[False, True])


def crosstool_summary(matrix: pd.DataFrame) -> dict:
    if matrix.empty:
        return {"all_three": 0, "two": 0, "single": 0, "mean": 0.0}
    return {
        "all_three": int((matrix["agreement"] == 3).sum()),
        "two": int((matrix["agreement"] == 2).sum()),
        "single": int((matrix["agreement"] == 1).sum()),
        "mean": round(float(matrix["agreement"].mean()), 2),
    }


# ---------------------------------------------------------------------------
# Detection coverage (toggle traceability)
# ---------------------------------------------------------------------------

def coverage_table(toggles: pd.DataFrame, fails: pd.DataFrame) -> pd.DataFrame:
    """
    Join the deliberate-misconfiguration catalogue to the findings that were
    actually raised, so undetected toggles become visible.
    """
    if toggles.empty:
        return pd.DataFrame()
    raised = set(fails["finding_id"].tolist()) if not fails.empty else set()
    tool_lookup = {}
    if not fails.empty:
        for _, r in fails.iterrows():
            tool_lookup[r["finding_id"]] = ", ".join(_tools_for_row(r)) or "-"
    out = toggles.copy()
    out["detected"] = out["expected_finding"].apply(lambda f: f in raised)
    out["detected_by"] = out["expected_finding"].apply(lambda f: tool_lookup.get(f, "-"))
    return out


def coverage_summary(cov: pd.DataFrame) -> dict:
    if cov.empty:
        return {"total": 0, "detected": 0, "missed": 0, "pct": 0.0}
    total = len(cov)
    detected = int(cov["detected"].sum())
    return {
        "total": total,
        "detected": detected,
        "missed": total - detected,
        "pct": round(100 * detected / total, 1) if total else 0.0,
    }


# ---------------------------------------------------------------------------
# What-if remediation planner
# ---------------------------------------------------------------------------

def project_compliance(current: pd.DataFrame, fixed_ids: list[str],
                       framework: str = "iso_27001") -> float:
    """
    Recompute the compliance score as if the selected findings were fixed:
    flip their status from FAIL to PASS, then re-run the normal rollup.
    """
    if current.empty:
        return 0.0
    sim = current.copy()
    sim.loc[sim["finding_id"].isin(fixed_ids), "status"] = "PASS"
    return compliance_score(sim, framework)


def project_severity(fails: pd.DataFrame, fixed_ids: list[str]) -> dict:
    """Residual open findings by severity after the selected fixes."""
    if fails.empty:
        return {}
    remaining = fails[~fails["finding_id"].isin(fixed_ids)]
    return remaining["severity"].value_counts().to_dict()


def marginal_gain(current: pd.DataFrame, fails: pd.DataFrame,
                  framework: str = "iso_27001") -> pd.DataFrame:
    """
    For each open finding, how many compliance points fixing it alone would add.
    This is what turns a ranked backlog into a decision tool.
    """
    if fails.empty:
        return pd.DataFrame(columns=["finding_id", "title", "severity", "gain"])
    base = compliance_score(current, framework)
    rows = []
    for fid in fails["finding_id"]:
        gain = project_compliance(current, [fid], framework) - base
        row = fails[fails["finding_id"] == fid].iloc[0]
        rows.append({
            "finding_id": fid,
            "title": row["title"],
            "severity": row["severity"],
            "risk_score": int(row["risk_score"]),
            "gain": round(gain, 1),
        })
    return pd.DataFrame(rows).sort_values(["gain", "risk_score"], ascending=[False, False])


# ---------------------------------------------------------------------------
# LLM verification
# ---------------------------------------------------------------------------

def llm_stats(current: pd.DataFrame) -> dict:
    """Verification outcome counts and a hallucination rate."""
    if current.empty:
        return {"verified": 0, "needs_review": 0, "flagged": 0,
                "total": 0, "hallucination_rate": 0.0, "no_remediation": 0}
    vs = current["verification_status"].astype(str).str.strip().str.lower()
    verified = int((vs == "verified").sum())
    needs = int((vs == "needs review").sum())
    flagged = int((vs == "flagged").sum())
    total = verified + needs + flagged
    no_rem = int((current["remediation"].astype(str).str.strip() == "").sum())
    return {
        "verified": verified,
        "needs_review": needs,
        "flagged": flagged,
        "total": total,
        "hallucination_rate": round(100 * flagged / total, 1) if total else 0.0,
        "no_remediation": no_rem,
    }


def llm_confidence_breakdown(current: pd.DataFrame) -> pd.DataFrame:
    if current.empty:
        return pd.DataFrame(columns=["llm_confidence", "count"])
    s = current["llm_confidence"].replace("", "Unstated").value_counts()
    return s.rename_axis("llm_confidence").reset_index(name="count")


# ---------------------------------------------------------------------------
# Compliance crosswalk (ISO x CIS x DPDP)
# ---------------------------------------------------------------------------

def crosswalk(current: pd.DataFrame, dpdp_map: pd.DataFrame) -> pd.DataFrame:
    """
    One row per ISO control, showing the CIS controls that share the same
    findings, the DPDP obligation it supports, and the current pass/fail state.
    """
    if current.empty:
        return pd.DataFrame()
    scored = current[current["status"].isin(["PASS", "FAIL"])].copy()
    scored = scored[scored["iso_27001"].astype(str).str.strip() != ""]
    if scored.empty:
        return pd.DataFrame()

    dpdp_lookup = {}
    if not dpdp_map.empty:
        for _, r in dpdp_map.iterrows():
            dpdp_lookup[r["iso_27001"].strip()] = (r["dpdp_section"], r["dpdp_obligation"])

    rows = []
    for iso, grp in scored.groupby("iso_27001"):
        cis = sorted({c for c in grp["cis_control"] if str(c).strip()})
        failing = int((grp["status"] == "FAIL").sum())
        section, obligation = dpdp_lookup.get(str(iso).strip(), ("", ""))
        rows.append({
            "iso_27001": iso,
            "cis_control": ", ".join(cis) if cis else "-",
            "dpdp_section": section or "-",
            "dpdp_obligation": obligation or "-",
            "checks": len(grp),
            "failing": failing,
            "result": "Fail" if failing else "Pass",
        })
    return pd.DataFrame(rows).sort_values(["result", "iso_27001"], ascending=[True, True])
