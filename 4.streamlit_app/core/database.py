"""
core/database.py
================
Stores reviewer DECISIONS on top of the read-only findings, plus a full audit
trail. Findings come from CSV (input); decisions are state, so they live in a
small SQLite file (data/console.db) that survives restarts. This is the human
approval gate + audit history (Week 3 requirements).

Decisions are keyed by finding_id, which is STABLE across scans — so a decision
you make survives a re-scan of the same issue.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

import pandas as pd

DB_PATH = os.path.join("data", "console.db")
VALID_STATUSES = ["Pending", "Approved", "Rejected", "Remediated"]


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS decisions (
                   finding_id TEXT PRIMARY KEY,
                   status     TEXT NOT NULL,
                   approver   TEXT,
                   note       TEXT,
                   decided_at TEXT )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   finding_id TEXT,
                   action     TEXT,
                   actor      TEXT,
                   detail     TEXT,
                   timestamp  TEXT )"""
        )


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def record_decision(finding_id: str, status: str, approver: str, note: str = "") -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}")
    ts = _now()
    with _connect() as conn:
        conn.execute(
            """INSERT INTO decisions (finding_id, status, approver, note, decided_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(finding_id) DO UPDATE SET
                   status=excluded.status, approver=excluded.approver,
                   note=excluded.note, decided_at=excluded.decided_at""",
            (finding_id, status, approver, note, ts),
        )
        conn.execute(
            """INSERT INTO audit_log (finding_id, action, actor, detail, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (finding_id, status, approver, note, ts),
        )


def get_decisions_df() -> pd.DataFrame:
    with _connect() as conn:
        return pd.read_sql_query("SELECT * FROM decisions", conn)


def get_audit_df() -> pd.DataFrame:
    with _connect() as conn:
        return pd.read_sql_query(
            """SELECT timestamp, finding_id, action, actor, detail
               FROM audit_log ORDER BY id DESC""",
            conn,
        )


def attach_decisions(findings: pd.DataFrame) -> pd.DataFrame:
    """Left-join current decisions onto a findings frame (defaults to Pending)."""
    if findings.empty:
        return findings
    findings = findings.copy()
    d = get_decisions_df()
    if d.empty:
        findings["decision_status"] = "Pending"
        findings["approver"] = ""
        findings["decided_at"] = ""
        findings["note"] = ""
        return findings
    d = d.rename(columns={"status": "decision_status"})
    findings = findings.merge(
        d[["finding_id", "decision_status", "approver", "decided_at", "note"]],
        on="finding_id", how="left",
    )
    findings["decision_status"] = findings["decision_status"].fillna("Pending")
    for c in ["approver", "decided_at", "note"]:
        findings[c] = findings[c].fillna("")
    return findings
