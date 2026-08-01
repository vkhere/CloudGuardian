# CloudGuardian Console

A local, cloud-agnostic **single pane of glass** for the CloudGuardian capstone.
It ingests your normalized CSPM reports from **Azure and AWS** across **Week 1,
Week 2 and Week 3**, and presents an enterprise-style security console with an
executive overview, a review-and-approval gate, a scan-history trend, a
compliance rollup, and an audit trail.

It runs entirely on your laptop (`localhost`). Nothing is published; your data
never leaves the machine.

## What each page shows

- **Executive overview** — open findings, critical+high count, % of checks
  passing, ISO 27001 and CIS gauges, the remediation gate funnel, severity and
  cloud breakdowns, and the top open risks.
- **Findings & approvals** — the open (FAIL) findings, a detail card per
  finding with the LLM remediation, and Approve / Reject / Mark-remediated
  buttons (the human-approval gate). `Flagged` LLM guidance shows a warning.
- **Scan history & trend** — failing checks over time per cloud (baseline →
  after-misconfig → after-remediation), the list of every scan run, and the
  Week 1 deliberate-misconfig catalogue.
- **Compliance posture** — ISO 27001 Annex A and CIS control rollup for the
  current view, with a DPDP crosswalk note.
- **Audit trail** — every decision, newest first, downloadable as CSV.

A **point-in-time** selector in the sidebar flips the whole console between
`Latest`, `Baseline`, `After misconfig`, and `After remediation` — so you can
show the "broken" state during a Week 1 demo and the "remediated" state for
Week 3, from the same app.

## The design idea

The console never reads raw scanner output. It reads **one normalized CSV
schema** (see `reports/README_reports.md`). Azure and AWS are just CSV files in
`reports/` that match that schema — adding a cloud or a new scan means adding a
file, not changing code.

```
Scanners ─► (Week 2 normalization) ─► reports/*.csv ─► CONSOLE
                                            ▲
                        your AWS teammate's reports drop in here
```

- **Reports = read-only input** (from your scanners + LLM step).
- **Decisions = state**, stored in `data/console.db` (SQLite), so approvals
  survive restarts and re-scans.

## Folder structure

```
cloudguardian-console/
├── app.py                     # entry point + sidebar + routing
├── core/
│   ├── loader.py              # schema + report ingestion + view selection
│   ├── metrics.py             # posture, trend, compliance calculations
│   └── database.py            # SQLite decisions + audit trail
├── views/
│   ├── overview.py  findings.py  trend.py  compliance.py  audit.py
├── tools/
│   └── generate_sample_reports.py
├── reports/                   # <- drop your normalized CSVs here
│   ├── *.csv  (sample Azure + AWS, Week 1–3)
│   └── README_reports.md      # the column contract
├── .streamlit/config.toml
├── requirements.txt
└── README.md
```

## Run it (Windows PowerShell)

```powershell
cd C:\projects\cloudguardian-console

python -m venv .venv
.\.venv\Scripts\Activate.ps1        # prompt shows (.venv)

pip install -r requirements.txt

# sample reports are already included; to regenerate them:
python tools\generate_sample_reports.py

streamlit run app.py
```

Opens at `http://localhost:8501`. Type your name in the sidebar to enable the
approval buttons. `Ctrl+C` in PowerShell stops it.

> Mac/Linux: activate with `source .venv/bin/activate`; everything else is the same.

## Plugging in your real data

1. Produce a normalized CSV per scan (see `reports/README_reports.md`).
2. Drop the CSVs in `reports/`. Delete the samples.
3. Click **🔄 Reload reports** in the sidebar.

Use the same `finding_id` for the same issue across scans so trends and
decisions line up.

## Where this sits in the capstone

This is the **observability** console — it records an approval; it does not
execute the fix. Actually flipping a setting is the separate remediation step
(an Azure Function triggered by an approved decision), which stays outside this
local app. Building infra and scans from the CLI first, then viewing them here,
keeps the console off your Week 1 critical path.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `streamlit : command not found` | Activate the venv, then reinstall. |
| "No reports found" | Ensure CSVs are in `reports/`, or run the generator, then Reload. |
| Edited a CSV, no change | Click **Reload reports** (reports are cached). |
| Buttons greyed out | Enter your name in the sidebar. |
| Reset all decisions | Close the app, delete `data/console.db`. |
| PowerShell blocks activate | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (once). |
