<div align="center">

# 🛡️ CloudGuardian Console

### A single pane of glass for multi-cloud, multi-tool security posture

**Consolidates Prowler, ScoutSuite, and Steampipe findings across Azure and AWS into one
governance console - with cross-tool detection validation, ATT&CK mapping, a
privacy-preserving LLM assurance layer, and a human-approval remediation gate.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Azure](https://img.shields.io/badge/Azure-Reports-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](#)
[![AWS](https://img.shields.io/badge/AWS-Reports-232F3E?style=flat-square&logo=amazonaws&logoColor=white)](#)
[![CSPM](https://img.shields.io/badge/Category-CSPM-6A5ACD?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-Educational-lightgrey?style=flat-square)](#-license)
[![Status](https://img.shields.io/badge/Status-Capstone%20Project-orange?style=flat-square)](#)

<sub>Built for the IIT Roorkee × Futurense PG Certificate in AI/GenAI-Powered Cybersecurity - Capstone CAP-CSE-3W</sub>

</div>

<br/>

<div align="center">
<img src="docs/screenshots/executive-overview-latest.png" alt="CloudGuardian Console - Executive Overview" width="880"/>

<sub><i>Executive overview - latest scan across Azure and AWS: 6 open findings, ISO 27001 at 44.4%,
CIS at 64.3%, and the remediation-gate funnel showing all 6 findings still Pending.</i></sub>
</div>

<br/>

> **Scope note.** This README documents the console exactly as implemented. It does **not** claim automated
> remediation execution, a backend API, or live cloud SDK calls at runtime - the project deliberately does not
> include these (see [Design Principle](#-design-principle) and [Roadmap](#-roadmap-not-yet-built)).

---

## 📑 Table of Contents

- [Executive Summary](#-executive-summary)
- [Design Principle](#-design-principle)
- [Why This Console Exists](#-why-this-console-exists)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Data Flow](#-data-flow)
- [Technology Stack](#-technology-stack)
- [Console Walkthrough](#-console-walkthrough)
  - [Posture](#posture)
  - [Analysis](#analysis)
  - [Decide](#decide)
  - [Assurance](#assurance)
- [The Approval Gate](#-the-approval-gate--what-remediation-means-here)
- [Privacy-Preserving Redaction](#-privacy-preserving-redaction)
- [Compliance Mapping](#-compliance-mapping)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running Locally](#-running-locally)
- [Serving Over HTTPS](#-serving-over-https)
- [Bringing Your Own Data](#-bringing-your-own-data)
- [Configuration Reference](#-configuration-reference)
- [Troubleshooting](#-troubleshooting)
- [Roadmap (Not Yet Built)](#-roadmap-not-yet-built)
- [Lessons Learned](#-lessons-learned)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)

---

## 🎯 Executive Summary

Cloud security posture management tools produce a lot of output - CSV exports, JSON dumps, benchmark reports -
and very little of it is *reviewable* by a human on a deadline. CloudGuardian Console exists to close that gap
for a specific, common shape of problem: **you have run several scanners against several clouds, and you need
one screen that tells you what's wrong, how confident you should be about it, and what happens if you fix it.**

| Dimension | What the console delivers |
|---|---|
| **Technical** | Normalizes Prowler, ScoutSuite, and Steampipe output into one schema; reconciles them into a per-finding agreement matrix |
| **Operational** | A single approval workflow (approve / reject / mark remediated) with a persistent, timestamped audit trail |
| **Security** | ATT&CK technique mapping, attack-path chain visualization, and detection-coverage gap analysis against a known misconfiguration catalogue |
| **Governance** | ISO 27001 × CIS × DPDP Act 2023 crosswalk, with LLM-generated remediation guidance verified against raw scanner data before it's trusted |
| **Privacy** | A working tokenizer that strips subscription IDs, account numbers, ARNs, and other identifiers before any text reaches a language model |

The console is an **observability and decision-support layer**. It does not modify cloud infrastructure.

---

## 🧭 Design Principle

> **The console reads files. It does not scan, and it does not deploy.**

This is the single architectural decision everything else follows from, and it was made deliberately rather
than by omission:

- **Reports are read-only input.** Scan output lands in `reports/` as CSV. Adding a new cloud, a new scanner,
  or a new scan is a matter of dropping in a file that matches the schema - zero code changes.
- **State lives in one place.** Every reviewer decision (approve / reject / mark remediated) is written to a
  local SQLite database (`data/console.db`), independent of the source reports.
- **No write path to production.** The console has no credentials, no SDK client, and no code path that calls
  Azure, AWS, or any live API to change infrastructure. It cannot misconfigure - or fix - anything it observes.

This has a direct, practical consequence worth stating plainly: **"remediated" in this console is a review
status, not an executed action.** A reviewer marks a finding remediated after they (or a separate script) have
fixed it elsewhere. See [The Approval Gate](#-the-approval-gate--what-remediation-means-here) for exactly what
does and doesn't happen when a decision is recorded.

---

## 💡 Why This Console Exists

Every CSPM exercise eventually runs into the same three problems:

**One tool's output isn't trustworthy alone.** Different scanners implement different rule logic against the
same benchmark. A finding raised by only one of three tools is a different class of evidence than a finding
all three agree on - and most tooling doesn't surface that distinction at all.

**Findings without traceable context don't get prioritized well.** A CVSS score tells you almost nothing about
whether a finding is one step in a live attack chain or an isolated, low-blast-radius issue. Severity alone
flattens that difference.

**LLM-assisted remediation guidance needs a paper trail, not blind trust.** Generated explanations are useful
until one is wrong. The console treats every piece of generated guidance as a claim to be checked against the
raw finding it describes, before a reviewer ever sees it as trustworthy.

CloudGuardian Console addresses these three problems directly, at the scale of a lab environment - not by
promising automation it doesn't have.

---

## ⭐ Key Features

| Feature | Description | Why It Matters | Reads From |
|---|---|---|---|
| **Executive posture overview** | Open findings, severity mix, ISO/CIS compliance gauges, remediation-gate funnel | One screen for the current state | `reports/*.csv` |
| **Human approval gate** | Approve, reject, or mark remediated; every action timestamped | Remediation is a decision, not a black box | `data/console.db` |
| **Cross-tool agreement matrix** | Per-finding Prowler / ScoutSuite / Steampipe detection flags with an agreement count | Shows exactly which findings only one tool would have caught | `detected_by` column |
| **Detection coverage & gap analysis** | Joins your deliberate misconfiguration catalogue to what the scanners actually raised | Surfaces absence-of-control gaps no scanner flags | `catalogue/toggles.csv` |
| **ATT&CK coverage heatmap** | Open findings mapped to MITRE ATT&CK techniques and tactics | Reframes findings as adversary capability, not just a rule violation | `mitre_attck` column |
| **Attack-path / blast-radius graph** | Renders catalogued multi-step chains; marks a path "live" only while every step is still open | A chain breaks the instant any one step is fixed - shows which fixes matter most | `catalogue/attack_paths.csv` |
| **Remediation planner (what-if)** | Select candidate fixes; see projected ISO/CIS compliance and residual severity mix before acting | Turns a flat backlog into a ranked decision | Computed from current view |
| **LLM verification scorecard** | Verified / needs-review / flagged counts for every generated remediation | A hallucination rate, not a trust assumption | `verification_status`, `llm_confidence` |
| **Privacy-preserving redaction** | Live, working tokenizer for GUIDs, ARNs, account numbers, UPNs, IPs, resource names | Nothing reaches a model in plaintext, and it's provable, not asserted | `core/redaction.py` |
| **Compliance crosswalk** | ISO 27001 Annex A × CIS Benchmark × DPDP Act 2023, per control | One artifact instead of three separate mappings | `catalogue/dpdp_map.csv` |
| **Environment inventory & drift** | Resource health and Terraform drift from a point-in-time snapshot | Confirms deployed state still matches code | `data/*_snapshot.json` |
| **Point-in-time comparison** | Flips the entire console between Baseline / After-misconfig / After-remediation | Same views, three moments - the story, not just the ending | `scan_stage` column |
| **Executive PDF export** | One-click management summary: posture, top risks, compliance, coverage, gate status | A leave-behind document that needs no live console | `core/pdfreport.py` |
| **Audit trail** | Full history of who decided what, and when | Defensible, not just usable | `data/console.db` |

---

## 🏗️ Architecture

```mermaid
flowchart TB
    subgraph Input["📥 Read-only input - never written to"]
        R["reports/*.csv<br/>Prowler · ScoutSuite · Steampipe<br/>normalized schema"]
        C["catalogue/*.csv<br/>toggles · attack paths · DPDP map<br/>hand-maintained reference data"]
        S["data/*_snapshot.json<br/>Azure / AWS environment snapshot<br/>captured by a separate script"]
    end

    subgraph App["🖥️ CloudGuardian Console - Streamlit, runs locally"]
        L["core/loader.py<br/>schema validation · normalization"]
        M["core/metrics.py<br/>posture · compliance · cross-tool ·<br/>ATT&CK · coverage · what-if"]
        RD["core/redaction.py<br/>identifier tokenizer"]
        PDF["core/pdfreport.py<br/>executive summary generator"]
        V["14 views<br/>Posture · Analysis · Decide ·<br/>Assurance · Records"]
    end

    subgraph State["💾 Local state - the only thing the console writes"]
        DB[("data/console.db<br/>SQLite<br/>decisions + audit log")]
    end

    subgraph Human["👤 Reviewer"]
        U["Browser<br/>HTTP or self-signed HTTPS"]
    end

    R --> L
    C --> M
    S --> V
    L --> M --> V
    M --> RD --> V
    V <--> DB
    V --> PDF
    U <--> V

    style Input fill:#1a1d24,stroke:#2563eb,color:#e6e6e6
    style App fill:#1a1d24,stroke:#2563eb,color:#e6e6e6
    style State fill:#1a1d24,stroke:#e8590c,color:#e6e6e6
    style Human fill:#1a1d24,stroke:#2f9e44,color:#e6e6e6
```

> **What's deliberately absent from this diagram:** a backend API, a message queue, a remediation executor, and
> any live Azure/AWS SDK call. The console's only external I/O is reading files from local disk and rendering
> to a browser.

---

## 🔄 Data Flow

```mermaid
sequenceDiagram
    actor Reviewer
    participant Tools as Prowler / ScoutSuite / Steampipe
    participant Reports as reports/*.csv
    participant Console as CloudGuardian Console
    participant DB as data/console.db

    Note over Tools: Run independently, outside the console
    Tools->>Reports: Scanner output normalized to schema
    Reviewer->>Console: Open browser, select scan stage & filters
    Console->>Reports: Load + cache (st.cache_data)
    Console->>Console: Compute posture, compliance,<br/>cross-tool agreement, ATT&CK mapping
    Console-->>Reviewer: Render Executive Overview

    Reviewer->>Console: Open Findings & Approvals
    Console->>DB: Read existing decisions
    Console-->>Reviewer: Findings with current status
    Reviewer->>Console: Approve / Reject / Mark remediated
    Console->>DB: Write decision + timestamp + reviewer name
    Console->>DB: Append audit log entry
    Console-->>Reviewer: Updated funnel counts

    Note over Reviewer,DB: No step in this flow calls Azure or AWS
```

---

## 🧰 Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **UI framework** | [Streamlit](https://streamlit.io/) 1.40+ | Renders all 14 pages; handles routing, filters, session state |
| **Data handling** | [pandas](https://pandas.pydata.org/) | Loads, normalizes, and joins all CSV/JSON input |
| **Visualization** | [Plotly](https://plotly.com/python/) | Gauges, treemaps, bar charts, pie charts |
| **Graph rendering** | Streamlit's built-in Graphviz support (DOT syntax) | Attack-path chain diagrams - no external binary required |
| **PDF generation** | [ReportLab](https://www.reportlab.com/) | Executive summary export, built from primitives - no headless-browser or image-rendering dependency |
| **Local persistence** | Python `sqlite3` (standard library) | Decisions and audit trail |
| **HTTPS certificate** | [`cryptography`](https://cryptography.io/) | Generates a self-signed wildcard certificate for local TLS |
| **Runtime** | Python 3.10+ | - |

**Explicitly not in the stack:** Azure SDK for Python, Boto3, Azure Functions, AWS Lambda, Terraform (invoked
by the console), or any backend/API framework. The console consumes their *output*; it does not call them.

---

## 🖼️ Console Walkthrough

Fourteen pages, organized into five sidebar sections. Every screenshot below is a real capture of the running
console with its sample dataset - nothing has been staged or edited.

### Posture

<table>
<tr><td width="50%">

**Executive Overview - Baseline**
<img src="docs/screenshots/executive-overview-baseline.png" width="100%"/>
<sub>Before any misconfiguration is introduced: 2 open findings, ISO 27001 at 77.8%, CIS at 85.7% -
the healthy starting state.</sub>

</td><td width="50%">

**Executive Overview - After Misconfig**
<img src="docs/screenshots/executive-overview-after-misconfig.png" width="100%"/>
<sub>After the deliberate misconfigurations are applied: 15 open findings, 11 critical + high,
compliance collapses to 0% on both frameworks.</sub>

</td></tr>
<tr><td width="50%">

**Executive Overview - Latest (Post-Remediation)**
<img src="docs/screenshots/executive-overview-latest.png" width="100%"/>
<sub>Latest scan across both clouds: 6 open findings remain, ISO 27001 recovered to 44.4%,
CIS to 64.3%. All 6 findings are still Pending review.</sub>

</td><td width="50%">

**Findings & Approvals**
<img src="docs/screenshots/findings-approvals.png" width="100%"/>
<sub>The review gate. <code>AZ-NET-SSH-OPEN</code> selected: risk score 93, LLM-suggested fix,
CVSS/MITRE/ISO/CIS detail, and the Approve / Reject / Mark remediated controls.</sub>

</td></tr>
</table>

> Point-in-time comparison in practice - the same console, the same layout, three different moments in the
> Week 1 → Week 3 story, driven entirely by the **Point in time** selector in the sidebar.

### Analysis

<table>
<tr><td width="50%">

**Scan History & Trend**
<img src="docs/screenshots/scan-history-trend.png" width="100%"/>
<sub>Failing checks over time: Azure spikes from 2 → 9 after misconfiguration, then drops to 4 after
remediation. Every individual scan run is listed below with its pass/fail counts.</sub>

</td><td width="50%">

**ATT&CK Coverage**
<img src="docs/screenshots/attck-coverage.png" width="100%"/>
<sub>3 techniques observed across 3 tactics, mapped from 6 findings - T1110 (Brute force) dominates
Credential access, with T1078 in Privilege escalation and T1562 in Defense evasion.</sub>

</td></tr>
<tr><td width="50%">

**Cross-Tool Agreement**
<img src="docs/screenshots/cross-tool-agreement.png" width="100%"/>
<sub>Mean agreement 1.67 of 3. Two findings - <code>AZ-IAM-MI-MISSING</code> and
<code>AZ-VM-PWD-AUTH</code> - were caught by exactly one scanner (ScoutSuite), called out explicitly
as the evidence for running a multi-tool pipeline.</sub>

</td><td width="50%">

**Detection Coverage**
<img src="docs/screenshots/detection-coverage.png" width="100%"/>
<sub>15 of 16 deliberately introduced misconfigurations detected (93.8%). The one miss -
<code>AZ-SQL-TDE</code> - is a manual-verification item, listed with the reason no scanner would
have raised it.</sub>

</td></tr>
</table>

<div align="center">

**Attack Paths**
<img src="docs/screenshots/attack-paths.png" width="820"/>

<sub>4 catalogued chains, 0 currently exploitable. <code>AP-01</code> expanded: Internet →
<code>AZ-NET-SSH-OPEN</code> → Web VM → <code>AZ-VM-PWD-AUTH</code> → SQL database →
<code>AZ-SQL-FW-ALLOWALL</code>, each step captioned with what the attacker does at that stage.</sub>

</div>

### Decide

<div align="center">

**Remediation Planner**
<img src="docs/screenshots/remediation-planner.png" width="820"/>

<sub>Six candidate fixes ranked by projected compliance gain (+11.2 pts each). With none yet selected,
the gauge shows the current 44.4% ISO 27001 baseline and the unmodeled residual severity mix.</sub>

</div>

### Assurance

<table>
<tr><td width="50%">

**Compliance Posture**
<img src="docs/screenshots/compliance-posture.png" width="100%"/>
<sub>ISO 27001 Annex A tab: 4 of 9 controls passing (44.4%). Network security and access control
controls are failing; logging, cryptography, and access restriction are passing.</sub>

</td><td width="50%">

**LLM Verification**
<img src="docs/screenshots/llm-verification.png" width="100%"/>
<sub>13 verified, 1 needs review, 2 flagged - a 12.5% flagged rate. Both flagged items
(<code>AWS-IAM-ADMIN</code>, <code>AZ-KV-PUBLIC</code>) are listed with the generated guidance that
triggered the flag.</sub>

</td></tr>
</table>

<div align="center">

**Privacy & Redaction**
<img src="docs/screenshots/redaction-viewer.png" width="820"/>

<sub>A real finding prompt tokenized live: subscription ID, resource name, and reporter email replaced
with <code>&lt;ACCT_001&gt;</code>, <code>&lt;RES_001&gt;</code>, and <code>&lt;UPN_001&gt;</code>.
4 identifiers tokenized, 0 leaked - confirmed by the leak check.</sub>

</div>

---

## 🔁 The Approval Gate - what "remediation" means here

This section exists because the word "remediation" is easy to over-read, and precision matters for a
security tool.

```mermaid
flowchart LR
    A["Finding is open<br/>(status: FAIL)"] --> B{"Reviewer decision<br/>on Findings & Approvals page"}
    B -->|Approve| C["Recorded as Approved<br/>+ timestamp + reviewer"]
    B -->|Reject| D["Recorded as Rejected<br/>+ timestamp + reviewer"]
    B -->|Mark remediated| E["Recorded as Remediated<br/>+ timestamp + reviewer"]
    C --> F["Written to data/console.db"]
    D --> F
    E --> F
    F --> G["Audit log entry appended"]
    G --> H["Funnel counts update<br/>on next page load"]

    style A fill:#3a1f1f,stroke:#b3261e,color:#fff
    style H fill:#1a3a1f,stroke:#2f9e44,color:#fff
```

**What actually happens when you click "Mark remediated":** a row is written to a local SQLite table.
Nothing is called on Azure or AWS. The fix itself - editing a Terraform toggle, changing a firewall rule,
rotating a key - happens separately, by the reviewer, using their own tooling. The console's job is to make
that decision reviewable and auditable, not to perform it. The Findings & Approvals screenshot above shows
this exactly: the decision buttons sit next to raw finding detail, not next to any "run fix" control.

This is a design boundary, not a gap discovered late: see [Design Principle](#-design-principle).

---

## 🔒 Privacy-Preserving Redaction

Before any finding text is framed as an LLM prompt, `core/redaction.py` tokenizes it. This is implemented,
tested, and demonstrable on the **Privacy & Redaction** page - see the screenshot above, not a
described-but-unbuilt feature.

**What it catches**, in fixed pass order (most specific first, so overlapping values can't be partially
replaced):

| Pattern | Example | Token |
|---|---|---|
| AWS ARN | `arn:aws:iam::111122223333:role/svc-deploy` | `<ARN_001>` |
| Azure GUID (subscription / tenant / object ID) | `010fdff4-2484-41a0-be8b-fccd3e3af6da` | `<GUID_001>` |
| AWS account number | `111122223333` | `<ACCT_001>` |
| AWS access key ID | `AKIAIOSFODNN7EXAMPLE` | `<AKID_001>` |
| User principal name / email | `kedar.pavaskar@techm.com` | `<UPN_001>` |
| IP address / CIDR | `203.0.113.45/32` | `<IP_001>` |
| Azure resource hostname | `stcloudguardianlab.blob.core.windows.net` | `<HOST_001>` |
| Resource name (caller-supplied) | `stcloudguardianlab` | `<RES_001>` |

Guarantees, verified in `core/redaction.py`'s own test path:

- **Deterministic** - the same value always maps to the same token within a session
- **Reversible, locally only** - `Redactor.restore()` puts originals back; the mapping is never transmitted
- **Leak-checked** - `leak_check()` confirms no original value survives into the redacted text

---

## 📋 Compliance Mapping

The **Compliance posture** page's third tab produces a control-level crosswalk:

```
ISO 27001 Annex A control  →  shared CIS Benchmark controls  →  DPDP Act 2023 obligation  →  current status
```

Sourced from `catalogue/dpdp_map.csv`. Because the DPDP Act 2023 does not itself enumerate technical
controls, the mapping is presented as an **argued link** between each technical control and a statutory
obligation (e.g., Section 8(5)'s "reasonable security safeguards" requirement) - not as a certified legal
mapping. The console states this explicitly on the page itself.

---

## 📂 Project Structure

```
cloudguardian-console/
├── app.py                        # Entry point - sidebar, routing, filters, point-in-time selector
│
├── core/                         # Business logic, no UI code
│   ├── loader.py                 #   Report schema, normalization, view selection
│   ├── metrics.py                #   Posture, compliance, cross-tool, ATT&CK, coverage, what-if
│   ├── catalogue.py              #   Loads toggles / attack_paths / dpdp_map reference data
│   ├── environment.py            #   Reads environment snapshots (inventory, drift, cost)
│   ├── database.py               #   SQLite: decisions + audit log
│   ├── redaction.py              #   Identifier tokenizer for the privacy page
│   └── pdfreport.py              #   Executive PDF builder (ReportLab)
│
├── views/                        # One file per page, imported by app.py
│   ├── overview.py  findings.py  environment.py  trend.py
│   ├── mitre.py  crosstool.py  coverage.py  attackpath.py
│   ├── planner.py  compliance.py  llm_assurance.py  redaction_view.py
│   └── audit.py  export.py
│
├── reports/                      # READ-ONLY scan input (drop your own CSVs here)
│   ├── azure_w1_baseline.csv
│   ├── azure_w1_after-misconfig.csv
│   ├── azure_w3_after-remediation.csv
│   ├── aws_w1_baseline.csv / aws_w1_after-misconfig.csv / aws_w3_after-remediation.csv
│   └── README_reports.md         #   Full column contract
│
├── catalogue/                    # READ-ONLY reference data, hand-maintained
│   ├── toggles.csv               #   Your deliberate misconfigurations + expected finding IDs
│   ├── attack_paths.csv          #   Ordered chains of findings (blast radius)
│   ├── dpdp_map.csv              #   ISO 27001 control → DPDP Act 2023 obligation
│   └── README_catalogue.md
│
├── data/                         # Runtime state - NOT input
│   ├── console.db                #   SQLite: decisions + audit trail (gitignored)
│   ├── azure_snapshot.json       #   Environment snapshot (gitignored - may contain subscription IDs)
│   └── aws_snapshot.json
│
├── docs/screenshots/             # Real console captures used in this README
│
├── tools/                        # Standalone scripts, run manually, never imported by app.py
│   ├── generate_sample_reports.py
│   ├── generate_catalogue.py
│   ├── snapshot_azure.py         #   Read-only az CLI + terraform plan calls
│   └── make_certs.py             #   Self-signed wildcard certificate generator
│
├── certs/                        # TLS material (gitignored - private key never committed)
├── run_https.ps1 / run_https.sh  # HTTPS launchers
├── .streamlit/config.toml        # Theme (SSL paths deliberately not set here)
├── requirements.txt
└── .gitignore
```

---

## ⚙️ Installation

**Prerequisites**

| Requirement | Check | If missing |
|---|---|---|
| Python 3.10+ | `python --version` | Install from [python.org](https://www.python.org/), tick "Add to PATH" |
| pip | `python -m pip --version` | Reinstall Python with default options |

**Setup**

```powershell
git clone <your-repo-url> cloudguardian-console
cd cloudguardian-console

python -m venv .venv
.\.venv\Scripts\Activate.ps1          # macOS/Linux: source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## ▶️ Running Locally

```powershell
# Load the sample dataset (skip once you're using real scan output)
python tools\generate_sample_reports.py
python tools\generate_catalogue.py

# Start
python -m streamlit run app.py
```

Open **http://localhost:8501**. The sidebar's top control is a **Section** dropdown - Posture, Analysis,
Decide, Assurance, Records - each revealing its own set of pages below it, as shown throughout the
[Console Walkthrough](#-console-walkthrough) above.

---

## 🔐 Serving Over HTTPS

The console runs over plain HTTP by default. To serve it over TLS with a self-signed wildcard certificate:

```powershell
python tools\make_certs.py
```

> **Why self-signed:** a public certificate authority will only issue a wildcard certificate for a domain
> you can prove you own via a DNS challenge. No CA will ever issue one for `localhost` or a private hostname.
> This generates a certificate for `*.cloudguardian.local`, valid once you trust it locally - the encryption
> is identical to a publicly-trusted certificate; only the identity attestation differs.

```powershell
# One-time, as Administrator
Import-Certificate -FilePath ".\certs\cloudguardian.crt" -CertStoreLocation Cert:\LocalMachine\Root
Add-Content C:\Windows\System32\drivers\etc\hosts "`n127.0.0.1  console.cloudguardian.local"

# Every session, as your normal user
.\run_https.ps1
```

Browse to **https://console.cloudguardian.local:8501**.

---

## 📥 Bringing Your Own Data

Replace the sample files - the console reads whatever matches the schema, filename is irrelevant.

**Reports** (`reports/*.csv`) - required columns include `cloud`, `scan_stage`, `finding_id`, `severity`,
`status`, `source_tool`, `risk_score`; optional columns `detected_by`, `iso_27001`, `cis_control`,
`mitre_attck`, `remediation`, `verification_status` unlock the cross-tool, compliance, ATT&CK, and LLM
assurance pages respectively. Full contract in `reports/README_reports.md`.

**Catalogue** (`catalogue/*.csv`) - optional. Missing files simply make the dependent page show an
explanation instead of failing. Full contract in `catalogue/README_catalogue.md`.

**Environment snapshot** (`data/*_snapshot.json`) - generate with:

```powershell
python tools\snapshot_azure.py --resource-group rg-cloudguardian-lab --terraform-dir <path>
```

Every call this script makes is read-only (`az` CLI queries, `terraform plan -detailed-exitcode`); nothing
is applied.

---

## 🔧 Configuration Reference

| Setting | Where | Notes |
|---|---|---|
| Theme colors | `.streamlit/config.toml` | Dark theme, primary `#2563eb` |
| SSL certificate paths | **Not** in config.toml, by design | Passed as CLI flags via `run_https.ps1` so plain HTTP always works even without certs |
| Decisions database | `data/console.db` | Auto-created on first run; delete to reset all decisions |
| ATT&CK technique dictionary | `core/metrics.py` → `ATTCK_REFERENCE` | Extend as your catalogue grows |

No environment variables, no cloud credentials, and no secrets are required to run the console itself -
it has no code path that authenticates to Azure or AWS. `tools/snapshot_azure.py` is the one script that
does, and it reuses your existing `az login` session; it is never imported by `app.py`.

---

## 🩹 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No module named streamlit` | Virtual environment not active in this shell | `.\.venv\Scripts\Activate.ps1`, confirm prompt shows `(.venv)` |
| Browser shows old pages after an update | Cached tab / stale run | Close all `localhost:8501` tabs, hard-reload with Ctrl+Shift+R |
| `pip` fails with a path that doesn't exist | venv created twice, stale launcher | `python -m pip install -r requirements.txt` instead of bare `pip` |
| Certificate warning over HTTPS | Not yet imported to Trusted Root | Re-run `Import-Certificate` as Administrator, close all browser windows |
| "No reports found" | Empty `reports/` folder | `python tools\generate_sample_reports.py`, then click **Reload data** |
| Detection coverage page is empty | `catalogue/toggles.csv` missing | `python tools\generate_catalogue.py` |

---

## 🗺️ Roadmap (Not Yet Built)

Listed explicitly so scope is never ambiguous. None of the following exist in the current codebase:

- **Automated remediation execution** (Azure Function / Lambda triggered by an approved decision)
- **Backend API** between the dashboard and any cloud provider
- **Live SDK calls** (Azure SDK for Python, Boto3) at runtime
- **Multi-user authentication / RBAC** - currently a free-text reviewer name field
- **Azure-hosted deployment** (Container Apps + managed identity + Entra ID Easy Auth) - architecture is
  understood and documented separately; not deployed
- Notifications, SSO, multi-cloud beyond Azure/AWS, predictive analytics

---

## 📚 Lessons Learned

- **Multi-tool CSPM only pays off if disagreement is visible.** Consolidating Prowler, ScoutSuite, and
  Steampipe into one schema wasn't the hard part - surfacing *which* findings only one tool caught (the
  Cross-Tool Agreement screenshot above shows 2 such findings) is what makes the multi-tool approach
  defensible rather than just redundant.
- **"Detected" and "existing" are different failure modes.** CSPM rules assert on what's present, not what's
  missing. The Detection Coverage page exists specifically because absence-of-control gaps (no managed
  identity, no alert rule) don't get raised by any scanner and need a separate catalogue to even notice.
- **LLM output needs a verification status, not a confidence label alone.** "High confidence" and "verified
  against raw scanner data" are different claims. The LLM Verification page's 12.5% flagged rate is the
  concrete evidence that treating them as the same thing is how hallucinated remediation guidance reaches
  a reviewer.
- **A read-only architecture is a security property, not just a simplification.** The console cannot
  misconfigure anything it observes, precisely because it has no write path to the environments it reports on.

---

## 📄 License

Educational / academic use - produced as a capstone deliverable for the IIT Roorkee × Futurense PG
Certificate in AI/GenAI-Powered Cybersecurity.

---

## 🙏 Acknowledgements

- **Prowler**, **ScoutSuite**, and **Steampipe** - the open-source CSPM tools this console consolidates output from
- **MITRE ATT&CK** - technique and tactic reference used in the coverage mapping
- IIT Roorkee × Futurense, PG Certificate Program in AI/GenAI-Powered Cybersecurity, Cohort 1

</div>
