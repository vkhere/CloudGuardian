![CloudGuardian](images/slide-01.jpg)

# CloudGuardian

**AI-Assisted Cloud Security Posture Management on Microsoft Azure & AWS**

![Framework](https://img.shields.io/badge/Frameworks-ISO%2027001%20%C2%B7%20CIS%20%C2%B7%20NIST%20CSF%20%C2%B7%20DPDP-1E2761?style=flat-square) ![Cloud](https://img.shields.io/badge/Cloud-Azure%20%7C%20AWS-0078D4?style=flat-square) ![Status](https://img.shields.io/badge/Status-Capstone%20Complete-2C5F2D?style=flat-square)

> Capstone Project — IIT Roorkee × Futurense, Cloud Security Essentials Track
> Team CyberSentinel: **Kedar Pavaskar · Vinay Kumar · Megha Sharma**

An end-to-end, closed-loop CSPM (Cloud Security Posture Management) capability: a real 3-tier cloud workload is deliberately broken with 16 controlled misconfigurations, detected by three independent scanners, triaged with a RAG-grounded and verified LLM, and remediated through a human-governed, ISO 27001-traceable pipeline — built at individual, free-tier scale.

---

## At a Glance

| | | | |
|---|---|---|---|
| **16** controlled misconfigurations | **83** Prowler findings | **68** confirmed FAILs | **82%** open-finding reduction |
| 2× the individual-track minimum | against the broken baseline | triaged, scored & governed | 68 → 12, end to end |

**The loop:** `Build & Break → Detect → Decide → Remediate → Re-verify` — proven achievable at free-tier scale, every control traceable to ISO 27001 Annex A, CIS Benchmarks, and India's DPDP Act 2023.

---

## Table of Contents

- [Part 1 — Executive Briefing (Main Deck, 29 slides)](#part-1--executive-briefing-main-deck)
  - [01 · The Business Problem](#01--the-business-problem)
  - [02–03 · Architecture & Technology](#0203--architecture--technology)
  - [04 · Implementation — Break · Reason · Govern](#04--implementation--break--reason--govern)
  - [05 · Controls & Framework Alignment](#05--controls--framework-alignment)
  - [06 · Results & Business Value](#06--results--business-value)
  - [08 · Executive Close](#08--executive-close)
- [Part 2 — Appendix / Backup Slides (9 slides)](#part-2--appendix--backup-slides)

---

## Part 1 — Executive Briefing (Main Deck)

### 01 · The Business Problem

#### Slide 1 — Title: CloudGuardian
![Slide 1](images/slide-01.jpg)
Executive briefing framing — a 15–20 minute deck-driven readout, not a lab walkthrough. The deck itself is the evidence.

#### Slide 2 — Executive Summary
![Slide 2](images/slide-02.jpg)
The whole engagement on one slide: **Build & Break → Detect → Decide → Remediate**, backed by the headline numbers (16 flaws, 83 findings, 68 confirmed FAILs, full ISO 27001/CIS/DPDP traceability).

#### Slide 3 — Why Manual Review Fails at Cloud Scale
![Slide 3](images/slide-03.jpg)
A point-in-time audit is stale the day it's published. Positions CloudGuardian as the CSPM core within the broader CNAPP market (CIEM, DSPM, attack-path analysis as future extension rings).

---

### 02–03 · Architecture & Technology

#### Slide 4 — Overall Solution Architecture
![Slide 4](images/slide-04.jpg)
The single most important visual: a **closed loop**, not a collection of scripts — Workload → CSPM Scanners → Canonical Findings → Prioritize + Explain → Approval Dashboard → Remediate + Audit, re-scanning continuously.

#### Slide 5 — Cloud Agnostic Workload Architecture
![Slide 5](images/slide-05.jpg)
The real 3-tier lab environment (web tier, data tier, storage, logging) provisioned via 11-file modular Terraform, plus the full technology stack: IaC, CSPM tooling, cloud-native signal, intelligence layer, governance console, and automation.

#### Slide 6 — Why Three Scanners, Not One
![Slide 6](images/slide-06.jpg)
Triangulation with **Prowler** (breadth), **ScoutSuite** (independent cross-check), and **Steampipe** (SQL + CIS benchmark validation) — plus the Azure and AWS event-driven remediation paths side by side.

#### Slide 7 — Findings Consolidation: One Canonical Schema
![Slide 7](images/slide-07.jpg)
The decision that makes the pipeline cloud-agnostic — three raw formats normalize into one schema. Includes the prioritization formula: **Priority Score = CVSS × Exposure × Blast Radius**.

#### Slide 8 — How RAG Grounds the Prioritization Engine
![Slide 8](images/slide-08.jpg)
A 6-step RAG pipeline: 25-chunk knowledge base (CIS, MCSB, ISO 27001, DPDP, HIPAA) → hybrid TF-IDF + embedding retrieval → grounded LLM generation → semantic verification (cosine similarity ≥ 0.55) → full audit trail.

#### Slide 9 — Event-Driven Remediation Architecture
![Slide 9](images/slide-09.jpg)
Severity-based routing: low/medium findings auto-remediate via Function App; high/critical route through a Logic App human-approval gate — all logged to Log Analytics with daily drift re-checks.

#### Slide 10 — Human-in-the-Loop Governance Console
![Slide 10](images/slide-10.jpg)
A three-page Streamlit operator console: **Overview** (posture at a glance), **Findings & Approvals** (approve/reject each fix), **Audit Trail** (immutable decision record).

---

### 05 · Controls & Framework Alignment (Slides 11, 16–19)

#### Slide 11 — Multi-Framework Compliance Crosswalk
![Slide 11](images/slide-11.jpg)
Direct traceability from every CloudGuardian control to ISO 27001 Annex A, CIS Benchmarks, and DPDP Act 2023 / Rules 2025 — the slide clients care about most.

#### Slide 16 — ISO 27001 Annex A Compliance Crosswalk
![Slide 16](images/slide-16.jpg)
The individual-track scope, drilled into exact Annex A references — storage, IAM, encryption, networking, logging, and remediation governance.

#### Slide 17 — CIS Benchmark Alignment
![Slide 17](images/slide-17.jpg)
Findings cross-validated against the CIS Microsoft Azure Foundations Benchmark via Steampipe's compliance mod — a benchmark-native second opinion.

#### Slide 18 — MITRE ATT&CK Technique Mapping
![Slide 18](images/slide-18.jpg)
Every misconfiguration mapped to a real attacker technique (T1530, T1133, T1190, T1110, T1078, T1562) — thinking like an attacker, not just a checklist auditor.

#### Slide 19 — Risk Reduction Heat Map
![Slide 19](images/slide-19.jpg)
Before/after severity intensity by domain — Networking and Storage carried the most risk, and cooled the most after remediation.

---

### 04 · Implementation — Break · Reason · Govern (Slide 25)

#### Slide 20–24 — Market Landscape Build (CSPM → CNAPP)
![Slide 20](images/slide-20.jpg) ![Slide 21](images/slide-21.jpg) ![Slide 22](images/slide-22.jpg) ![Slide 23](images/slide-23.jpg) ![Slide 24](images/slide-24.jpg)
A progressive build sequence of the CSPM → CNAPP market diagram, showing how CloudGuardian's schema-first CSPM core extends outward to CIEM, DSPM, and attack-path analysis.

#### Slide 25 — Misconfiguration Catalogue & Rationale
![Slide 25](images/slide-25.jpg)
Every toggle chosen for a documented reason, mapped to ATT&CK and severity — a representative 5 of 16 (full catalogue in the appendix).

---

### 06 · Results & Business Value (Slide 12–13)

#### Slide 12 — Before vs. After: Security Posture
![Slide 12](images/slide-12.jpg)
The proof: **68 → 12** open findings (≈82% reduction) after end-to-end remediation, plus the security maturity progression from Ad hoc/Reactive to Managed, with a path to Optimized.

#### Slide 13 — Executive Recommendation
![Slide 13](images/slide-13.jpg)
**Recommendation:** adopt continuous, multi-tool, AI-assisted, human-governed CSPM as the default posture-management model — proven, standards-aligned, and extensible.

---

### 08 · Executive Close (Slide 14, 15)

#### Slide 14 — Thank You / Q&A
![Slide 14](images/slide-14.jpg)
Formal handoff to questions, with an indexed appendix staged and ready to go deeper on any topic.

#### Slide 15 — Infrastructure-as-Code Discipline
![Slide 15](images/slide-15.jpg)
An 11-file modular Terraform project — reproducible, auditable, and cost-safe. `init → apply → destroy` rebuilds the identical estate in minutes at zero idle cost.

---

## Part 2 — Appendix / Backup Slides

*Deep-dive material held in reserve for Q&A — not part of the timed briefing, but included here for completeness.*

#### Slide 26 — Secure-by-Default Baseline
![Slide 26](images/slide-26.jpg)
Proof the lab started secure — every control defaults to the safe setting; insecurity had to be deliberately switched on.

#### Slide 27 — Build & Break: Engineering the Baseline
![Slide 27](images/slide-27.jpg)
The full breakdown: **16 controlled misconfigurations across 5 domains** (IAM, Storage, Networking, Encryption, Logging) — double the individual-track minimum.

#### Slide 28 — Multi-Tool Detection: Triangulating the Baseline
![Slide 28](images/slide-28.jpg)
The hard numbers: 83 total Prowler findings, 68 confirmed FAILs, 3 independent scanners cross-checking each other.

#### Slide 29 — AI-Assisted Remediation Guidance – Verified
![Slide 29](images/slide-29.jpg)
AI translates, never decides — every 2-line LLM explanation is cross-checked against raw scanner evidence before it ever reaches an operator.

#### Slide 30 — Automated Remediation & Safety Guardrails
![Slide 30](images/slide-30.jpg)
Safe/reversible findings auto-fix; risky/irreversible findings (key rotation, firewall changes) stop at a human approval gate. Both paths are logged.

#### Slide 31 — Audit Trail & Governance Logging
![Slide 31](images/slide-31.jpg)
An immutable, append-only SQLite decision log — closing the loop back to the opening problem: repeated audit failure becomes a continuous evidence trail.

#### Slide 32 — Security Controls Matrix
![Slide 32](images/slide-32.jpg)
Every domain paired with both a detective and a corrective control — comprehensive, even coverage, not concentrated in one area.

#### Slide 33 — Zero Trust Alignment
![Slide 33](images/slide-33.jpg)
Verify explicitly, least privilege, and assume breach — expressed as concrete CloudGuardian controls, not dated perimeter thinking.

#### Slide 34 — NIST CSF 2.0 Mapping
![Slide 34](images/slide-34.jpg)
CloudGuardian touches all six CSF functions, with Detect, Respond, and the newer Govern function as the primary center of gravity.

#### Slide 35 — Operational KPIs
![Slide 35](images/slide-35.jpg)
Metrics a SOC lead would put on a monthly report: mean detection coverage, ~60% auto-remediation rate, 100% gate adherence on risky actions, time-to-triage.

#### Slide 36 — Business Value Translation
![Slide 36](images/slide-36.jpg)
Why a CISO cares: faster audit readiness, fewer repeat findings, reduced manual toil, and defensible ISO-mapped evidence.

#### Slide 37 — Cost Discipline vs. Risk Reduction
![Slide 37](images/slide-37.jpg)
Meaningful risk reduction (82%) at near-zero infrastructure cost — free-tier resources with disciplined teardown.

#### Slide 38 — Engineering Challenges & Lessons Learned
![Slide 38](images/slide-38.jpg)
Real friction, methodically diagnosed: Windows `MAX_PATH` limits breaking Prowler, Azure platform constraints breaking Terraform applies, and provider race conditions resolved via `terraform import`.

---

## Project Structure Reference

| Layer | Tools / Technology |
|---|---|
| Infrastructure-as-Code | Terraform (Azure + AWS providers) |
| CSPM Detection | Prowler · ScoutSuite · Steampipe + CIS mod |
| Cloud-Native Signal | Microsoft Defender for Cloud / AWS Security Hub |
| Intelligence Layer | Python + pandas, RAG-grounded LLM (`meta/llama-3.1-8b-instruct` via NVIDIA NIM) |
| Governance Console | Streamlit + SQLite + Plotly |
| Automation | PowerShell / AWS CLI, Azure Functions & Logic Apps / Lambda & Step Functions |

## Compliance Frameworks Covered

ISO/IEC 27001:2022 Annex A · CIS Microsoft Azure Foundations Benchmark · NIST CSF 2.0 · MITRE ATT&CK · India's DPDP Act 2023 / Rules 2025

---

<sub>Source: `Final_CloudGuardian_Executive_Deck.pptx` — 29 briefing slides + 9 appendix/backup slides, all rendered above.</sub>
