# Week 2 - ML Prioritization, RAG-Grounded LLM Guidance & SMOTE Evaluation

> **CloudGuardian | CAP-CSE-3W | IIT Roorkee x Futurense**
> PG Certificate in AI/GenAI Powered Cybersecurity

---

## Overview

Week 2 ingests the raw CSPM scan data from Week 1 and applies a multi-stage AI pipeline to:

1. **Normalize and consolidate** findings from Prowler, ScoutSuite, and Steampipe into a single unified CSV
2. **Score and prioritize** every finding using a custom ML-driven formula (CVSS x Exposure x Blast Radius)
3. **Classify risk** using a Random Forest model trained on the consolidated findings
4. **Balance class distribution** using SMOTE (Synthetic Minority Over-sampling Technique) to improve HIGH/CRITICAL risk detection
5. **Generate actionable remediation guidance** using a RAG (Retrieval-Augmented Generation) pipeline grounded in a custom AWS/Azure security knowledge base, calling Meta LLaMA 3.1 8B via NVIDIA NIM
6. **Redact PII** from all findings before LLM ingestion (OWASP LLM06 compliance)
7. **Produce a Streamlit dashboard** visualizing findings by cloud, severity, service, and priority band

---

## Directory Structure

```
2.Week2/
├── README.md                              # This file
├── consolidated_findings.csv              # [632 KB] Unified dataset - 1,522 findings
├── consolidated_findings.json             # [1.05 MB] Same data in JSON format
├── llm_remediation_guidance.csv           # [17 KB] LLM-generated guidance for top 30 findings
├── rag_retrieval_audit.csv                # [14 KB] RAG retrieval audit trail (15 findings)
├── remediation_dry_run_log.csv            # [3 KB] Dry-run remediation results log
├── week2_dashboard.png                    # [263 KB] Streamlit dashboard screenshot
├── learning_curve.png                     # [81 KB] ML model learning curve (baseline)
├── learning_curve_smote.png               # [86 KB] ML model learning curve (SMOTE)
├── ml_model_dashboard_multicloud.png      # [202 KB] 6-panel ML metrics dashboard (baseline)
├── ml_model_dashboard_smote_multicloud.png # [214 KB] 6-panel ML metrics dashboard (SMOTE)
├── before_after_smote_comparison.png      # [121 KB] SMOTE before/after 4-panel comparison
└── llm-outputs/
    └── owasp_redaction_proof.csv          # [6 KB] Evidence of PII redaction before LLM call
```

---

## Pipeline Architecture

```
Week 1 Scan Outputs
(Prowler CSV + ScoutSuite HTML + Steampipe CSV)
        |
        v
[1. CSPM Consolidation]
  consolidate_findings.py
  - Normalize schema across 3 tools
  - Deduplicate overlapping findings
  - Assign unique Finding IDs (FND-XXXX)
        |
        v
[2. ML Scoring & Prioritization]
  Priority Score = CVSS Score x Exposure Factor x Blast Radius
  - P0 CRITICAL: score >= 100
  - P1 HIGH:     score 70-99
  - P2 MEDIUM:   score 30-69
  - P3 LOW:      score < 30
        |
        v
[3. PII Redaction] (OWASP LLM06)
  PIIDetector engine
  - Strips: IPs, Subscription IDs, UUIDs, ARNs, emails, account numbers
  - Replaces with: [PROJECT_RESOURCE_NAME_XXX], [VPC_ID_XXX], etc.
        |
        v
[4. RAG Retrieval]
  Knowledge base: guidance_chunk_aws.json + guidance_chunk_azure.json + guidance_chunk_scout.json
  - Hybrid retrieval (embedding + keyword)
  - Similarity threshold: >= 0.35 (raw data), >= 0.55 (control grounding)
  - Dual-verify gate: both grounding checks must pass
        |
        v
[5. LLM Guidance Generation]
  Model: meta/llama-3.1-8b-instruct via NVIDIA NIM API
  - Input: redacted finding + retrieved KB chunks
  - Output: step-by-step remediation guidance + verify method
        |
        v
[6. SMOTE Evaluation]
  - Baseline RF: 729 findings, imbalanced classes
  - SMOTE RF: synthetic minority samples to balance HIGH/CRITICAL
  - Cross-validation: 5-fold stratified
        |
        v
[7. Streamlit Dashboard]
  week2_dashboard.png - Interactive multi-cloud CSPM view
```

---

## Key Dataset: `consolidated_findings.csv`

**1,522 findings** across AWS and Azure, normalized from 3 tools.

### Schema

| Column | Description |
|--------|-------------|
| `check_id` | Tool-specific check identifier |
| `title` | Human-readable finding name |
| `severity` | critical / high / medium / low |
| `service` | Cloud service (rds, iam, s3, storage, network, etc.) |
| `region` | Cloud region |
| `resource_name` | Resource identifier (PII-redacted) |
| `description` | What the check found |
| `risk` | Business risk if exploited |
| `remediation` | Raw remediation hint from scanner |
| `tool` | Prowler / ScoutSuite / Steampipe |
| `cloud_provider` | AWS / Azure |
| `finding_id` | Unique ID (FND-XXXX) |
| `account_id` | Cloud account/subscription ID |
| `scan_date` | Date of scan |
| `cvss_score` | CVSS base score (0-10) |
| `exposure_score` | Network exposure factor (1-3) |
| `blast_radius` | Impact radius score (1-4) |
| `priority_score` | `cvss x exposure x blast_radius` |
| `priority_band` | P0-CRITICAL / P1-HIGH / P2-MEDIUM / P3-LOW |
| `risk_label` | HIGH / MEDIUM / LOW |
| `ai_risk_level` | RF model prediction (baseline) |
| `ai_confidence` | RF model confidence (baseline) |
| `ai_score` | Combined AI risk score |
| `ai_risk_level_smote` | RF model prediction (SMOTE) |
| `ai_confidence_smote` | RF model confidence (SMOTE) |
| `status_detail` | Redacted resource detail string |

### Priority Band Distribution

| Band | Findings | % |
|------|----------|---|
| P0 - CRITICAL | ~2 | 0.1% |
| P1 - HIGH | ~58 | 3.8% |
| P2 - MEDIUM | ~129 | 8.5% |
| P3 - LOW | ~1,333 | 87.5% |

### Cloud Provider Split

| Cloud | Findings |
|-------|----------|
| AWS | ~497 (33%) |
| Azure | ~1,025 (67%) |

---

## ML Model: Random Forest Prioritization

### Feature Engineering

The priority score formula drives both ranking and ML features:

```
Priority Score = CVSS Score x Exposure Factor x Blast Radius

Where:
  CVSS Score    = Base severity score (0-10, from NVD or tool-assigned)
  Exposure Factor = 1 (internal) | 2 (VPC-exposed) | 3 (internet-facing)
  Blast Radius    = 1 (isolated resource) | 2 | 3 | 4 (account-level impact)
```

### Baseline Model Results

| Metric | Value |
|--------|-------|
| CV Accuracy | 88.3% (+/- 12.1%) |
| Macro F1 | 76.2% |
| HIGH-Risk Precision | 71.4% |
| HIGH-Risk Recall | 68.9% |
| Learning curve gap | 0.042 (GOOD FIT) |

### SMOTE-Enhanced Model Results

| Metric | Value |
|--------|-------|
| CV Accuracy | **92.6% (+/- 8.7%)** |
| Macro F1 | **82.4%** |
| HIGH-Risk Precision | **84.1%** |
| HIGH-Risk Recall | **79.3%** |
| Learning curve gap | 0.019 (EXCELLENT FIT) |

### Comparison (Baseline vs SMOTE)

| Metric | Baseline | SMOTE | Change |
|--------|----------|-------|--------|
| CV Accuracy | 88.3% | 92.6% | +4.3 pp |
| Macro F1 | 76.2% | 82.4% | +6.2 pp |
| HIGH Precision | 71.4% | 84.1% | +12.7 pp |
| HIGH Recall | 68.9% | 79.3% | +10.4 pp |
| Learning Curve Gap | 0.042 | 0.019 | -54% |

---

## Charts & Visualizations

### `learning_curve.png`
Learning curve for the baseline Random Forest model. Shows training score vs cross-validation score as training set size increases. Gap of 0.042 indicates a well-fitted model with no significant overfitting.

### `learning_curve_smote.png`
Learning curve for the SMOTE-balanced model. Gap narrows to 0.019, confirming improved generalization for minority classes (HIGH/CRITICAL findings).

### `ml_model_dashboard_multicloud.png`
6-panel dashboard (baseline model):
- **Panel 1:** Confusion Matrix - classification accuracy by class
- **Panel 2:** Feature Importance - top predictors (cvss_score, exposure_score, blast_radius)
- **Panel 3:** Cloud Provider Split Pie - AWS vs Azure distribution
- **Panel 4:** CV Score Stability - 5-fold cross-validation box plot
- **Panel 5:** Risk Label Distribution - class imbalance visualization
- **Panel 6:** AI Confidence Distribution - histogram of model confidence scores

### `ml_model_dashboard_smote_multicloud.png`
Same 6-panel layout for the SMOTE model. Notable improvements visible in confusion matrix (fewer HIGH misclassifications) and CV stability.

### `before_after_smote_comparison.png`
4-panel direct comparison:
- Overall CV Accuracy (before vs after)
- HIGH-Risk Precision (before vs after)
- HIGH-Risk Recall (before vs after)
- Confusion Matrix side-by-side (Baseline | SMOTE)

### `week2_dashboard.png`
Full Streamlit dashboard screenshot showing:
- Priority Band distribution pie chart
- Severity distribution bar chart
- Cloud provider breakdown pie
- Top 10 most-affected services bar chart
- CSPM Tool breakdown
- Priority Band by Cloud Provider grouped bar

---

## RAG Pipeline: LLM Remediation Guidance

### Knowledge Base

Three JSON knowledge base files (not in this directory - see `llm/` in root):
- `guidance_chunk_aws.json` - AWS-specific security controls and remediation steps
- `guidance_chunk_azure.json` - Azure-specific security controls and remediation steps
- `guidance_chunk_scout.json` - ScoutSuite-specific finding context

Each chunk is tagged with a control reference (e.g., `AWS-RDS-01`), framework name, and source URL.

### Retrieval Strategy

```
Query: finding title + severity + service
  -> Hybrid retrieval: embedding similarity + keyword match
  -> Dual-verify gate:
       control_grounding:   similarity >= 0.55 (PASS)
       raw_data_grounding:  similarity >= 0.35 (PASS)
  -> Both must PASS before sending to LLM
```

### LLM Configuration

| Setting | Value |
|---------|-------|
| Model | `meta/llama-3.1-8b-instruct` |
| Provider | NVIDIA NIM API |
| Input | Redacted finding + retrieved KB chunks |
| Output | Step-by-step remediation + verify_method + verify_reason |

### `llm_remediation_guidance.csv` - Schema

| Column | Description |
|--------|-------------|
| `finding_id` | Unique finding ID (FND-XXXX) |
| `cloud_provider` | AWS / Azure |
| `title` | Finding name |
| `severity` | critical / high / medium / low |
| `priority_band` | P0 - P3 |
| `llm_model` | Model identifier |
| `llm_provider` | NVIDIA NIM |
| `rag_control_ref` | Retrieved control IDs (e.g., AWS-RDS-01) |
| `rag_framework` | Compliance framework(s) cited |
| `rag_similarity` | Top retrieval similarity score |
| `llm_guidance` | Full remediation guidance text |
| `verify_method` | How to verify remediation was applied |
| `verified` | YES / NO / YES - REVIEW RECOMMENDED |

### `rag_retrieval_audit.csv` - Schema

Full audit trail of what was retrieved for each finding, including the raw text chunks and similarity scores. Used to verify RAG grounding quality.

---

## PII Redaction (OWASP LLM06)

Before any finding is sent to the LLM, the `PIIDetector` engine strips all sensitive identifiers:

| Pattern | Replaced With |
|---------|--------------|
| AWS Account IDs | `[AWS_ACCOUNT_ID_XXX]` |
| Azure Subscription IDs | `[AZURE_SUBSCRIPTION_XXX]` |
| IP Addresses | `[IP_ADDRESS_XXX]` |
| VPC IDs | `[VPC_ID_XXX]` |
| ARNs | `[ARN_XXX]` |
| UUIDs | `[UUID_XXX]` |
| Email addresses | `[EMAIL_XXX]` |
| AWS Secret/Access Keys | `[AWS_SECRET_KEY_XXX]` |
| Resource names | `[PROJECT_RESOURCE_NAME_XXX]` |

**Evidence:** `llm-outputs/owasp_redaction_proof.csv` - shows original vs redacted side-by-side for 15 sample findings.

---

## Dry Run Log: `remediation_dry_run_log.csv`

Records the results of running remediation functions in `--dry-run` mode before any live changes were applied. Confirms that:
- The correct AWS API calls are constructed
- Dry-run mode returns no errors
- Resource targeting is accurate

---

## Frameworks Referenced in RAG Output

| Framework | Coverage |
|-----------|---------|
| AWS Well-Architected Framework - Security Pillar | RDS, IAM, S3, EC2 findings |
| CIS AWS Foundations Benchmark v5.0.0 | IAM, networking, logging |
| CIS Azure Foundations Benchmark | Azure storage, network, IAM |
| NIST 800-53 Rev 5 | Cross-cloud access control |
| ISO 27001:2022 | Storage and logging findings |
| PCI-DSS v4.0 | Network and encryption findings |

---

## How to Reproduce

### 1. Run the Notebook

The core pipeline is in `week2_notebook.ipynb` (root of repo) or the full version in the local `week2_prioritization_Rag_updated.ipynb`.

```bash
pip install -r requirements.txt
jupyter notebook week2_notebook.ipynb
```

### 2. Set Up NVIDIA NIM API Key

```bash
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit .streamlit/secrets.toml and add your NVIDIA NIM API key
```

### 3. Run the Streamlit Dashboard

```bash
streamlit run 4.Dashboard\ -\ Streamlit_app/app.py
```

---

## Connections to Other Weeks

| Direction | Link |
|-----------|------|
| Inputs from | [Week 1](../1.Week1/README.md) - Raw CSPM scan CSVs (Prowler, ScoutSuite, Steampipe) |
| Outputs to | [Week 3](../3.Week3/README.md) - `consolidated_findings.csv` and `llm_remediation_guidance.csv` feed the remediation pipeline |
| Dashboard | [4.Dashboard - Streamlit_app](../4.Dashboard\ -\ Streamlit_app/README.md) - Interactive visualization of this week's outputs |
| Final results | [5.Results](../5.Results/) - Production-ready copies of all charts and CSVs |

---

*CloudGuardian | Week 2 | IIT Roorkee x Futurense | July 2026*
