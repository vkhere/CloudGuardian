# How to feed reports into the console

The console reads **every `.csv` in this folder**. Each CSV is **one scan run**
(one cloud, one stage). Drop as many as you like — Azure and AWS, across
Week 1, 2 and 3 — and the console merges them automatically.

You do **not** point the console at raw Prowler / ScoutSuite / Steampipe output.
You point it at the *normalized* CSV your Week 2 pipeline produces (your
PowerShell catalogue generator already does this for Azure; the AWS teammate
produces the same shape). This keeps the dashboard cloud-agnostic.

## Filename convention (recommended)

```
<cloud>_w<week>_<stage>.csv
e.g.  azure_w1_baseline.csv
      azure_w1_after-misconfig.csv
      azure_w3_after-remediation.csv
      aws_w1_baseline.csv
      aws_w1_after-misconfig.csv
      aws_w3_after-remediation.csv
```

The cloud is also read from the `cloud` column inside the file; the filename is
just a helpful fallback.

## Columns

Scan-level (same value on every row of the file):

| column | example | notes |
| --- | --- | --- |
| `cloud` | Azure / AWS | required |
| `week` | 1 / 2 / 3 | integer |
| `scan_stage` | Baseline / After misconfig / After remediation | drives the trend + point-in-time selector |
| `scan_id` | azure-w1-baseline | unique per scan run |
| `captured_at` | 2026-06-20 | date the scan was taken |

Finding-level (one row per check result):

| column | example | notes |
| --- | --- | --- |
| `finding_id` | AZ-STG-PUBLIC-CONTAINER | **stable** id — reuse the same id for the same issue across scans so decisions and trends line up |
| `account_id` | sub-0f3a2b / 1111… | subscription / account |
| `service` | Storage, SQL, Network, IAM, S3 … | |
| `resource_name` | stcloudguardianlab | |
| `region` | Central US / us-east-1 | |
| `check_id` | storage_blob_public_access | scanner check id |
| `title` | Blob container is publicly readable | short |
| `description` | … | one or two sentences |
| `severity` | Critical / High / Medium / Low / Informational | |
| `status` | PASS / FAIL / MANUAL | FAIL rows are the "open findings" |
| `source_tool` | Prowler / ScoutSuite / Steampipe | |
| `risk_score` | 0–100 | from your Week 2 prioritization model |
| `cvss` | 9.1 | optional |
| `exposure` | Public / Internal / Private | optional |
| `blast_radius` | Account / Subscription / Resource | optional |
| `remediation` | plain-English fix | your LLM output |
| `llm_confidence` | High / Medium / Low | |
| `verification_status` | Verified / Needs Review / Flagged | `Flagged` shows a warning before approval |
| `iso_27001` | A.8.3 Access restriction | drives the compliance rollup |
| `cis_control` | CIS 3.7 | drives the compliance rollup |
| `mitre_attck` | T1530 | |
| `is_catalogued_misconfig` | Yes / No | `Yes` = one of your deliberate Week-1 toggles |

Missing optional columns are filled with blanks, so a partial CSV still loads.

## Regenerating the samples

```
python tools/generate_sample_reports.py
```

Delete the sample CSVs once your real reports are in place.
