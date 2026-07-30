# CloudGuardian — Streamlit App

Week 2 notebook (`week2_notebook.ipynb`) streamlined, portable Streamlit version. 22. We have taken Final/Production version from Notebook Cells.

## Contents:

| Tab | Notebook cell(s) | What it does |
|---|---|---|
| 1. Upload & Consolidate | Cell 3, 4 | Upload Prowler + Steampipe + ScoutSuite data and then merger in a single DataFrame. (AWS + Azure) |
| 2. Prioritize | Cell 5 | CVSS × Exposure × Blast Radius scoring, negation-aware keyword matching |
| 3. AI Classify | Cell 6 + 6.1 | RandomForest + SMOTE (final balanced model — Skipped baseline comparison) |
| 4. Redact | Cell 9 (OWASPRedactionEngine) | OWASP LLM06-compliant redaction, as it is |
| 5. RAG Remediation | Cell 11 (updated version) | Used NVIDIA NIM (`meta/llama-3.1-8b-instruct`) for RAG-grounded 2-line guidance, 25 chunks · 6 frameworks KB (CIS, MCSB, ISO 27001, DPDP, HIPAA) |
| 6. Auto-Remediate | Cell 13 | **Dry-run only** — 4 remediation functions (RDS public access, SG open ingress, Azure storage x2) |
| 7. Export | Cell 12 | CSV/JSON download buttons |

## How to use it (In Kali Linux, used separate `"kali"` user not "root" user)

```bash
cd ~/Desktop/Cloudguardian_Capstone   # This is the location where all files of CLoudGuradian are kept
pip install -r requirements.txt --break-system-packages

# NVIDIA API key )optional) App shall work without it as well. However, it will show only retrieval in Tab 5 no Live Guidance from LLM.
export NVIDIA_API_KEY='nvapi-...'

streamlit run app.py
```

In Browser `http://localhost:8501` shall open.

## File upload — What and Where

The notebook had hardcoded paths (`/home/kali/Desktop/Cloudguardian_Capstone/...`); the app now has a file uploader, so the demo can run anywhere:

- **Prowler CSV**: Directly upload `prowler-output-*.csv` (semicolon-delimited, as provided by Prowler v4)
- **Steampipe CSVs (AWS)**: From `M01_M02_...csv` to `M12_...csv`, plus `CloudTrail_logging_validation_region_coverage.csv` and `CloudTrail_log_bucket_public_check.csv` — all of these can be multi-uploaded together
- **Steampipe CSVs (Azure)**: `steampipe_compute.csv`, `steampipe_iam.csv`, `steampipe_logging.csv`, `steampipe_nsg.csv`, `steampipe_sql.csv`, `steampipe_storage.csv`
- **ScoutSuite**: `scoutsuite_results_*.js` file (not the entire folder, only this single `.js` file)

## Important — Safety design is maintained

- **The app never stores or displays AWS/Azure credentials.**
- **Auto-remediation (Tab 6) is always in dry-run mode** — no live API calls are made, it only shows "this call would be made". If you want to run live remediation, run the original notebook/Python script on your machine with proper credentials, not from this web app (this is by design — performing live cloud mutations from a shared app is risky).
- The redaction engine (Tab 4) is the same as before — AWS keys, ARNs, IPs, instance/VPC/SG IDs are all redacted before being sent to the LLM.

## Notebook cells that are NOT in this app (based on the streamlined choice)

- Cell 6 standalone baseline RandomForest display (the SMOTE version is the final one, and that is what we used)
- Cell 6.2–6.6: ML visualization dashboards, before/after SMOTE comparison, overfitting/learning-curve diagnostics — these were for the report/PPT, they were not necessary in the working app
- Cell 8: matplotlib PNG dashboard — instead of this, Streamlit's native bar charts were used (interactive, no PNG files are generated)
- Cell 10 (RAG v1, superseded): only the updated version from Cell 11 (with source_url citations) has been kept
