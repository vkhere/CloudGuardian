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

Notebook mein hardcoded paths the (`/home/kali/Desktop/Cloudguardian_Capstone/...`); app mein ab file uploader hai, kahin bhi demo chal sakta hai:

- **Prowler CSV**: seedha `prowler-output-*.csv` (semicolon-delimited, jaisa Prowler v4 deta hai)
- **Steampipe CSVs (AWS)**: `M01_M02_...csv` se `M12_...csv` tak, plus `CloudTrail_logging_validation_region_coverage.csv` aur `CloudTrail_log_bucket_public_check.csv` — sab ek saath multi-upload kar sakte ho
- **Steampipe CSVs (Azure)**: `steampipe_compute.csv`, `steampipe_iam.csv`, `steampipe_logging.csv`, `steampipe_nsg.csv`, `steampipe_sql.csv`, `steampipe_storage.csv`
- **ScoutSuite**: `scoutsuite_results_*.js` file (poora folder nahi, sirf ye ek `.js` file)

## Important — safety design maintained hai

- **AWS/Azure credentials app kabhi store ya display nahi karta.**
- **Auto-remediation (Tab 6) hamesha dry-run mode mein hai** — koi live API call nahi hoti, sirf "ye call hoti" dikhata hai. Agar live remediation chalana ho to original notebook/Python script apne machine par proper credentials ke saath chalana, is web app se nahi (jaanbujh kar aisa design kiya hai — shared app se live cloud mutations karna risky hai).
- Redaction engine (Tab 4) pehle jaisa hi hai — AWS keys, ARNs, IPs, instance/VPC/SG IDs sab redact hote hain LLM ko bhejne se pehle.

## Jo notebook cells is app mein NAHI hain (streamlined choice ke hisaab se)

- Cell 6 ka standalone baseline RandomForest display (SMOTE version hi final hai, wahi use kiya)
- Cell 6.2–6.6: ML visualization dashboards, before/after SMOTE comparison, overfitting/learning-curve diagnostics — ye report/PPT ke liye the, working app mein zaroori nahi the
- Cell 8: matplotlib PNG dashboard — iski jagah Streamlit ke native bar charts use kiye hain (interactive, koi PNG file nahi banti)
- Cell 10 (RAG v1, superseded): sirf Cell 11 ka updated version (source_url citations wala) rakha hai
