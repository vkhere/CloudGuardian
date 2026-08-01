# Week 1 - Infrastructure Setup, Misconfiguration Injection & CSPM Scanning

> **CloudGuardian | CAP-CSE-3W | IIT Roorkee x Futurense**
> PG Certificate in AI/GenAI Powered Cybersecurity

---

## Overview

Week 1 establishes the foundation of the CloudGuardian project. The goal is to:

1. Provision a **realistic, secure 3-tier cloud infrastructure** on both AWS and Azure using Terraform (Infrastructure as Code)
2. **Deliberately inject 16 Azure + multiple AWS misconfigurations** using Terraform variable overrides
3. **Scan both environments** using three complementary CSPM (Cloud Security Posture Management) tools: Prowler, ScoutSuite, and Steampipe
4. **Compare baseline vs insecure** scan outputs to validate detection capability

This week produces the raw scanning data that feeds into the Week 2 ML prioritization and RAG-based LLM guidance pipeline.

---

## Directory Structure

```
1.Week1/
├── 1. AWS/                         # AWS cloud environment
│   ├── 1.baseline/                 # Secure AWS infrastructure
│   │   ├── 1.terraform/            # Terraform IaC (VPC, EC2, RDS, S3, IAM)
│   │   ├── 2. prowler/             # Prowler baseline scan outputs + 51 compliance CSVs
│   │   ├── 3. scoutesuite/         # ScoutSuite baseline HTML report
│   │   └── 4.steampipe/            # Steampipe baseline CSV queries
│   └── 2.misconfig/                # Misconfigured AWS infrastructure
│       ├── 1.0 Misconfig/          # Terraform with AWS misconfigurations applied
│       ├── 1.1.Prowler/            # Prowler misconfig scan outputs + 37 compliance CSVs
│       ├── 1.2.scoutsuite/         # ScoutSuite misconfig HTML report
│       ├── 1.3steampipe/           # Steampipe misconfig queries + evidence shell script
│       └── 5.snapshots/            # Process screenshots (terraform plan/apply, tool runs)
│
└── 2.Azure/                        # Azure cloud environment
    ├── 1.baseline/                 # Secure Azure infrastructure
    │   ├── 1.Terraform/            # Terraform IaC (VNet, VM, SQL, Storage, RBAC)
    │   ├── 2.Prowler/              # Prowler baseline scan outputs + compliance CSVs
    │   ├── 3.Scoutsuite/           # ScoutSuite baseline HTML report
    │   └── 4.Steampipe/            # Steampipe baseline CSV queries
    └── 2.Misconfig/                # Misconfigured Azure infrastructure (16 misconfigs injected)
        ├── 1.Terraform/            # README.md with all 18 toggle descriptions
        ├── 2.Prowler/              # Prowler delta analysis + compliance CSVs + screenshots
        │   ├── prowler_findings_azure.md  # Full audit report
        │   ├── Prowler_in_action.PNG
        │   └── Prowler_overview_results1.PNG
        ├── 3.Scoutsuite/           # ScoutSuite full report + 12 dashboard screenshots
        │   ├── scoutsuite_findings_azure.md  # Full audit report
        │   └── images/             # 12 service dashboard PNG screenshots
        └── 4.Steampipe/            # Steampipe targeted SQL verification
            └── steampipe_findings_azure.md   # Full audit report
```

---

## Cloud Architecture

### AWS - 3-Tier Architecture

| Component | Resource | Configuration |
|-----------|----------|---------------|
| Network | VPC + Public/Private Subnets | Segmented web and data tiers |
| Compute | EC2 (Amazon Linux 2) | Web server in public subnet |
| Database | RDS MySQL | Private subnet, encrypted at rest |
| Storage | S3 Bucket | Server-side encryption, versioning |
| Identity | IAM Roles + Policies | Least-privilege EC2 and Lambda roles |
| Audit | CloudTrail | Multi-region logging enabled |

**Terraform files (baseline):** `1.1.1.main.tf`, `1.1.2.vpc.tf`, `1.1.3.ec2.tf`, `1.1.4.rds.tf`, `1.1.5.s3.tf`, `1.1.6.Iam.tf`, `1.1.7.variables.tf`, `1.1.8.outputs.tf`

### Azure - 3-Tier Architecture

| Component | Resource | Configuration |
|-----------|----------|---------------|
| Network | VNet + Web Subnet + Data Subnet | Segmented via NSG |
| Compute | Linux VM (Ubuntu 22.04) | Web tier in web subnet |
| Database | Azure SQL Server + Database | Basic tier, private access |
| Storage | Storage Account + Blob Container | HTTPS-only, TLS 1.2 |
| Identity | Azure AD + RBAC | Scoped roles, no Owner at RG |
| Audit | Diagnostic Settings | Storage and SQL logging enabled |

**Terraform files (baseline):** `main.tf`, `network.tf`, `compute.tf`, `database.tf`, `storage.tf`, `iam_and_extra_misconfigs.tf`, `variables.tf`, `providers.tf`, `versions.tf`, `outputs.tf`

---

## Misconfiguration Injection

### How It Works

The Terraform code uses **boolean toggle variables** to switch between secure (baseline) and insecure configurations:

```hcl
# Example from variables.tf
variable "misconfig_storage_public_container" {
  type    = bool
  default = false   # Secure default
}
```

Setting these to `true` in `terraform.tfvars` instantly injects the vulnerability without modifying the core Terraform code. This preserves a clean baseline for delta analysis.

```bash
# Deploy secure baseline
terraform apply -var-file="terraform.tfvars"         # all misconfigs = false

# Inject 16 misconfigurations
terraform apply -var-file="terraform.tfvars.insecure"  # targeted misconfigs = true
```

### Azure Misconfiguration Catalogue (CG-001 to CG-016)

| ID | Category | Misconfiguration | Risk |
|----|----------|-----------------|------|
| CG-001 | IAM | Owner Role at Resource Group Scope | Full admin over all resources |
| CG-002 | IAM | Over-Privileged VM Identity | VM identity can modify/delete subscription-wide |
| CG-003 | Compute | SSH Password Authentication Enabled | Allows password-based SSH alongside key auth |
| CG-004 | Network | NSG Allow Any-Any Inbound | All ports/protocols open from any source |
| CG-005 | Network | SSH Port 22 Open to Internet (0.0.0.0/0) | SSH exposed to the entire internet |
| CG-006 | Network | VM NSG Association Removed | Subnet has no network security group |
| CG-007 | Network | SQL Database Allows All IPs | Database reachable from any IP |
| CG-008 | Storage | Public Blob Container | Unauthenticated read access to blob contents |
| CG-009 | Storage | Public Network Access Enabled | Storage reachable from any IP |
| CG-010 | Storage | Secure Transfer (HTTPS) Disabled | Permits unencrypted HTTP connections |
| CG-011 | Storage | Shared Key Access Enabled | Bypasses Azure AD audit trail |
| CG-012 | Storage | Minimum TLS Version Lowered to 1.0 | Allows deprecated TLS with known weaknesses |
| CG-013 | Storage | CORS Allow All Origins | Any website can make cross-origin requests |
| CG-014 | Logging | Storage Diagnostic Logging Disabled | No audit trail for blob reads/writes/deletes |
| CG-015 | Logging | SQL Diagnostic Logging Disabled | No audit trail for database queries |
| CG-016 | Logging | Log Retention Shortened (90 to 30 days) | Reduced forensic investigation window |

> **Note:** The Terraform code also includes `misconfig_sql_disable_tde` and `misconfig_sql_min_tls_version` as additional toggles not included in the final 16-item compliance mapping.

---

## CSPM Tool Scanning

Three tools are used in combination to maximise detection coverage. Each has complementary strengths and blind spots.

### Tool Comparison

| Dimension | Prowler | ScoutSuite | Steampipe |
|-----------|---------|-----------|-----------|
| **Approach** | CIS Benchmark checks | Rule-engine config audit | SQL-based targeted queries |
| **Output** | CSV + HTML + OCSF JSON | Interactive HTML dashboard | CSV tables |
| **Azure detection rate** | 8/16 (50%) | 7/16 (44%) | 14/16 (88%) |
| **AWS detection rate** | 11/12 (91%) | 8/12 (66%) | 12/12 (100%) |
| **Strengths** | Compliance breadth (50+ frameworks) | Visual drill-down, network/storage rules | Precise, targeted verification |
| **Blind spots** | Context-dependent IAM | IAM privilege analysis, logging granularity | Requires custom query per check |
| **Combined** | **-** | **-** | **~15/16 (93%+) Azure, 12/12 (100%) AWS** |

### Running the Scans

**Prowler:**
```bash
# Azure
conda activate prowler_env
prowler azure --az-cli-auth \
  --output-directory prowler-report/insecure \
  --output-file prowler-insecure

# AWS
prowler aws --profile default \
  --output-directory prowler-report/aws-insecure
```

**ScoutSuite:**
```bash
conda activate scout_env
python cspm/run_scout.py azure --cli \
  --report-dir scoutsuite-report/insecure
```

**Steampipe:**
```bash
steampipe query "SELECT name, enable_https_traffic_only FROM azure_storage_account;"
```

---

## Scan Results Summary

### Azure - Baseline vs Insecure Delta

| Tool | Total Checks | Baseline Flagged | Insecure Flagged | New Findings | Misconfigs Detected |
|------|-------------|-----------------|-----------------|-------------|-------------------|
| Prowler | ~148 | ~126 FAIL | ~148 FAIL | +22 | **8/16 (50%)** |
| ScoutSuite | 1031 | 43 flagged | 52 flagged | +9 | **7/16 (44%)** |
| Steampipe | 16 targeted | 0/16 | 14/16 | +14 | **14/16 (88%)** |

**Prowler Misconfig Scan (Azure) - Severity Breakdown:**

| Service | FAIL Count | Critical | High | Medium | Low |
|---------|------------|----------|------|--------|-----|
| Defender | 30 | 0 | 30 | 0 | 0 |
| Network | 12 | 0 | 4 | 6 | 2 |
| Storage | 18 | 0 | 8 | 8 | 2 |
| SQL | 10 | 2 | 4 | 4 | 0 |
| IAM | 18 | 0 | 10 | 6 | 2 |

**ScoutSuite - Detected vs Not Detected:**

| Result | Misconfigs |
|--------|-----------|
| Detected | M1, M2, M3, M10, M11, M13, M15 |
| Not Detected | M4, M5, M6, M7, M8, M9, M12, M14, M16 |

> ScoutSuite excels at network perimeter (NSG rules) and storage exposure checks but has significant blind spots in IAM privilege analysis, compute configuration, and logging granularity.

### AWS - Key Findings

| Service | Notable Findings |
|---------|----------------|
| RDS | `rds_publicly_accessible` (Critical) - DB has public endpoint |
| IAM | `iam_inline_policy_allows_privilege_escalation` (High) |
| S3 | Public access block missing on buckets |
| CloudTrail | Multi-region logging not enabled on all accounts |
| EC2 | Security groups with unrestricted ingress (0.0.0.0/0) |

---

## Compliance Coverage (Prowler)

The Prowler scans were run against **50+ compliance frameworks**. Key frameworks covered:

| Framework | File Pattern |
|-----------|-------------|
| CIS Azure Foundations 2.0 - 5.0 | `*_cis_2.0_azure.csv` ... `*_cis_5.0_azure.csv` |
| CIS AWS Foundations 1.4 - 7.0 | `*_cis_1.4_aws.csv` ... `*_cis_7.0_aws.csv` |
| HIPAA | `*_hipaa_azure.csv` |
| ISO 27001:2022 | `*_iso27001_2022_azure.csv` |
| PCI-DSS v4.0 | `*_pci_4.0_azure.csv` |
| NIST 800-53 Rev 5 | `*_nist_800_53_revision_5_aws.csv` |
| SOC 2 | `*_soc2_azure.csv`, `*_soc2_aws.csv` |
| MITRE ATT&CK | `*_mitre_attack_azure.csv` |
| GDPR | `*_gdpr_aws.csv` |
| DORA 2022 | `*_dora_2022_2554.csv` |

---

## Key Output Files

| File | Description |
|------|-------------|
| `1. AWS/2.misconfig/5.snapshots/` | 50+ JPG screenshots of the full Week 1 process |
| `2.Azure/2.Misconfig/2.Prowler/prowler_findings_azure.md` | Prowler delta analysis report |
| `2.Azure/2.Misconfig/2.Prowler/Prowler_in_action.PNG` | Prowler CLI execution screenshot |
| `2.Azure/2.Misconfig/3.Scoutsuite/scoutsuite_findings_azure.md` | ScoutSuite full audit report |
| `2.Azure/2.Misconfig/3.Scoutsuite/images/` | 12 ScoutSuite dashboard screenshots |
| `2.Azure/2.Misconfig/4.Steampipe/steampipe_findings_azure.md` | Steampipe targeted SQL verification report |
| `2.Azure/2.Misconfig/3.Scoutsuite/cross_tool_comparison.csv` | Side-by-side tool comparison CSV |
| `1. AWS/baseline_outputs_final.txt` | Full AWS baseline scan text output |

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | >= 1.5 | Infrastructure provisioning |
| Azure CLI | >= 2.x | Azure authentication for tools |
| AWS CLI | >= 2.x | AWS authentication |
| Prowler | v4.x | CIS compliance scanning |
| ScoutSuite | v5.x | Rule-based security audit |
| Steampipe | v2.4.4 | SQL-based targeted queries |
| conda | any | Environment management for tool isolation |

---

## Next Steps

The scan outputs from Week 1 feed directly into:

- **[Week 2](../2.Week2/README.md)** - ML-based prioritization, RAG-grounded LLM guidance, and SMOTE-balanced model evaluation
- **[Week 3](../3.Week3/README.md)** - Automated and semi-automatic remediation pipelines

---

*CloudGuardian | Week 1 | IIT Roorkee x Futurense | July 2026*
