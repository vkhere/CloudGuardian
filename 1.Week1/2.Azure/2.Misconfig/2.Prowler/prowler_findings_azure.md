# Prowler Audit Report - Azure
## CloudGuardian - CAP-CSE-3W | IIT Roorkee × Futurense
### PG Certificate in AI/GenAI Powered Cybersecurity

---

| Field | Detail |
|-------|--------|
| **Student** | Vinay |
| **Azure Subscription** | 7e3283a3-d466-4e6f-95b1-543eec016e08 |
| **Resource Group** | rg-cloudguardian-lab |
| **Tool** | Prowler v4.x (Open Source CIS Scanner) |
| **Date** | 2026-07-04 |
| **Purpose** | Broad compliance scanning and delta comparison of 16 injected misconfigurations |

---

## What is Prowler?

Prowler is an open-source security tool that performs CIS compliance checks, security best practice assessments, and incident response readiness checks across cloud providers. 
Unlike ScoutSuite (which uses a generic rule engine) and Steampipe (SQL-based), Prowler is strictly aligned with the **CIS Microsoft Azure Foundations Benchmark**.

**How it was run:**
```bash
conda activate prowler_env
prowler azure --az-cli-auth --output-directory prowler-report/insecure --output-file prowler-insecure
```

![Prowler CLI Execution](file:///C:/Users/DELL/Documents/Capstone/CSE2/prowler-findings_Azure/Prowler_in_action.PNG)

---

## Executive Summary

| Metric | Baseline (Secure) | Insecure (16 Misconfigs) |
|--------|-------------------|--------------------------|
| **Overall Pass/Fail** | ~14% Pass / 86% Fail | ~12% Pass / 88% Fail |
| **Misconfigs Detected** | - | **8 / 16 (50%)** |

> **Key Insight:** Prowler generated massive CSV and HTML reports with hundreds of findings. However, a significant portion of these are pre-existing "fails" due to Azure's default configurations not adhering to strict CIS benchmarks (e.g., Azure Defender being turned off by default). 
> 
> By running a strict delta analysis (comparing the baseline CSV against the insecure CSV), we isolated exactly which of our 16 injected misconfigurations triggered new Prowler alerts.

![Prowler HTML Report Overview](file:///C:/Users/DELL/Documents/Capstone/CSE2/prowler-findings_Azure/Prowler_overview_results1.PNG)

---

## Baseline vs Insecure - Delta Analysis (New Fails)

The following `FAIL` findings appeared **only** after the 16 misconfigurations were injected. 
*(Note: Resource names have been mapped to reflect the updated `stcloudguardianlab6thil` storage account).*

| Service | Prowler Check ID | Resource Name | Severity | Terraform Misconfig |
|---------|------------------|---------------|----------|---------------------|
| **Network** | `network_ssh_internet_access_restricted` | `nsg-web-cloudguardian-lab` | 🔴 High | M10 (SSH Open) / M11 (Any-Any) |
| **Network** | `network_subnet_nsg_associated` | `snet-web-cloudguardian-lab` | 🔴 High | M12 (Subnet NSG Removed) |
| **SQL** | `sqlserver_unrestricted_inbound_access` | `sql-cloudguardian-lab-6thil` | 🔴 Critical | M13 (SQL Any IP) |
| **Storage** | `storage_default_network_access_rule_is_denied` | `stcloudguardianlab6thil` | 🔴 High | M2 (Public Network Access) |
| **Storage** | `storage_secure_transfer_required_is_enabled` | `stcloudguardianlab6thil` | 🔴 High | M3 (Secure transfer) |
| **Storage** | `storage_ensure_minimum_tls_version_12` | `stcloudguardianlab6thil` | 🟡 Medium | M4 (Min TLS 1.0) |
| **Storage** | `storage_default_to_entra_authorization_enabled`| `stcloudguardianlab6thil` | 🟡 Medium | M5 (Shared Key Access) |
| **Compute** | `vm_linux_enforce_ssh_authentication` | `vm-web-cloudguardian-lab` | 🔴 High | M9 (SSH Password Auth) |

---

## Misconfig-to-Prowler Mapping (16/16 Verification)

| # | Misconfiguration | Terraform Toggle | Prowler Delta Detection | Status |
|---|-----------------|-----------------|------------------------|--------|
| M1 | Public Blob Container | `misconfig_storage_public_container` | - | ❌ Missed (or masked by baseline) |
| M2 | Public Network Access | `misconfig_storage_allow_public_network_access` | `storage_default_network_access_rule_is_denied` | ✅ Detected |
| M3 | Secure Transfer Disabled | `misconfig_storage_disable_secure_transfer` | `storage_secure_transfer_required_is_enabled` | ✅ Detected |
| M4 | Min TLS Lowered (1.0) | `misconfig_storage_min_tls_version` | `storage_ensure_minimum_tls_version_12` | ✅ Detected |
| M5 | Shared Key Access | `misconfig_storage_allow_shared_key_access` | `storage_default_to_entra_authorization_enabled` | ✅ Detected |
| M6 | CORS Allow All | `misconfig_storage_cors_allow_all` | - | ❌ Not Detected |
| M7 | Owner Role at RG | `misconfig_iam_owner_role_at_rg_scope` | - | ❌ Not Detected |
| M8 | VM Identity Overprivileged | `misconfig_vm_identity_over_privileged` | - | ❌ Not Detected |
| M9 | SSH Password Auth | `misconfig_vm_allow_password_auth` | `vm_linux_enforce_ssh_authentication` | ✅ Detected |
| M10 | SSH Open to Internet | `misconfig_ssh_open_to_internet` | `network_ssh_internet_access_restricted` | ✅ Detected |
| M11 | NSG Allow Any-Any | `misconfig_nsg_allow_any_any` | (Caught under M10 alert) | ✅ Detected |
| M12 | Subnet NSG Removed | `misconfig_vm_remove_nsg_association` | `network_subnet_nsg_associated` | ✅ Detected |
| M13 | SQL Allow All IPs | `misconfig_sql_allow_all_ips` | `sqlserver_unrestricted_inbound_access` | ✅ Detected |
| M14 | Storage Logging Disabled | `misconfig_disable_storage_logging` | - | ❌ Missed (Pre-existing in baseline) |
| M15 | SQL Logging Disabled | `misconfig_disable_sql_logging` | - | ❌ Missed (Pre-existing in baseline) |
| M16 | Short Log Retention | `misconfig_short_log_retention` | - | ❌ Missed (Pre-existing in baseline) |

### Confirmation: 8 / 16 Detected (50%) in strict delta analysis

---

## Gap Analysis - Prowler Blind Spots

While Prowler is excellent for overarching CIS compliance, it struggles with highly specific configuration drifts when analyzing strict deltas:

### 1. The "Pre-existing Fail" Problem (Logging Gaps)
Prowler flags logging configurations (M14, M15, M16) as `FAIL` even in the secure baseline because our baseline architecture does not implement enterprise-grade Log Analytics for every single resource by default. Therefore, when we *explicitly* disable them via Terraform in the insecure scan, Prowler doesn't register it as a *new* threat. It was already failing.

### 2. IAM/RBAC Granularity Gaps
- **M7 (Owner at RG):** Prowler heavily focuses on Subscription-level IAM (like checking if there are more than 3 Subscription Owners). It completely missed the assignment of the `Owner` role at the specific Resource Group level.
- **M8 (VM Managed Identity):** Prowler checks if Managed Identities are *used*, but does not thoroughly crawl Azure AD to see if a System Assigned Identity has been granted overly permissive roles (like Contributor) at higher scopes.

### 3. Application-Level Gaps
- **M6 (CORS wildcard):** Prowler does not inspect Cross-Origin Resource Sharing rules on Blob Services.
- **M1 (Public Container):** Interestingly, while Prowler checks if the *Storage Account* allows public access (M2), it struggles to accurately report individual blob container ACL drifts in this specific dataset without generating false positives.

---

## Final CloudGuardian Tool Triangulation Matrix

| # | Misconfiguration | Prowler (CIS) | ScoutSuite (Rules) | Steampipe (SQL) |
|---|-----------------|---------------|--------------------|-----------------|
| M1 | Public Blob Container | ❌ | ✅ Danger | ✅ Query 2 |
| M2 | Public Network Access | ✅ High | ✅ Warning | ✅ Query 1 |
| M3 | Secure Transfer Disabled | ✅ High | ✅ Warning | ✅ Query 1 |
| M4 | Min TLS Lowered | ✅ Medium | ❌ | ✅ Query 1 |
| M5 | Shared Key Access | ✅ Medium | ❌ | ✅ Query 11b |
| M6 | CORS Allow All | ❌ | ❌ | ✅ Query 11a |
| M7 | Owner at RG Scope | ❌ | ❌ | ✅ Query 3 |
| M8 | VM Identity Overprivileged | ❌ | ❌ | ✅ Query 3 |
| M9 | SSH Password Auth | ✅ High | ❌ | ✅ Query 6 |
| M10 | SSH Open to Internet | ✅ High | ✅ Warning | ✅ Query 5 |
| M11 | NSG Allow Any-Any | ✅ High | ✅ Danger | ✅ Query 5 |
| M12 | Subnet NSG Removed | ✅ High | ❌ | ✅ Query 9 |
| M13 | SQL Allow All IPs | ✅ Critical | ✅ Warning | ✅ Query 4 |
| M14 | Storage Logging Disabled | ⚠️ Baseline Masked | ❌ | ✅ Query 8 |
| M15 | SQL Logging Disabled | ⚠️ Baseline Masked | ⚠️ Partial | ✅ Query 10 |
| M16 | Short Log Retention | ⚠️ Baseline Masked | ❌ | ✅ Query 12 |

> **Conclusion:** 
> - **Prowler** is best for initial CIS compliance benchmarking.
> - **ScoutSuite** provides the best visual dashboard for non-technical stakeholders, particularly for network topology.
> - **Steampipe** is the *only* tool capable of 100% precise detection of targeted engineering drifts, proving the necessity of custom SQL validation in a mature DevSecOps pipeline.
