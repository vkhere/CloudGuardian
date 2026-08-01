# ScoutSuite Audit Report - Azure
## CloudGuardian - CAP-CSE-3W | IIT Roorkee × Futurense
### PG Certificate in AI/GenAI Powered Cybersecurity

---

| Field | Detail |
|-------|--------|
| **Student** | Vinay |
| **Azure Subscription** | 7e3283a3-d466-4e6f-95b1-543eec016e08 |
| **Azure Tenant** | fd9388b0-2c00-4cf1-9e27-123b32fe4a92 |
| **Region** | Central US |
| **Resource Group** | rg-cloudguardian-lab |
| **Tool** | ScoutSuite v5.x (NCC Group) |
| **Date** | 2026-07-03 |
| **Purpose** | Automated multi-service Azure security audit with baseline vs insecure comparison |

---

## What is ScoutSuite?

ScoutSuite is an open-source multi-cloud security auditing tool maintained by NCC Group.
Unlike Steampipe (SQL-based) or Prowler (CIS benchmark-driven), ScoutSuite uses a
**rule-engine approach** - it fetches the full configuration of your cloud environment
and evaluates it against a library of pre-defined security rules.

It produces an **interactive HTML dashboard** that lets you drill into each service,
view flagged rules, and inspect the raw resource configuration.

**How it was run:**
```bash
conda activate scout_env
python cspm/run_scout.py azure --cli --report-dir scoutsuite-report/insecure
```

---

## Executive Summary

| Metric | Baseline (Secure) | Insecure (16 Misconfigs) | Delta |
|--------|-------------------|--------------------------|-------|
| **Total Checks** | 1031 | 1031 | 0 |
| **Total Flagged** | 43 | 52 | **+9** |
| **Services Affected** | 5 | 8 | +3 |
| **Danger-Level Findings** | 2 | 4 | +2 |
| **Misconfigs Detected** | - | 7 / 16 | **44%** |

### Detection Rate Summary

| Result | Count | Misconfigs |
|--------|-------|------------|
| ✅ Detected | 7 | M1, M2, M3, M10, M11, M13, M15 |
| ❌ Not Detected | 9 | M4, M5, M6, M7, M8, M9, M12, M14, M16 |

> **Key Insight:** ScoutSuite excels at network perimeter (NSG rules) and storage
> exposure checks but has significant blind spots in IAM privilege analysis, compute
> configuration, and logging granularity. This validates the multi-tool CSPM approach
> used in CloudGuardian.

---

## Baseline vs Insecure - Delta Analysis

The following table shows the 9 **NEW** findings that appeared only after
the 16 misconfigurations were injected via Terraform:

| # | Service | Rule ID | Description | Level |
|---|---------|---------|-------------|-------|
| Δ1 | Network | `network-security-groups-rule-inbound-internet-all` | All Inbound Access Allowed from Internet | 🔴 danger |
| Δ2 | Network | `network-security-groups-rule-inbound-SSH` | Inbound SSH Access Allowed | 🟡 warning |
| Δ3 | Network | `network-security-groups-rule-inbound-RDP` | Inbound RDP Access Allowed | 🟡 warning |
| Δ4 | Network | `network-security-groups-rule-inbound-MsSQL` | Inbound MsSQL Access Allowed | 🟡 warning |
| Δ5 | Network | `network-security-groups-rule-inbound-UDP` | Inbound UDP Access Allowed | 🟡 warning |
| Δ6 | Storage | `storageaccount-public-blob-container` | Blob Containers Allowing Public Access | 🔴 danger |
| Δ7 | Storage | `storageaccount-account-allowing-clear-text` | Secure Transfer (HTTPS) Not Enforced | 🟡 warning |
| Δ8 | Storage | `storageaccount-public-traffic-allowed` | Storage Allowing Public Traffic | 🟡 warning |
| Δ9 | SQL | `sqldatabase-allow-any-ip` | SQL Database Allow Ingress 0.0.0.0/0 (Any IP) | 🟡 warning |

### Screenshot (ScoutSuite Dashboard - Summary)
![ScoutSuite Summary](./images/Scout_Suite_Summary_page_Dashboard.PNG)

---

## Detailed Findings by Service

---

### Service 1 - Storage Accounts (6 flagged)

#### Finding S1: Public Blob Container
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-public-blob-container` |
| **Level** | 🔴 danger |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` / container: `app-data` |
| **Terraform Toggle** | `misconfig_storage_public_container = true` |
| **Delta** | ✅ NEW (not in baseline) |

**Risk:** Any anonymous user with the container URL can list and download all blobs.
This is the #1 cause of cloud data breaches.

#### Finding S2: Secure Transfer (HTTPS) Not Enforced
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-account-allowing-clear-text` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` |
| **Terraform Toggle** | `misconfig_storage_disable_secure_transfer = true` |
| **Delta** | ✅ NEW (not in baseline) |

**Risk:** Data transmitted over HTTP can be intercepted via Man-in-the-Middle attacks.

#### Finding S3: Public Traffic Allowed
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-public-traffic-allowed` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` |
| **Terraform Toggle** | `misconfig_storage_allow_public_network_access = true` |
| **Delta** | ✅ NEW (not in baseline) |

**Risk:** Storage account accepts connections from any IP address, removing network-level defense.

#### Finding S4: Access Keys Not Rotated
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-access-keys-not-rotated` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` |
| **Terraform Toggle** | N/A (Azure default) |
| **Delta** | Pre-existing (also in baseline) |

**Risk:** Long-lived access keys increase the window of opportunity for credential-based attacks.

#### Finding S5: Storage Not Encrypted with CMK
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-encrypted-not-customer-managed` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` |
| **Terraform Toggle** | N/A (Azure default - platform-managed key) |
| **Delta** | Pre-existing (also in baseline) |

**Risk:** Without a Customer-Managed Key (CMK), the organization cannot independently revoke encryption access.

#### Finding S6: Soft Delete Disabled
| Field | Value |
|-------|-------|
| **Rule ID** | `storageaccount-soft-delete-enabled` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `stcloudguardianlab6thil` |
| **Terraform Toggle** | N/A (Azure default) |
| **Delta** | Pre-existing (also in baseline) |

**Risk:** Deleted blobs cannot be recovered, increasing risk of accidental or malicious data loss.

### Screenshot (Storage Findings)
![Storage Dashboard](./images/Storage_Account_Dashboard.PNG)
![Storage Configurations](./images/Storage_Account_Configurations_Dashboard.PNG)

---

### Service 2 - SQL Database (13 flagged)

#### Finding SQL1: Allow Ingress from Any IP ⭐
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-allow-any-ip` |
| **Level** | 🟡 warning |
| **Flagged Items** | 2 (AllowAzureServices 0.0.0.0 + MISCONFIG-AllowAllIPs 0.0.0.0-255.255.255.255) |
| **Resource** | `sql-cloudguardian-lab-6thil` |
| **Terraform Toggle** | `misconfig_sql_allow_all_ips = true` |
| **Delta** | ✅ NEW (not in baseline) |

**Risk:** The MISCONFIG-AllowAllIPs firewall rule exposes the SQL server to the entire IPv4 address space.

#### Finding SQL2: Server Auditing Disabled ⭐
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-servers-no-auditing` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `sql-cloudguardian-lab-6thil` |
| **Terraform Toggle** | `misconfig_disable_sql_logging = true` |
| **Delta** | Pre-existing (also in baseline - auditing was never configured) |

**Risk:** No audit trail for database operations. Failed logins, SQL injection, and unauthorized queries leave no trace.

#### Finding SQL3: Database Auditing Disabled
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-databases-no-auditing` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |
| **Resource** | `sqldb-cloudguardian-lab` |

#### Finding SQL4: Server Threat Detection (ATP) Disabled
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-servers-no-threat-detection` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |

#### Finding SQL5: Database Threat Detection Disabled
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-databases-no-threat-detection` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |

#### Finding SQL6: TDE Not Encrypted with CMK
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-servers-TDE-not-encrypted-with-customer-managed-key` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |

#### Finding SQL7: AD Admin Not Configured
| Field | Value |
|-------|-------|
| **Rule ID** | `sqldatabase-servers-no-ad-admin-configured` |
| **Level** | 🟡 warning |
| **Flagged Items** | 1 |

#### Finding SQL8-SQL12: Vulnerability Assessment & Alerts
| Rule ID | Description | Flagged |
|---------|-------------|---------|
| `sqldatabase-servers-threat-detection-send-alerts-disabled` | ATP Alerts Disabled (Server) | 1 |
| `sqldatabase-databases-threat-detection-send-alerts-disabled` | Threat Alerts Disabled (DB) | 1 |
| `sqldatabase-servers-vulnerability-email-notif-to-admins-owners-not-set` | Email Notifications Not Set | 1 |
| `sqldatabase-servers-vulnerability-recurring-scans-disabled` | Recurring Scans Disabled | 1 |
| `sqldatabase-servers-vulnerability-send-scan-reports-to-not-configured` | Scan Reports Not Configured | 1 |

### Screenshot (SQL Database Findings)
![SQL Dashboard](./images/SQL_Database_Dashboard.PNG)
![SQL Configs 1](./images/SQL_Configurations_Dashboard1.PNG)
![SQL Configs 2](./images/SQL_Configurations_Dashboard2.PNG)

---

### Service 3 - Network (5 flagged)

All 5 findings are **NEW** in the insecure scan and originate from two NSG rules:
- `MISCONFIG-Allow-Any-Any` (any protocol, any port, from `*`)
- `Allow-SSH-Inbound` (port 22 from `*`)

#### Finding N1: All Inbound Access Allowed from Internet
| Field | Value |
|-------|-------|
| **Rule ID** | `network-security-groups-rule-inbound-internet-all` |
| **Level** | 🔴 danger |
| **Flagged Items** | 1 |
| **NSG** | `nsg-web-cloudguardian-lab` |
| **Source Rule** | `MISCONFIG-Allow-Any-Any` - priority 100, protocol `*`, port `*`, source `*` |
| **Terraform Toggle** | `misconfig_nsg_allow_any_any = true` |

**Risk:** Complete network perimeter collapse. Every port and protocol on the VM is exposed to the internet.

#### Finding N2: Inbound SSH Access
| Field | Value |
|-------|-------|
| **Rule ID** | `network-security-groups-rule-inbound-SSH` |
| **Level** | 🟡 warning |
| **Terraform Toggle** | `misconfig_ssh_open_to_internet = true` |

#### Finding N3-N5: RDP, MsSQL, UDP Access
| Rule ID | Port | Triggered By |
|---------|------|-------------|
| `network-security-groups-rule-inbound-RDP` | 3389 | MISCONFIG-Allow-Any-Any |
| `network-security-groups-rule-inbound-MsSQL` | 1433 | MISCONFIG-Allow-Any-Any |
| `network-security-groups-rule-inbound-UDP` | UDP/* | MISCONFIG-Allow-Any-Any |

### Screenshot (Network Findings)
![Network Dashboard](./images/Network_Dashboard.PNG)
![Network Configs](./images/Network_Configuration_Dashboard.PNG)

---

### Service 4 - Logging & Monitoring (8 flagged)

All 8 findings are **pre-existing** (also in baseline). They indicate that
Activity Log Alerts are not configured for critical administrative actions.

| Rule ID | Missing Alert For |
|---------|-------------------|
| `create_delete_firewall_rule_exist` | SQL Server Firewall Rule Changes |
| `create_update_NSG_exist` | NSG Create/Update |
| `create_update_NSG_rule_exist` | NSG Rule Create/Update |
| `delete_NSG_exist` | NSG Delete |
| `delete_NSG_rule_exist` | NSG Rule Delete |
| `create_update_security_solution_exist` | Security Solution Create/Update |
| `delete_security_solution_exist` | Security Solution Delete |
| `logging-monitoring-log-alert-not-exist-create-policy-assignment` | Create Policy Assignment |



---

### Service 5 - Security Center (17 flagged)

All 17 findings are **pre-existing** (also in baseline). They indicate that
Azure Defender (Standard Tier) is not enabled for 16 resource types, and
no security contact email is configured.

| Rule ID | Description | Flagged |
|---------|-------------|---------|
| `securitycenter-standard-tier-not-enabled` | Azure Defender Not Enabled | 16 |
| `securitycenter-security-contacts-not-set` | No Security Contact | 1 |



---

### Service 6 - Azure Active Directory (1 flagged)

| Rule ID | Description | Level |
|---------|-------------|-------|
| `aad-users-create-security-groups-disabled` | Users Can Create Security Groups | 🔴 danger |

**Note:** Pre-existing tenant-level setting - not caused by Terraform misconfigs.

---

### Service 7 - RBAC (1 flagged)

| Rule ID | Description | Level |
|---------|-------------|-------|
| `rbac-administering-resource-locks-assigned` | No Resource Locks Role | 🔴 danger |

**Note:** Pre-existing - no resource lock management role assigned in the subscription.

---

### Service 8 - Virtual Machines (1 flagged)

| Rule ID | Description | Level |
|---------|-------------|-------|
| `virtual-machines-os-data-encrypted-cmk` | OS/Data Disks Not Encrypted with CMK | 🟡 warning |

**Note:** Pre-existing governance observation. Azure encrypts all disks with Platform-Managed Keys (PMK) by default;
this finding flags the absence of a Customer-Managed Key (CMK).

---

## Misconfig-to-ScoutSuite Mapping (16/16 Verification)

| # | Misconfiguration | Terraform Toggle | ScoutSuite Detection | Status |
|---|-----------------|-----------------|---------------------|--------|
| M1 | Public Blob Container | `misconfig_storage_public_container` | `storageaccount-public-blob-container` (🔴) | ✅ Detected |
| M2 | Public Network Access | `misconfig_storage_allow_public_network_access` | `storageaccount-public-traffic-allowed` | ✅ Detected |
| M3 | Secure Transfer Disabled | `misconfig_storage_disable_secure_transfer` | `storageaccount-account-allowing-clear-text` | ✅ Detected |
| M4 | Min TLS Lowered (1.0) | `misconfig_storage_min_tls_version` | - | ❌ Not Detected |
| M5 | Shared Key Access | `misconfig_storage_allow_shared_key_access` | - | ❌ Not Detected |
| M6 | CORS Allow All | `misconfig_storage_cors_allow_all` | - | ❌ Not Detected |
| M7 | Owner Role at RG | `misconfig_iam_owner_role_at_rg_scope` | - | ❌ Not Detected |
| M8 | VM Identity Over-Privileged | `misconfig_vm_identity_over_privileged` | - | ❌ Not Detected |
| M9 | SSH Password Auth | `misconfig_vm_allow_password_auth` | - | ❌ Not Detected |
| M10 | SSH Open to Internet | `misconfig_ssh_open_to_internet` | `network-...-inbound-SSH` | ✅ Detected |
| M11 | NSG Allow Any-Any | `misconfig_nsg_allow_any_any` | `network-...-inbound-internet-all` (🔴) | ✅ Detected |
| M12 | Subnet NSG Removed | `misconfig_vm_remove_nsg_association` | - | ❌ Not Detected |
| M13 | SQL Allow All IPs | `misconfig_sql_allow_all_ips` | `sqldatabase-allow-any-ip` | ✅ Detected |
| M14 | Storage Logging Disabled | `misconfig_disable_storage_logging` | - | ❌ Not Detected |
| M15 | SQL Logging Disabled | `misconfig_disable_sql_logging` | `sqldatabase-servers-no-auditing` | ⚠️ Partial |
| M16 | Short Log Retention | `misconfig_short_log_retention` | - | ❌ Not Detected |

### Confirmation: 7 / 16 Detected (43.75%)

---

## Gap Analysis - ScoutSuite Blind Spots

The following 9 misconfigurations are **NOT detected** by ScoutSuite.
These gaps are covered by Prowler and/or Steampipe in the CloudGuardian multi-tool pipeline.

### Storage Gaps (3)

| Misconfig | Why ScoutSuite Misses It | Covered By |
|-----------|------------------------|------------|
| M4 - TLS 1.0 | No rule checking `minimum_tls_version` on storage accounts | Prowler ✅, Steampipe ✅ |
| M5 - Shared Key Access | No rule checking `allow_shared_key_access` property | Steampipe ✅ |
| M6 - CORS wildcard | No rule inspecting CORS configuration on blob services | Steampipe ✅ |

### IAM/RBAC Gaps (2)

| Misconfig | Why ScoutSuite Misses It | Covered By |
|-----------|------------------------|------------|
| M7 - Owner at RG scope | Only checks generic RBAC (resource locks), not specific overprivileged role assignments | Prowler ✅, Steampipe ✅ |
| M8 - VM Managed Identity | Does not evaluate managed identity role assignments at subscription scope | Steampipe ✅ |

### Compute Gap (1)

| Misconfig | Why ScoutSuite Misses It | Covered By |
|-----------|------------------------|------------|
| M9 - SSH Password Auth | VM checks limited to disk encryption; no SSH authentication method inspection | Prowler ✅, Steampipe ✅ |

### Network Gap (1)

| Misconfig | Why ScoutSuite Misses It | Covered By |
|-----------|------------------------|------------|
| M12 - Subnet NSG removed | Checks NSG *rules* but not whether NSGs are *associated* with subnets | Steampipe ✅ |

### Logging/Monitoring Gaps (2)

| Misconfig | Why ScoutSuite Misses It | Covered By |
|-----------|------------------------|------------|
| M14 - Storage Diagnostics | Checks Activity Log alerts but not per-resource diagnostic settings | Steampipe ✅ |
| M16 - Log Retention | No check on Log Analytics workspace retention period | Steampipe ✅ |

---

## Cross-Tool Comparison Matrix

| # | Misconfiguration | Prowler | ScoutSuite | Steampipe |
|---|-----------------|---------|------------|-----------|
| M1 | Public Blob Container | ✅ FAIL | ✅ danger | ✅ Query 2 |
| M2 | Public Network Access | ✅ FAIL | ✅ warning | ✅ Query 1 |
| M3 | Secure Transfer Disabled | ✅ FAIL | ✅ warning | ✅ Query 1 |
| M4 | Min TLS Lowered | ✅ FAIL | ❌ | ✅ Query 1 |
| M5 | Shared Key Access | ❌ | ❌ | ✅ Query 11b |
| M6 | CORS Allow All | ❌ | ❌ | ✅ Query 11a |
| M7 | Owner at RG Scope | ✅ FAIL | ❌ | ✅ Query 3 |
| M8 | VM Identity Overprivileged | ❌ | ❌ | ✅ Query 3 |
| M9 | SSH Password Auth | ✅ FAIL | ❌ | ✅ Query 6 |
| M10 | SSH Open to Internet | ✅ FAIL | ✅ warning | ✅ Query 5 |
| M11 | NSG Allow Any-Any | ✅ FAIL | ✅ danger | ✅ Query 5 |
| M12 | Subnet NSG Removed | ❌ | ❌ | ✅ Query 9 |
| M13 | SQL Allow All IPs | ✅ FAIL | ✅ warning | ✅ Query 4 |
| M14 | Storage Logging Disabled | ✅ FAIL | ❌ | ✅ Query 8 |
| M15 | SQL Logging Disabled | ✅ FAIL | ⚠️ partial | ✅ Query 10 |
| M16 | Short Log Retention | ✅ FAIL | ❌ | ✅ Query 12 |
| | **TOTAL** | **~12/16 (75%)** | **7/16 (44%)** | **16/16 (100%)** |

> **Conclusion:** No single CSPM tool detects all 16 misconfigurations. The combination of
> Prowler (broad CIS coverage), ScoutSuite (visual dashboard + network/storage depth),
> and Steampipe (precision SQL targeting) achieves **100% coverage** - validating the
> CloudGuardian multi-tool approach.

---

## Appendix: ScoutSuite Command Reference

### Scan Execution
```bash
# Activate ScoutSuite environment
conda activate scout_env

# Run baseline scan
yes y | python cspm/run_scout.py azure --cli --report-dir scoutsuite-report/baseline

# Run insecure scan (after misconfigs injected)
yes y | python cspm/run_scout.py azure --cli --report-dir scoutsuite-report/insecure
```

### Report Locations
| Report | Path |
|--------|------|
| Insecure HTML Dashboard | `scoutsuite-report/insecure/azure-tenant-fd9388b0-*.html` |
| Baseline HTML Dashboard | `scoutsuite-report/baseline/azure-tenant-fd9388b0-*.html` |
| Insecure Raw JSON | `scoutsuite-report/insecure/scoutsuite-results/scoutsuite_results_*.js` |
| Baseline Raw JSON | `scoutsuite-report/baseline/scoutsuite-results/scoutsuite_results_*.js` |
