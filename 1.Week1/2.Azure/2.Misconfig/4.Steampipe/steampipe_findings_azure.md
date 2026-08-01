# Steampipe Targeted Query Report - Azure
## CloudGuardian - CAP-CSE-3W | IIT Roorkee × Futurense
### PG Certificate in AI/GenAI Powered Cybersecurity

---

| Field | Detail |
|-------|--------|
| **Student** | Vinay |
| **Azure Subscription** | 7e3283a3-d466-4e6f-95b1-543eec016e08 |
| **Region** | Central US |
| **Resource Group** | rg-cloudguardian-lab |
| **Tool** | Steampipe v2.4.4 + Azure Plugin v1.x |
| **Date** | 2026-07-03 |
| **Purpose** | Targeted SQL-based cross-validation of 16 introduced misconfigurations |

---

## What is Steampipe?

Steampipe is an open-source tool that lets you query cloud infrastructure using SQL.
Instead of clicking through the Azure Portal, you write queries like:

```sql
SELECT name, enable_https_traffic_only FROM azure_storage_account;
```

It acts as the **third CSPM tool** (after Prowler and ScoutSuite) for precise,
targeted verification of specific misconfigurations.

---

## Prowler Scan Summary (Context)

Before Steampipe queries, Prowler full scan results:

```
Executing checks against Azure subscription...

Overview Results:
┌──────────────────────────┬────────────────────┬────────────────┐
│ 85.14% (126) Failed      │ 14.86% (22) Passed │ 0.0% (0) Muted │
└──────────────────────────┴────────────────────┴────────────────┘

Subscription 7e3283a3-d466-4e6f-95b1-543eec016e08 | Region: Central US
```

| Service | FAIL Count | Critical | High | Medium | Low |
|---------|------------|----------|------|--------|-----|
| defender | 30 | - | 30 | - | - |
| monitor | 26 | - | 11 | 15 | - |
| entra | 20 | 2 | 8 | 10 | - |
| network | 17 | - | 5 | 10 | 2 |
| storage | 15 | - | 5 | 8 | 2 |
| sqlserver | 9 | - | 5 | 3 | 1 |
| vm | 7 | - | 3 | 4 | - |
| appinsights | 2 | - | - | - | 2 |

> Output files saved at:
> - CSV: `prowler-report/insecure/prowler-insecure.csv`
> - HTML: `prowler-report/insecure/prowler-insecure.html`
> - JSON-OCSF: `prowler-report/insecure/prowler-insecure.ocsf.json`

---

## Steampipe Setup

```bash
# Install Azure plugin
steampipe plugin install azure

# Start interactive query mode
steampipe query
```

> **Note:** Ensure Azure CLI is authenticated (`az login`) before running Steampipe queries.
> The Azure plugin uses the default Azure CLI credential chain.

---

## Query 1 - Storage Account Public Access & Transport Security

### Misconfig Introduced
- Public network access set to "Allow" (open to internet) - `misconfig_storage_allow_public_network_access`
- HTTPS-only disabled (`enable_https_traffic_only = false`) - `misconfig_storage_disable_secure_transfer`
- Minimum TLS version lowered to TLS 1.0 - `misconfig_storage_min_tls_version`

### SQL Query
```sql
select name, allow_blob_public_access,
       enable_https_traffic_only, minimum_tls_version,
       network_rule_default_action
from azure_storage_account
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+---------------------------+---------------------------+----------------------------+---------------------+-----------------------------+
| name                      | allow_blob_public_access  | enable_https_traffic_only  | minimum_tls_version | network_rule_default_action |
+---------------------------+---------------------------+----------------------------+---------------------+-----------------------------+
| stcloudguardianlab6thil   | true                      | false                      | TLS1_0              | Allow                       |
+---------------------------+---------------------------+----------------------------+---------------------+-----------------------------+
1 row
```

### Screenshot
![Query 1 Result](./images/Q1%20Storage%20Account%20Security%20Settings.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| allow_blob_public_access | true | false | ℹ️ AZURE DEFAULT (prerequisite for Q2 container access) |
| enable_https_traffic_only | false | true | ❌ MISCONFIG (`misconfig_storage_disable_secure_transfer`) |
| minimum_tls_version | TLS1_0 | TLS1_2 | ❌ MISCONFIG (`misconfig_storage_min_tls_version`) |
| network_rule_default_action | Allow | Deny | ❌ MISCONFIG (`misconfig_storage_allow_public_network_access`) |

**Risk:** Storage account `stcloudguardianlab6thil` accepts unencrypted HTTP traffic,
permits obsolete TLS 1.0 connections, and is open to all networks. The
`allow_blob_public_access = true` is an Azure default that enables the container-level
public access tested in Query 2. This is a multi-layered data exposure vulnerability.

---

## Query 2 - Storage Container Public Access Level

### Misconfig Introduced
Blob container `app-data` set to public access level `blob` - anyone with the URL can read files.

### SQL Query
```sql
select name, public_access
from azure_storage_container
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+----------+---------------+
| name     | public_access |
+----------+---------------+
| app-data | Blob          |
+----------+---------------+
1 row
```

### Screenshot
![Query 2 Result](./images/Q2%20Storage%20Container%20Public%20Access%20Level.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| public_access | Blob | None (private) | ❌ MISCONFIG |

**Risk:** Container `app-data` is world-readable. Any user with the blob URL
can download sensitive files - the classic "public S3/blob bucket" data leak.

---

## Query 3 - IAM Over-Privileged Role Assignments

### Misconfig Introduced
- `Owner` role assigned at Resource Group scope (excessive human identity privilege)
- `Contributor` role assigned to VM managed identity at Subscription scope (over-privileged service identity)

### SQL Query
```sql
select a.principal_type, d.role_name, a.scope
from azure_role_assignment as a
join azure_role_definition as d
  on a.role_definition_id = d.id
where d.role_name in ('Owner', 'Contributor')
  and a.scope like '%cloudguardian%';
```

### Result
```
+------------------+-----------+---------------------------------------------------------------------+
| principal_type   | role_name | scope                                                               |
+------------------+-----------+---------------------------------------------------------------------+
| ServicePrincipal | Owner     | /subscriptions/.../resourceGroups/rg-cloudguardian-lab              |
| ServicePrincipal | Contributor| /subscriptions/7e3283a3-d466-4e6f-95b1-543eec016e08                |
+------------------+-----------+---------------------------------------------------------------------+
2 rows
```

### Screenshot
![Query 3 Result](./images/Q3%20IAM%20Over-Privileged%20Role%20Assignments.PNG)

### Analysis
| Principal | Role | Scope | Expected (Secure) | Status |
|-----------|------|-------|--------------------|--------|
| Deploying identity | Owner | Resource Group | Scoped custom role | ❌ MISCONFIG |
| VM Managed Identity | Contributor | Subscription | Reader at RG only | ❌ MISCONFIG |

**Risk:** The deploying identity has `Owner` at RG level - full control including
delete. The VM's managed identity has `Contributor` at subscription scope. If the
web server is compromised, an attacker can control the entire Azure subscription.

---

## Query 4 - SQL Server Firewall Rules

### Misconfig Introduced
SQL Server firewall rule allows traffic from `0.0.0.0` to `255.255.255.255` - database
exposed to entire internet.

### SQL Query
```sql
select
  server.name as server_name,
  rule ->> 'name' as rule_name,
  rule -> 'properties' ->> 'startIpAddress' as start_ip_address,
  rule -> 'properties' ->> 'endIpAddress' as end_ip_address
from
  azure_sql_server as server,
  jsonb_array_elements(firewall_rules) as rule
where
  server.name = 'sql-cloudguardian-lab-6thil';
```

### Result
```
+-----------------------------+-----------------------+------------------+-----------------+
| server_name                 | rule_name             | start_ip_address | end_ip_address  |
+-----------------------------+-----------------------+------------------+-----------------+
| sql-cloudguardian-lab-6thil | AllowAzureServices    | 0.0.0.0          | 0.0.0.0         |
| sql-cloudguardian-lab-6thil | AllowMyIP             | 103.170.81.198   | 103.170.81.198  |
| sql-cloudguardian-lab-6thil | MISCONFIG-AllowAllIPs | 0.0.0.0          | 255.255.255.255 |
+-----------------------------+-----------------------+------------------+-----------------+
3 rows
```

### Screenshot
![Query 4 Result](./images/Q4%20SQL%20Server%20Firewall%20Rules.PNG)

### Analysis
| Rule | Start IP | End IP | Status |
|------|----------|--------|--------|
| AllowAzureServices | 0.0.0.0 | 0.0.0.0 | ℹ️ Azure internal |
| AllowIP | 103.170.81.198 | 103.170.81.198 | ✅ OK |
| MISCONFIG-AllowAllIPs | 0.0.0.0 | 255.255.255.255 | ❌ MISCONFIG |

**Risk:** The `MISCONFIG-AllowAllIPs` rule exposes the SQL server to the entire
IPv4 address space. Attackers can directly attempt SQL injection, credential
brute-forcing, or other database attacks without any network barrier.

---

## Query 5 - NSG Security Rules (SSH Open to Internet)

### Misconfig Introduced
- NSG rule opens SSH (port 22) to `*` (entire internet)
- Additional rule allows ANY protocol, ANY port, from ANY source

### SQL Query
```sql
select
  nsg.name as nsg_name,
  rule ->> 'name' as rule_name,
  rule -> 'properties' ->> 'protocol' as protocol,
  rule -> 'properties' ->> 'destinationPortRange' as dest_port,
  rule -> 'properties' ->> 'sourceAddressPrefix' as source,
  rule -> 'properties' ->> 'access' as access
from
  azure_network_security_group as nsg,
  jsonb_array_elements(security_rules) as rule
where
  nsg.name = 'nsg-web-cloudguardian-lab'
  and rule -> 'properties' ->> 'direction' = 'Inbound'
  and rule -> 'properties' ->> 'access' = 'Allow';
```

### Result
```
+--------------------------+-------------------------+----------+-----------+----------+-------+
| nsg_name                 | rule_name               | protocol | dest_port | source   | access|
+--------------------------+-------------------------+----------+-----------+----------+-------+
| nsg-web-cloudguardian-lab| Allow-HTTPS-Internet    | Tcp      | 443       | Internet | Allow |
| nsg-web-cloudguardian-lab| Allow-HTTP-Internet     | Tcp      | 80        | Internet | Allow |
| nsg-web-cloudguardian-lab| Allow-SSH               | Tcp      | 22        | *        | Allow |
| nsg-web-cloudguardian-lab| MISCONFIG-Allow-Any-Any | *        | *         | *        | Allow |
+--------------------------+-------------------------+----------+-----------+----------+-------+
4 rows
```

### Screenshot
![Query 5 Result](./images/Q5%20NSG%20Security%20Rules.PNG)

### Analysis
| Rule | Port | Protocol | Source | Status |
|------|------|----------|--------|--------|
| Allow-HTTPS-Internet | 443 | Tcp | Internet | ✅ OK |
| Allow-HTTP-Internet | 80 | Tcp | Internet | ✅ OK |
| Allow-SSH | 22 | Tcp | * | ❌ MISCONFIG |
| MISCONFIG-Allow-Any-Any | * | * | * | ❌ MISCONFIG |

**Risk:** SSH (port 22) is open to the entire internet, inviting automated brute-force
attacks. The `Allow-Any-Any` rule completely disables network perimeter defense -
all ports and services on the VM are exposed.

---

## Query 6 - VM Password Authentication

### Misconfig Introduced
VM SSH password authentication enabled instead of key-only - weak authentication.

### SQL Query
```sql
select name,
       disable_password_authentication,
       os_type
from azure_compute_virtual_machine
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+--------------------------+----------------------------------+---------+
| name                     | disable_password_authentication  | os_type |
+--------------------------+----------------------------------+---------+
| vm-web-cloudguardian-lab | false                            | Linux   |
+--------------------------+----------------------------------+---------+
1 row
```

### Screenshot
![Query 6 Result](./images/Q6%20VM%20Password%20Authentication.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| disable_password_authentication | false | true | ❌ MISCONFIG |

**Risk:** SSH password authentication is enabled. Passwords can be brute-forced
or guessed. Combined with port 22 open to internet (Query 5), this creates a
direct attack vector for ransomware and botnet infections.

> **Note:** This is the Azure equivalent of Megha's AWS "EC2 IMDSv1" finding.
> Azure IMDS has no v1/v2 toggle - the closest "weak authentication" finding
> on Azure is password-based SSH being allowed.

---

## Query 7 - OS Disk Encryption (Informational - AWS Cross-Reference)

### Context
This query has **no corresponding misconfig toggle** in the Azure Terraform deployment.
It exists for cross-platform comparison with Megha's AWS Q5 (EBS Unencrypted).
Azure managed disks are **always encrypted with SSE** by default - unlike AWS EBS
which can be completely unencrypted.

### SQL Query
```sql
select name, encryption_type, disk_state, managed_by
from azure_compute_disk
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+------------------------------------------------------------+--------------------------------------+------------+--------------------------+
| name                                                       | encryption_type                      | disk_state | managed_by               |
+------------------------------------------------------------+--------------------------------------+------------+--------------------------+
| vm-web-cloudguardian-lab_OsDisk_1_2fc96adf487d4936ad28c87c9| EncryptionAtRestWithPlatformKey      | Attached   | vm-web-cloudguardian-lab |
+------------------------------------------------------------+--------------------------------------+------------+--------------------------+
1 row
```

### Screenshot
![Query 7 Result](./images/Q7%20OS%20Disk%20Encryption.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| encryption_type | EncryptionAtRestWithPlatformKey | EncryptionAtRestWithCustomerKey | ℹ️ AZURE DEFAULT |
| disk_state | Attached | - | ℹ️ Active |

**Observation:** OS disk is encrypted with Azure-managed keys (SSE-PMK) - the platform
default. This is **NOT one of the 16 deliberate misconfigurations**. CIS benchmarks
recommend CMK for sensitive workloads, but the absence of CMK is a governance gap, not
a missing encryption vulnerability. Unlike AWS EBS, Azure disks cannot be unencrypted.

---

## Query 8 - Diagnostic Settings (Storage & SQL Logging)

### Misconfig Introduced
- Storage blob diagnostic settings not configured (no logging of read/write/delete)
- SQL database diagnostic settings disabled (no audit trail)

### SQL Query
```sql
select name, id
from azure_diagnostic_setting
where id like '%cloudguardian%';
```

### Result
```
+------+----+
| name | id |
+------+----+
+------+----+
0 rows
```

### Screenshot
![Query 8 Result](./images/Q8%20Diagnostic%20Settings%20(Storage%20&%20SQL).PNG)

### Analysis
| Finding | Status |
|---------|--------|
| Storage blob diagnostic settings | 0 (none exist) ❌ MISCONFIG |
| SQL database diagnostic settings | 0 (none exist) ❌ MISCONFIG |

**Risk:** Zero diagnostic settings means no record of any blob read/write/delete
operations or SQL queries/errors. Data exfiltration and unauthorized database
access would be completely undetectable.

---

## Query 9 - Subnet NSG Associations

### Misconfig Introduced
Network Security Group association removed from the web subnet - no network-layer
filtering at all.

### SQL Query
```sql
select name, virtual_network_name,
       network_security_group_id
from azure_subnet
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+-----------------------------+------------------------+---------------------------+
| name                        | virtual_network_name   | network_security_group_id |
+-----------------------------+------------------------+---------------------------+
| snet-web-cloudguardian-lab  | vnet-cloudguardian-lab | <null>                    |
| snet-data-cloudguardian-lab | vnet-cloudguardian-lab | <null>                    |
+-----------------------------+------------------------+---------------------------+
2 rows
```

### Screenshot
![Query 9 Result](./images/Q9%20Subnet%20NSG%20Associations.PNG)

### Analysis
| Subnet | NSG Attached | Expected (Secure) | Status |
|--------|--------------|--------------------|--------|
| snet-web-cloudguardian-lab | null (none) | nsg-web-cloudguardian-lab | ❌ MISCONFIG |
| snet-data-cloudguardian-lab | null (none) | dedicated NSG | ❌ MISCONFIG |

**Risk:** Without NSG associations, subnets fall back to default VNet rules.
Combined with a public IP on the VM, this bypasses all carefully crafted security
boundaries and exposes services directly to the internet.

---

## Query 10 - SQL Server TLS & Auditing

### Misconfig Introduced
- SQL Server auditing disabled (no audit policy configured)
- SQL Server minimum TLS verified (remains 1.2 - Azure enforced)

### SQL Query
```sql
select name, minimal_tls_version,
       server_audit_policy ->> 'state' as audit_state
from azure_sql_server
where name like '%cloudguardian%';
```

### Result
```
+-----------------------------+---------------------+-------------+
| name                        | minimal_tls_version | audit_state |
+-----------------------------+---------------------+-------------+
| sql-cloudguardian-lab-6thil | 1.2                 | <null>      |
+-----------------------------+---------------------+-------------+
1 row
```

### Screenshot
![Query 10 Result](./images/Q10%20SQL%20Server%20TLS%20&%20Auditing.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| minimal_tls_version | 1.2 | 1.2 | ✅ OK (Azure enforced) |
| audit_state | <null> | Enabled | ❌ MISCONFIG |

**Risk:** SQL auditing is disabled. Failed login attempts, SQL injection attacks,
and unauthorized queries leave no trace. Azure enforces TLS 1.2 as minimum for
SQL Server since August 2025, so TLS downgrade is not possible.

---

## Query 11 - Storage Account CORS & Authentication Default

### Misconfig Introduced
- CORS rules set to allow `*` (all origins, all methods)
- Storage account defaults to Shared Key authentication instead of Microsoft Entra ID

### SQL Query (CORS)
```sql
select storage_account_name as name,
       cors_rules
from azure_storage_blob_service
where storage_account_name = 'stcloudguardianlab6thil';
```

### Result
```
+---------------------------+---------------------------------------------------------------------+
| name                      | cors_rules                                                          |
+---------------------------+---------------------------------------------------------------------+
| stcloudguardianlab6thil   | [{"allowedOrigins":["*"],"allowedMethods":["GET","PUT","POST",      |
|                           |   "DELETE","HEAD","MERGE","OPTIONS"],"allowedHeaders":["*"],         |
|                           |   "exposedHeaders":["*"],"maxAgeInSeconds":3600}]                   |
+---------------------------+---------------------------------------------------------------------+
1 row
```

### SQL Query (Auth Default)
```sql
select name, default_to_oauth_authentication
from azure_storage_account
where name = 'stcloudguardianlab6thil';
```

### Result
```
+---------------------------+----------------------------------+
| name                      | default_to_oauth_authentication  |
+---------------------------+----------------------------------+
| stcloudguardianlab6thil   | false                            |
+---------------------------+----------------------------------+
1 row
```

### Screenshot
![Query 11a Result](./images/Q11a%20Storage%20Account%20CORS%20&%20Auth%20Default.PNG)
![Query 11b Result](./images/Q11b%20Storage%20Account%20CORS%20&%20Auth%20Default.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| CORS allowedOrigins | * (all origins) | specific domains only | ❌ MISCONFIG |
| CORS allowedMethods | all 7 HTTP methods | GET, HEAD only | ❌ MISCONFIG |
| default_to_oauth_authentication | false | true (Microsoft Entra ID) | ❌ MISCONFIG |

**Risk:** CORS allows any website to make cross-origin API calls to read or
delete storage data on behalf of an authenticated user. Defaulting to Shared Key
authentication means permanent access keys are used instead of identity-based
access - keys are harder to scope, audit, and rotate.

---

## Query 12 - Log Analytics Workspace Retention

### Misconfig Introduced
Log Analytics workspace retention reduced from 90 days to 30 days.

### SQL Query
```sql
select name, retention_in_days, sku ->> 'name' as sku_name
from azure_log_analytics_workspace
where resource_group = 'rg-cloudguardian-lab';
```

### Result
```
+------------------------+-------------------+----------+
| name                   | retention_in_days | sku_name |
+------------------------+-------------------+----------+
| log-cloudguardian-lab  | 30                | PerGB2018|
+------------------------+-------------------+----------+
1 row
```

### Screenshot
![Query 12 Result](./images/Q12%20Log%20Analytics%20Workspace%20Retention.PNG)

### Analysis
| Field | Value | Expected (Secure) | Status |
|-------|-------|-------------------|--------|
| retention_in_days | 30 | 90+ | ❌ MISCONFIG |

**Risk:** APT dwell time averages 100+ days. With only 30-day retention,
historical evidence is destroyed before an investigation can begin. Forensic
analysis of breaches becomes impossible.

---

## All 16 Misconfigs - Steampipe Confirmation Summary

Each row maps 1:1 to a Terraform toggle in [`variables.tf`](file:///C:/Users/DELL/Documents/Capstone/CSE/2.%20azure-3tier-terraform%20(Misconfigs)/variables.tf).

| # | Category | Misconfig | Terraform Toggle | Query | Status |
|---|----------|-----------|-----------------|-------|--------|
| M1 | Storage | Public Blob Container (access = blob) | `misconfig_storage_public_container` | Q2 | ❌ CONFIRMED |
| M2 | Storage | Public Network Access (default_action = Allow) | `misconfig_storage_allow_public_network_access` | Q1 | ❌ CONFIRMED |
| M3 | Storage | Secure Transfer Disabled (HTTP allowed) | `misconfig_storage_disable_secure_transfer` | Q1 | ❌ CONFIRMED |
| M4 | Storage | Min TLS Lowered to 1.0 | `misconfig_storage_min_tls_version` | Q1 | ❌ CONFIRMED |
| M5 | Storage | Shared Key Auth Default (not Entra ID) | `misconfig_storage_allow_shared_key_access` | Q11 | ❌ CONFIRMED |
| M6 | Storage | CORS Allow All Origins | `misconfig_storage_cors_allow_all` | Q11 | ❌ CONFIRMED |
| M7 | IAM | Owner Role at Resource Group Scope | `misconfig_iam_owner_role_at_rg_scope` | Q3 | ❌ CONFIRMED |
| M8 | IAM | VM Identity Contributor at Subscription | `misconfig_vm_identity_over_privileged` | Q3 | ❌ CONFIRMED |
| M9 | Compute | VM SSH Password Auth Enabled | `misconfig_vm_allow_password_auth` | Q6 | ❌ CONFIRMED |
| M10 | Networking | SSH Port 22 Open to Internet | `misconfig_ssh_open_to_internet` | Q5 | ❌ CONFIRMED |
| M11 | Networking | NSG Allow Any-Any Rule | `misconfig_nsg_allow_any_any` | Q5 | ❌ CONFIRMED |
| M12 | Networking | Subnet NSG Association Removed | `misconfig_vm_remove_nsg_association` | Q9 | ❌ CONFIRMED |
| M13 | Database | SQL Firewall Allow All IPs (0.0.0.0-255.255.255.255) | `misconfig_sql_allow_all_ips` | Q4 | ❌ CONFIRMED |
| M14 | Logging | Storage Diagnostic Settings Disabled | `misconfig_disable_storage_logging` | Q8 | ❌ CONFIRMED |
| M15 | Logging | SQL Diagnostic Settings Disabled | `misconfig_disable_sql_logging` | Q8 | ❌ CONFIRMED |
| M16 | Logging | Log Retention Shortened to 30 days | `misconfig_short_log_retention` | Q12 | ❌ CONFIRMED |

**Confirmation Rate: 16/16 (100%) ✅**

> **Note:** Query 7 (OS Disk Encryption) is included for AWS cross-platform comparison only.
> Azure managed disks are always encrypted with SSE by default - this is NOT one of the 16
> deliberate misconfigurations. The `allow_blob_public_access = true` finding in Q1 is an
> Azure default (prerequisite for M1's container-level access), not a separate toggle.

---

## Cross-Tool Comparison

| Service | Prowler FAILs | ScoutSuite Findings | Steampipe Confirms | Agreement |
|---------|---------------|--------------------|--------------------|-----------|
| Storage | 15 | Public access + TLS + CORS | ✅ Public + HTTP + TLS 1.0 + CORS + SharedKey | ✅ |
| Network/NSG | 17 | SSH + open ports | ✅ SSH open + Any-Any + NSG removed | ✅ |
| SQL Server | 9 | Firewall + audit | ✅ Allow-all firewall + audit disabled | ✅ |
| Compute/VM | 7 | Password auth | ✅ Password auth + disk PMK only | ✅ |
| IAM | (via entra: 20) | Role assignments | ✅ Owner at RG + Contributor at subscription | ✅ |
| Logging/Monitor | 26 | Diagnostic gaps | ✅ Missing diag settings + short retention | ✅ |

**Cross-tool agreement: 100%** - All three tools confirm the same misconfigurations.

---

## AWS ↔ Azure Comparison - Teammate Reference

This section maps Megha's 12 AWS Steampipe findings to the equivalent Azure queries above,
demonstrating platform parity across the CloudGuardian project.

| Megha's AWS Query | AWS Service | Azure Equivalent Query | Azure Service | Key Difference |
|---|---|---|---|---|
| Q1: S3 Public Access | S3 | Q1 + Q2: Storage Public Access | Storage Account + Container | Azure separates account vs container settings |
| Q2: IAM User MFA | IAM | Q3: Role Assignments | Azure RBAC | Azure uses RBAC roles, not per-user MFA toggles |
| Q3: RDS Public + Unencrypted | RDS | Q4 + Q10: SQL Firewall + Audit | SQL Server | Azure SQL TDE always ON; firewall is the risk |
| Q4: SG SSH Open | VPC SG | Q5: NSG SSH Open | NSG | NSG rules in JSONB array; same concept |
| Q5: EBS Unencrypted | EBS | Q7: Disk Encryption | Managed Disk | Azure SSE always ON; finding is PMK vs CMK |
| Q6: EC2 IMDSv1 | EC2 IMDS | Q6: VM Password Auth | VM Auth | No Azure IMDS toggle; closest is weak SSH auth |
| Q7: CloudTrail Disabled | CloudTrail | Q8: Diagnostic Settings | Monitor | Azure uses per-resource diagnostic settings |
| Q8: IAM Admin Role | IAM Role | Q3: Over-privileged Roles | Azure RBAC | Same concept; Azure scope = subscription/RG |
| Q9: NACL All Open | VPC NACL | Q5 + Q9: NSG Any-Any + Subnet | NSG + Subnet | Azure has no separate NACL; NSG serves both |
| Q10: RDS SSL Not Enforced | RDS | Q10: SQL TLS Version | SQL Server | Azure retired TLS < 1.2 for SQL in Aug 2025 |
| Q11: S3 Versioning | S3 | Q11: CORS + Auth Default | Storage Account | Versioning vs CORS/auth - different storage risks |
| - | - | Q12: Log Retention | Log Analytics | Azure-only: shortened workspace retention |

---

## File Saved Location

```
steampipe-findings_Azure/
├── steampipe_storage.csv     ← Query 1 + 2 + 11 results
├── steampipe_iam.csv         ← Query 3 results
├── steampipe_sql.csv         ← Query 4 + 10 results
├── steampipe_nsg.csv         ← Query 5 + 9 results
├── steampipe_compute.csv     ← Query 6 + 7 results
├── steampipe_logging.csv     ← Query 8 + 12 results
└── steampipe_findings_azure.md ← This report
```

---

## References

- Steampipe Documentation: https://steampipe.io/docs
- Azure Plugin Hub: https://hub.steampipe.io/plugins/turbot/azure
- CIS Azure Benchmark: https://www.cisecurity.org/cis-benchmarks
- MITRE ATT&CK Cloud: https://attack.mitre.org/matrices/enterprise/cloud/
- Azure Misconfiguration Catalogue: `misconfigs/azure_misconfiguration_catalogue.md`
- Prowler Azure Scan: `prowler-report/insecure/prowler-insecure.csv`

---

*Report generated for CAP-CSE-3W CloudGuardian Capstone - IIT Roorkee × Futurense Cohort 1*
