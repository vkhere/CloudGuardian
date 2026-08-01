# CloudGuardian - Azure 3-Tier Reference Workload (Terraform)

Maps the capstone's brief onto Azure:

| Capstone brief says | This deploys |
|---|---|
| VPC, two subnets | `azurerm_virtual_network` + `web` and `data` subnets |
| Web tier | `azurerm_linux_virtual_machine` (Ubuntu 22.04) with public IP + NSG |
| Small RDS/SQL instance | `azurerm_mssql_server` + `azurerm_mssql_database` (Basic tier) |
| Object-storage bucket | `azurerm_storage_account` + `azurerm_storage_container` |
| (implicit) logging | `azurerm_log_analytics_workspace` + diagnostic settings on Storage/SQL |

Eleven `.tf` files, all secure-by-default, with **sixteen boolean toggles**
that let you intentionally introduce specific misconfigurations on demand -
see "Misconfiguration toggles" below. That's your Week 1 catalogue built
into the code instead of bolted on afterwards.

## 1. Prerequisites

- Terraform >= 1.7.0
- An Azure subscription (free/student account is fine) + `az login` already
  done, or a service principal exported as `ARM_CLIENT_ID` /
  `ARM_CLIENT_SECRET` / `ARM_SUBSCRIPTION_ID` / `ARM_TENANT_ID`
- An SSH key pair (`ssh-keygen -t rsa -b 4096` if you don't have one)
- Your current public IP (https://ifconfig.me)

## 2. Setup

```bash
cd azure-3tier-terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: my_ip_cidr, ssh_public_key, sql_admin_username

export TF_VAR_sql_admin_password="PickA-Strong-Password123!"

terraform init
terraform plan
terraform apply
```

After apply, `terraform output web_vm_ssh_command` gives you the SSH command,
and the VM serves a placeholder nginx page on its public IP over HTTP.

**Tear down when you're done for the day:** `terraform destroy`. The VM,
public IP, and SQL Basic tier all cost a little even when idle - don't leave
this running unattended on a free-account budget.

## 3. Misconfiguration toggles (Week 1 deliverable)

All sixteen default to the **secure** setting. Set any of these to `true`
in `terraform.tfvars`, then `terraform apply`, to deliberately introduce
that finding:

| Variable | Misconfig it creates | Category |
|---|---|---|
| `misconfig_storage_public_container` | Blob container readable by anyone | Storage |
| `misconfig_storage_allow_public_network_access` | Storage account reachable from any network | Storage / Network |
| `misconfig_sql_allow_all_ips` | SQL firewall rule `0.0.0.0-255.255.255.255` | Network / Database |
| `misconfig_ssh_open_to_internet` | NSG allows SSH (22) from `0.0.0.0/0` | Network |
| `misconfig_vm_allow_password_auth` | VM accepts SSH password auth, not just keys | IAM / Auth |
| `misconfig_disable_storage_logging` | Storage diagnostic settings skipped entirely | Logging |
| `misconfig_storage_allow_shared_key_access` | Storage account defaults to Shared Key auth in Portal/tools instead of Microsoft Entra ID | IAM |
| `misconfig_iam_owner_role_at_rg_scope` | Owner role assigned at Resource Group scope, not a scoped role | IAM |
| `misconfig_vm_identity_over_privileged` | Web VM's managed identity granted Contributor at subscription scope | IAM |
| `misconfig_storage_disable_secure_transfer` | Storage account reachable over plain HTTP | Encryption |
| `misconfig_storage_min_tls_version` | Storage account minimum TLS lowered to TLS1_0 | Encryption |
| `misconfig_vm_remove_nsg_association` | NSG detached from the web subnet entirely - no firewall at all | Network |
| `misconfig_nsg_allow_any_any` | Standalone NSG rule allowing any protocol/port from any source | Network |
| `misconfig_disable_sql_logging` | SQL diagnostic setting skipped, independently of storage logging | Logging |
| `misconfig_short_log_retention` | Log Analytics retention shortened from 90 to 30 days | Logging |
| `misconfig_storage_cors_allow_all` | Storage account CORS rules allow any origin/method | Storage |

`terraform output active_misconfigs` gives you a clean true/false summary to
paste straight into your misconfig catalogue table.

> **Note on SQL Encryption:** Two additional misconfigurations (`misconfig_sql_disable_tde` and `misconfig_sql_min_tls_version`) were originally planned but have been removed from the code. Azure now enforces TDE on all Standard/Basic SKUs and retired TLS 1.0/1.1 at the platform level, making it impossible to deliberately misconfigure them via Terraform without errors.

This comfortably clears the rubric's minimum of 8 (individual) or 12+
(team), spread across all five required categories (IAM, Storage,
Networking, Encryption, Logging).

> **Note on `misconfig_iam_owner_role_at_rg_scope` and
> `misconfig_vm_identity_over_privileged`:** both create a real Azure role
> assignment, which needs `Microsoft.Authorization/roleAssignments/write`
> permission. On a free/student subscription the signup account is normally
> the subscription's Owner, so this should just work - but if `apply` fails
> with `AuthorizationFailed` on either one, document that finding manually
> instead via Portal → Resource Group → Access control (IAM) → Add role
> assignment, the same way you've already handled Prowler's AAD-level check
> failures.

> **Note on `misconfig_vm_allow_password_auth`:** also requires setting
> `vm_admin_password` (Azure requires a password whenever password auth is
> permitted, even alongside an SSH key) - set it via
> `TF_VAR_vm_admin_password`, never in `terraform.tfvars` directly.

## 4. Detecting these with your Week 2 stack

```bash
# Prowler
pipx install prowler
prowler azure --az-cli-auth --output-formats json csv html

# Checkov (scans the .tf code itself, no cloud creds needed)
pip install checkov
checkov -d .

# Steampipe (Azure plugin)
steampipe plugin install azure
steampipe query "select name, allow_blob_public_access from azure_storage_account"
```

## 5. Cost / free-account notes

- VM `Standard_D2s_v3`: check your subscription's quota; destroy between sessions if budget-conscious
- SQL `Basic` tier: ~$5/month if left running - destroy between sessions
- Storage account, Log Analytics (7-30 day retention), NSG, VNet: negligible/free at this scale
- Nothing here touches management groups or tenant-level resources, so it works fine on a constrained student/guest subscription

## 6. File map

| File | Contents |
|---|---|
| `versions.tf` | Terraform + provider version pinning |
| `providers.tf` | Azure provider config |
| `variables.tf` | All inputs, including all 16 misconfig toggles |
| `locals.tf` | Naming convention + random unique suffix |
| `main.tf` | Resource Group + Log Analytics Workspace |
| `network.tf` | VNet, subnets, NSG |
| `compute.tf` | Public IP, NIC, Linux VM |
| `database.tf` | Azure SQL server + database |
| `storage.tf` | Storage account + container + diagnostic logging |
| `iam_and_extra_misconfigs.tf` | The two IAM role-assignment misconfigs |
| `outputs.tf` | Printed values + `active_misconfigs` summary |
