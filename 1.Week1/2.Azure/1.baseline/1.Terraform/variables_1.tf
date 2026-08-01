############################
# Core / naming
############################

variable "project_name" {
  description = "Short name used as a prefix for every resource (lowercase, no spaces)."
  type        = string
  default     = "cloudguardian"
}

variable "environment" {
  description = "Environment tag/suffix, e.g. lab, dev."
  type        = string
  default     = "lab"
}

variable "location" {
  description = "Azure region to deploy into. Central US recommended over Central India for free/student subscriptions - several VM SKUs (including the basic B-series) are commonly restricted in Central India for non-enterprise subscriptions."
  type        = string
  default     = "Central US"
}

variable "tags" {
  description = "Common tags applied to every resource."
  type        = map(string)
  default = {
    project = "CloudGuardian"
    owner   = "capstone"
  }
}

############################
# Networking
############################

variable "vnet_address_space" {
  description = "Address space for the VNet."
  type        = list(string)
  default     = ["10.10.0.0/16"]
}

variable "web_subnet_prefix" {
  description = "CIDR for the web-tier subnet."
  type        = string
  default     = "10.10.1.0/24"
}

variable "data_subnet_prefix" {
  description = "CIDR for the data-tier subnet (SQL/Storage service endpoints)."
  type        = string
  default     = "10.10.2.0/24"
}

############################
# Web tier (VM)
############################

variable "vm_size" {
  description = "VM size for the web tier. Standard_B1s is in Azure's free-account 12-month allowance in principle, but is frequently SkuNotAvailable on free/student subscriptions in many regions. Standard_D2s_v3 is a safer default - check availability for your subscription with: az vm list-skus --location <region> --resource-type virtualMachines --query \"[?restrictions[0]==null].name\" --output table"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "admin_username" {
  description = "Admin username for the web-tier VM."
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key" {
  description = "Your SSH public key contents (e.g. contents of ~/.ssh/id_rsa.pub). Required - no default on purpose."
  type        = string
}

variable "my_ip_cidr" {
  description = "Your current public IP in CIDR form (e.g. 203.0.113.10/32), used to scope SSH/admin access. Find yours at https://ifconfig.me"
  type        = string
}

############################
# Database tier
############################

variable "sql_admin_username" {
  description = "Admin login for the Azure SQL logical server."
  type        = string
  default     = "sqladminuser"
}

variable "sql_admin_password" {
  description = "Admin password for the Azure SQL logical server. Pass via TF_VAR_sql_admin_password env var or a .auto.tfvars file that is gitignored - never commit this."
  type        = string
  sensitive   = true
}

variable "sql_sku_name" {
  description = "SQL Database SKU. 'Basic' is the cheapest single-database tier (~5 DTU, 2GB)."
  type        = string
  default     = "Basic"
}

############################
# Storage tier
############################

variable "storage_account_tier" {
  description = "Storage account performance tier."
  type        = string
  default     = "Standard"
}

variable "storage_replication_type" {
  description = "Storage account replication type."
  type        = string
  default     = "LRS"
}

############################
# Misconfiguration toggles
#
# All sixteen default to the SECURE setting. Flip any of them to true in
# terraform.tfvars, then re-apply, to deliberately introduce that finding -
# this is your Week 1 "controlled misconfigurations" catalogue, built into
# the code instead of bolted on afterwards. Each one maps to a real-world
# finding Prowler/Checkov/ScoutSuite will flag.
############################

# --- Original six -----------------------------------------------------

variable "misconfig_storage_public_container" {
  description = "If true, makes the blob container publicly readable (misconfig: public storage)."
  type        = bool
  default     = false
}

variable "misconfig_storage_allow_public_network_access" {
  description = "If true, allows the storage account to be reached from any network, not just the VNet/your IP (misconfig: overly permissive network access)."
  type        = bool
  default     = false
}

variable "misconfig_sql_allow_all_ips" {
  description = "If true, adds a SQL firewall rule allowing 0.0.0.0-255.255.255.255 (misconfig: DB open to the internet)."
  type        = bool
  default     = false
}

variable "misconfig_ssh_open_to_internet" {
  description = "If true, the NSG allows inbound SSH (22) from 0.0.0.0/0 instead of just my_ip_cidr (misconfig: open management port)."
  type        = bool
  default     = false
}

variable "misconfig_vm_allow_password_auth" {
  description = "If true, enables SSH password authentication on the VM instead of key-only (misconfig: weak authentication)."
  type        = bool
  default     = false
}

variable "vm_admin_password" {
  description = "Only required if misconfig_vm_allow_password_auth = true (Azure requires an admin_password whenever password auth is enabled, even alongside an SSH key). Leave null otherwise."
  type        = string
  default     = null
  sensitive   = true
}

variable "misconfig_disable_storage_logging" {
  description = "If true, skips wiring the storage account's diagnostic settings to Log Analytics (misconfig: missing logging)."
  type        = bool
  default     = false
}

# --- Added to reach 16 total, covering IAM and Encryption properly ----

variable "misconfig_storage_allow_shared_key_access" {
  description = "If true, configures the storage account to default to Shared Key authentication in the Azure Portal/tools instead of Microsoft Entra ID (misconfig: key-based access encouraged by default, harder to audit/revoke than Entra ID identities)."
  type        = bool
  default     = false
}

variable "misconfig_iam_owner_role_at_rg_scope" {
  description = "If true, assigns the Owner role (instead of a scoped role) to the deploying identity at the Resource Group scope (misconfig: over-privileged human identity)."
  type        = bool
  default     = false
}

variable "misconfig_vm_identity_over_privileged" {
  description = "If true, grants the web VM's system-assigned managed identity the Contributor role at the subscription scope, far beyond what the VM needs (misconfig: over-privileged service identity)."
  type        = bool
  default     = false
}

variable "misconfig_storage_disable_secure_transfer" {
  description = "If true, allows the storage account to be reached over plain HTTP instead of requiring HTTPS (misconfig: unencrypted data in transit)."
  type        = bool
  default     = false
}

variable "misconfig_storage_min_tls_version" {
  description = "If true, lowers the storage account's minimum TLS version to TLS1_0 instead of TLS1_2 (misconfig: outdated transport encryption permitted)."
  type        = bool
  default     = false
}


variable "misconfig_vm_remove_nsg_association" {
  description = "If true, detaches the Network Security Group from the web subnet entirely, leaving it with no network-layer filtering at all (misconfig: missing firewall)."
  type        = bool
  default     = false
}

variable "misconfig_nsg_allow_any_any" {
  description = "If true, adds an additional NSG rule allowing any protocol, any port, from any source (misconfig: fully open network ACL)."
  type        = bool
  default     = false
}

variable "misconfig_disable_sql_logging" {
  description = "If true, skips the SQL database's diagnostic settings independently of the storage logging toggle (misconfig: missing database-tier logging)."
  type        = bool
  default     = false
}

variable "misconfig_short_log_retention" {
  description = "If true, shortens the Log Analytics workspace retention from 90 days down to Azure's allowed minimum of 30 days (misconfig: insufficient log retention for investigation)."
  type        = bool
  default     = false
}

variable "misconfig_storage_cors_allow_all" {
  description = "If true, configures the storage account's CORS rules to allow any origin and any method (misconfig: overly permissive cross-origin access)."
  type        = bool
  default     = false
}
