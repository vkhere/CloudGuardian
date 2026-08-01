############################################################
# variables.tf
# ------------------------------------------------------------
# WHAT: Every adjustable setting for the Week 3 remediation
#       stack, in one place. Same philosophy as Week 1's
#       variables.tf - this is the blank template; your real
#       values go into terraform.tfvars (never into this file).
#
# WHY THESE VALUES ARE VARIABLES AND NOT HARDCODED:
#       Week 3 does not build a new Resource Group. It ATTACHES
#       to the Week 1 Resource Group, Log Analytics Workspace
#       and Key Vault that already exist, because remediation
#       only makes sense against real, already-misconfigured
#       resources. The variables below are how you tell this
#       stack "here is what Week 1 already built."
############################################################

variable "existing_resource_group_name" {
  description = "Name of the Resource Group created in Week 1 (e.g. rg-cloudguardian-lab). Week 3 deploys INTO this RG rather than creating a new one."
  type        = string
}

variable "existing_log_analytics_workspace_name" {
  description = "Name of the Week 1 Log Analytics Workspace. Function App logs, Automation Account job logs, and diagnostic-setting remediations all point back here so everything lands in one place for KQL queries."
  type        = string
}

variable "existing_key_vault_name" {
  description = "Name of the Week 1 Key Vault. Week 3 stores the Function key and (optionally) the LLM endpoint/API key here instead of in application settings."
  type        = string
}

variable "existing_storage_account_name" {
  description = "Name of the Week 1 Storage Account whose public-access and encryption misconfig toggles the remediation engine will fix."
  type        = string
}

variable "existing_sql_server_name" {
  description = "Name of the Week 1 SQL logical server hosting the database whose TDE remediation the engine will fix."
  type        = string
}

variable "existing_sql_database_name" {
  description = "Name of the Week 1 SQL database to remediate (TDE)."
  type        = string
}

variable "location" {
  description = "Azure region. Must match Week 1's region so all resources can talk to each other without cross-region latency/cost."
  type        = string
  default     = "Central US"
}

variable "project_name" {
  description = "Short project prefix, must match Week 1's project_name so locals.tf produces matching resource names."
  type        = string
  default     = "cloudguardian"
}

variable "environment" {
  description = "Environment tag applied to every resource this stack creates."
  type        = string
  default     = "lab"
}

variable "approver_email" {
  description = "Email address that receives Logic App approval requests for High/Critical findings. Use your own inbox for the lab/demo."
  type        = string
}

variable "notification_email" {
  description = "Email address that receives remediation completion / drift alerts from the Automation Account runbook."
  type        = string
}

variable "auto_remediate_severities" {
  description = "Severities that skip human approval and remediate automatically via the Event Grid -> Function path. Keep this short and low-risk on purpose."
  type        = list(string)
  default     = ["Low", "Medium"]
}

variable "approval_required_severities" {
  description = "Severities that must go through the Logic App human-approval gate before the Function executes anything."
  type        = list(string)
  default     = ["High", "Critical"]
}

variable "drift_check_schedule_time" {
  description = "Daily UTC time (HH:mm:ss) the Automation Account runbook re-checks the 6 controls for configuration drift."
  type        = string
  default     = "02:00:00"
}

variable "acs_data_location" {
  description = "Data residency region for Azure Communication Services (a separate concept from the Azure region in the location variable - ACS only supports a fixed set of data locations, e.g. United States, Europe, Asia Pacific)."
  type        = string
  default     = "United States"
}

variable "acs_sender_domain_override" {
  description = "Only set this if terraform plan errors on the computed ACS sending-domain attribute in acs_email.tf (provider version drift). Otherwise leave as an empty string and Terraform derives it automatically. If set, use the exact value from az communication email domain show ... --query mailFromSenderDomain -o tsv (e.g. a1b2c3d4-....azurecomm.net, no DoNotReply@ prefix)."
  type        = string
  default     = ""
}

variable "automation_account_location" {
  description = "Region for the Automation Account and its runbook - kept as a SEPARATE variable from location because Free Trial and Student Azure subscriptions can only create Automation Accounts in a fixed allow-list of regions (as of this writing: eastus, eastus2, westus, northeurope, southeastasia, japanwest), which may not include the region the rest of your stack lives in. There is a small latency/cost cost to this cross-region call, but it is negligible for a once-daily runbook. If your subscription is NOT a Free Trial/Student subscription and does not hit this restriction, feel free to set this to the same value as location."
  type        = string
  default     = "East US"
}

variable "tags" {
  description = "Common tags merged onto every Week 3 resource."
  type        = map(string)
  default = {
    project    = "CloudGuardian"
    week       = "3"
    managed_by = "terraform"
  }
}
