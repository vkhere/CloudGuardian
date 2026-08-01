############################################################
# locals.tf
# ------------------------------------------------------------
# WHAT: Consistent resource naming + lookups of Week 1's
#       existing resources.
# WHY:  Same reasoning as Week 1 - predictable names, one
#       random suffix where Azure demands global uniqueness
#       (the new Function App's Storage Account).
############################################################

resource "random_string" "suffix" {
  length  = 5
  special = false
  upper   = false
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  function_app_name           = "func-${local.name_prefix}-remediate"
  function_storage_name       = lower(replace("st${var.project_name}fn${random_string.suffix.result}", "-", ""))
  app_service_plan_name       = "asp-${local.name_prefix}-remediate"
  app_insights_name           = "appi-${local.name_prefix}-remediate"
  eventgrid_topic_name        = "evgt-${local.name_prefix}-findings"
  eventgrid_sub_auto_name     = "evgs-${local.name_prefix}-auto-remediate"
  eventgrid_sub_appr_name     = "evgs-${local.name_prefix}-approval-required"
  logic_app_name              = "logic-${local.name_prefix}-approval"
  logic_app_callback_name     = "logic-${local.name_prefix}-approval-callback"
  automation_account_name     = "aa-${local.name_prefix}-governance"
  runbook_name                = "Test-RemediationDrift"
  custom_role_name            = "CloudGuardian Remediator (${var.environment})"
  communication_service_name  = "acs-${local.name_prefix}"
  email_service_name          = "acs-email-${local.name_prefix}"
  email_domain_name           = "AzureManagedDomain"
}

# ---- Existing Week 1 resources this stack attaches to ----

data "azurerm_resource_group" "main" {
  name = var.existing_resource_group_name
}

data "azurerm_log_analytics_workspace" "main" {
  name                = var.existing_log_analytics_workspace_name
  resource_group_name = data.azurerm_resource_group.main.name
}

data "azurerm_key_vault" "main" {
  name                = var.existing_key_vault_name
  resource_group_name = data.azurerm_resource_group.main.name
}

data "azurerm_storage_account" "target" {
  name                = var.existing_storage_account_name
  resource_group_name = data.azurerm_resource_group.main.name
}

data "azurerm_mssql_server" "target" {
  name                = var.existing_sql_server_name
  resource_group_name = data.azurerm_resource_group.main.name
}

data "azurerm_client_config" "current" {}
