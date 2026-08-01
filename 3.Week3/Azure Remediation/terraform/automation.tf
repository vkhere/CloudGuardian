############################################################
# automation.tf
# ------------------------------------------------------------
# WHAT: An Azure Automation Account running a daily PowerShell
#       runbook that re-checks all 6 remediated controls and
#       flags configuration drift. This is the "Govern" half of
#       Week 3's "Remediate and Govern" objective - a one-time
#       fix without ongoing verification is not governance.
############################################################

resource "azurerm_automation_account" "governance" {
  name                = local.automation_account_name
  resource_group_name = data.azurerm_resource_group.main.name
  # Deliberately NOT var.location - see variables.tf's
  # automation_account_location comment: Free Trial/Student
  # subscriptions restrict which regions can host an Automation
  # Account, independent of where the rest of the stack lives.
  location            = var.automation_account_location
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# Ship the Automation Account's own job logs into the same Log
# Analytics Workspace as everything else, so drift alerts are
# queryable alongside CSPM findings and Function execution logs.
resource "azurerm_monitor_diagnostic_setting" "automation_to_law" {
  name                       = "diag-${local.automation_account_name}"
  target_resource_id         = azurerm_automation_account.governance.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "JobLogs"
  }
  enabled_log {
    category = "JobStreams"
  }
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_automation_runbook" "drift_check" {
  name                    = local.runbook_name
  # Must match the Automation Account's own region, not the rest
  # of the stack's - see the comment on azurerm_automation_account.governance above.
  location                = var.automation_account_location
  resource_group_name     = data.azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.governance.name
  log_verbose             = true
  log_progress            = true
  runbook_type            = "PowerShell"

  content = file("${path.module}/../automation/Test-RemediationDrift.ps1")

  tags = var.tags
}

resource "azurerm_automation_schedule" "daily_drift_check" {
  name                    = "daily-drift-check"
  resource_group_name     = data.azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.governance.name
  frequency               = "Day"
  interval                = 1
  timezone                = "Etc/UTC"
  start_time              = timeadd(timestamp(), "24h") # Automation requires a future start time on create

  lifecycle {
    ignore_changes = [start_time] # avoid perpetual diff since timestamp() changes every plan
  }
}

resource "azurerm_automation_job_schedule" "daily_drift_check" {
  resource_group_name     = data.azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.governance.name
  schedule_name           = azurerm_automation_schedule.daily_drift_check.name
  runbook_name            = azurerm_automation_runbook.drift_check.name

  parameters = {
    subscriptionid          = data.azurerm_client_config.current.subscription_id
    resourcegroupname       = data.azurerm_resource_group.main.name
    storageaccountname      = data.azurerm_storage_account.target.name
    sqlservername           = data.azurerm_mssql_server.target.name
    sqldatabasename         = var.existing_sql_database_name
    keyvaultname            = data.azurerm_key_vault.main.name
    notificationemail       = var.notification_email
    loganalyticsworkspaceid = data.azurerm_log_analytics_workspace.main.workspace_id
  }
}
