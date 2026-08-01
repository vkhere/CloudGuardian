############################################################
# outputs.tf
# ------------------------------------------------------------
# WHAT: The values Terraform prints after apply - everything
#       you need to deploy the Function code, test the Event
#       Grid topic, and open the Logic App run history.
############################################################

output "function_app_name" {
  value       = azurerm_linux_function_app.remediate.name
  description = "Deploy the Python code to this Function App (func azure functionapp publish <name>)."
}

output "function_app_default_hostname" {
  value       = azurerm_linux_function_app.remediate.default_hostname
  description = "Base URL of the remediation Function App."
}

output "function_app_principal_id" {
  value       = azurerm_linux_function_app.remediate.identity[0].principal_id
  description = "The Function App's Managed Identity object ID - confirm this appears under the custom role's assignments in the Portal."
}

output "eventgrid_topic_endpoint" {
  value       = azurerm_eventgrid_topic.findings.endpoint
  description = "POST findings here to trigger the pipeline (see docs/CloudGuardian_Week3_Setup_Guide for the exact curl command)."
  sensitive   = false
}

output "eventgrid_topic_key_command" {
  value       = "az eventgrid topic key list --name ${azurerm_eventgrid_topic.findings.name} --resource-group ${data.azurerm_resource_group.main.name} --query key1 -o tsv"
  description = "Run this to retrieve the Event Grid topic key needed to publish test events."
}

output "logic_app_name" {
  value       = azurerm_logic_app_workflow.approval.name
  description = "Open this in the Portal (Logic App Designer or Overview > Run History) to watch approvals happen live."
}

output "automation_account_name" {
  value       = azurerm_automation_account.governance.name
  description = "Automation Account running the daily drift-check runbook."
}

output "acs_sender_address" {
  value       = local.acs_sender_address
  description = "The 'from' address approval and confirmation emails will be sent from. No manual authorization step needed - ACS Email authenticates via the Function App's Managed Identity, not OAuth. If this value looks wrong (e.g. blank domain), see the VERIFY BEFORE APPLY comment in acs_email.tf."
}

output "no_manual_email_auth_step_needed" {
  value       = "Unlike an Office 365 Outlook connector, this stack's ACS Email setup requires NO manual Portal authorization click - Terraform provisions everything, including the send permission (Managed Identity RBAC). The only thing to double-check post-apply is the acs_sender_address output above looks like a real domain, not blank."
  description = "Confirms there is no equivalent of Week 1/2's manual steps for the approval email path."
}

output "active_week3_config" {
  value = {
    auto_remediate_severities    = var.auto_remediate_severities
    approval_required_severities = var.approval_required_severities
    drift_check_schedule_utc     = var.drift_check_schedule_time
  }
  description = "Quick summary for your final report / defense deck."
}
