############################################################
# function_app.tf
# ------------------------------------------------------------
# WHAT: The remediation engine's compute. A Python Azure
#       Function App on the Consumption (Y1) plan, with a
#       System-Assigned Managed Identity - no passwords, no
#       connection strings, no service principal secrets.
#
# WHY CONSUMPTION PLAN AND NOT PREMIUM/DEDICATED:
#       This runs a handful of short remediation calls per day
#       in a student lab. Consumption is pay-per-execution and
#       free-tier friendly. See the comparison table in the
#       setup guide for when you'd upgrade to Premium (VNet
#       integration, no cold start, private endpoints) in a
#       real production SOC.
#
# WHY SYSTEM-ASSIGNED MANAGED IDENTITY:
#       Zero Trust principle - the Function proves who it is to
#       Azure AD without any credential a human could leak. The
#       exact permissions it gets are in rbac.tf, scoped tightly
#       to only the actions each remediation needs (see WAF
#       "least privilege" pillar).
############################################################

# Small storage account the Function runtime itself needs
# (this is NOT the target Storage Account being remediated -
# that one is looked up via data.azurerm_storage_account.target
# in locals.tf). Every Function App requires one of these to
# store its trigger state, logs and deployment package.
resource "azurerm_storage_account" "function_storage" {
  name                     = local.function_storage_name
  resource_group_name      = data.azurerm_resource_group.main.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Secure-by-default, matching everything Week 1 taught about
  # the storage misconfig toggles - this account is never public.
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"

  tags = var.tags
}

resource "azurerm_service_plan" "function_plan" {
  name                = local.app_service_plan_name
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption - scales to zero, pay per execution

  tags = var.tags
}

resource "azurerm_application_insights" "function_insights" {
  name                = local.app_insights_name
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location
  application_type    = "web"
  # Route Application Insights telemetry into the SAME Log
  # Analytics Workspace Week 1 built. This is what makes the
  # Function's execution logs and the CSPM findings queryable
  # side by side with one KQL query later.
  workspace_id = data.azurerm_log_analytics_workspace.main.id

  tags = var.tags
}

resource "azurerm_linux_function_app" "remediate" {
  name                = local.function_app_name
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location

  storage_account_name       = azurerm_storage_account.function_storage.name
  storage_account_access_key = azurerm_storage_account.function_storage.primary_access_key
  service_plan_id            = azurerm_service_plan.function_plan.id

  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_insights_connection_string = azurerm_application_insights.function_insights.connection_string
    minimum_tls_version                    = "1.2"
    ftps_state                             = "Disabled"

    application_stack {
      python_version = "3.12"
    }

    # No cors block: none of this stack's callers (curl, the Logic
    # App's server-to-server HTTP call, or a human clicking the
    # approval link - a top-level navigation, not a cross-origin
    # fetch/XHR) are subject to CORS. Add one later only if you
    # wire a browser dashboard to call these endpoints directly
    # via JavaScript, scoped to that dashboard's real origin -
    # never "*" on a Function that can execute remediations.
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"   = "python"
    "AzureWebJobsFeatureFlags"   = "EnableWorkerIndexing" # required for the Python v2 programming model
    "LOG_ANALYTICS_WORKSPACE_ID" = data.azurerm_log_analytics_workspace.main.workspace_id
    "TARGET_SUBSCRIPTION_ID"     = data.azurerm_client_config.current.subscription_id
    "TARGET_RESOURCE_GROUP"      = data.azurerm_resource_group.main.name
    "TARGET_STORAGE_ACCOUNT_NAME" = data.azurerm_storage_account.target.name
    "TARGET_SQL_SERVER_NAME"     = data.azurerm_mssql_server.target.name
    "TARGET_SQL_DATABASE_NAME"   = var.existing_sql_database_name
    "TARGET_KEY_VAULT_NAME"      = data.azurerm_key_vault.main.name
    "DRY_RUN_DEFAULT"            = "false"

    # ACS Email + approval-callback settings (see acs_email.tf and
    # functions/shared/notifications.py). The Function reads these
    # about ITSELF at runtime - no Terraform circular dependency,
    # unlike trying to bake in the Function's own host key would be.
    "ACS_ENDPOINT"           = local.acs_endpoint
    "ACS_SENDER_ADDRESS"     = local.acs_sender_address
    "APPROVER_EMAIL"         = var.approver_email
    "CALLBACK_SHARED_SECRET" = random_password.callback_secret.result
  }

  tags = var.tags

  lifecycle {
    # App Insights connection strings and storage keys change
    # under Terraform's feet if Azure rotates them - ignore so
    # `terraform plan` doesn't show noisy false diffs every run.
    ignore_changes = [
      app_settings["WEBSITE_RUN_FROM_PACKAGE"],
    ]
  }
}
