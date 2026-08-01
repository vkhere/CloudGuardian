resource "azurerm_storage_account" "main" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.storage_replication_type

  # Secure default: TLS1_2. misconfig_storage_min_tls_version = true lowers
  # this to TLS1_0 - outdated transport encryption permitted.
  min_tls_version = var.misconfig_storage_min_tls_version ? "TLS1_0" : "TLS1_2"

  # Secure default: HTTPS-only. misconfig_storage_disable_secure_transfer =
  # true allows plain HTTP - unencrypted data in transit.
  https_traffic_only_enabled = !var.misconfig_storage_disable_secure_transfer

  # Secure default: Azure AD-first. misconfig_storage_allow_shared_key_access
  # = true makes the account default to Shared Key auth in the Portal/tools
  # instead of Microsoft Entra ID (the CIS/Defender "default to Azure AD
  # authorization" finding). Note: we deliberately do NOT disable
  # shared_access_key_enabled outright here - Azure's provider hard-requires
  # Shared Key auth specifically to update an existing container's public-
  # access setting, which would conflict with misconfig_storage_public_
  # container being independently toggleable. This achieves the same IAM
  # finding without that conflict.
  default_to_oauth_authentication = !var.misconfig_storage_allow_shared_key_access

  public_network_access_enabled = true

  # The network_rules block below is the real gate. default_action = "Deny"
  # with an allow-list is the secure pattern; misconfig_storage_allow_public_
  # network_access flips default_action to "Allow" (open to the internet).
  network_rules {
    default_action             = var.misconfig_storage_allow_public_network_access ? "Allow" : "Deny"
    ip_rules                   = [split("/", var.my_ip_cidr)[0]]
    virtual_network_subnet_ids = [azurerm_subnet.data.id]
    bypass                     = ["AzureServices"]
  }

  # Secure default: no CORS rule at all. misconfig_storage_cors_allow_all =
  # true adds one permitting any origin/method - overly permissive
  # cross-origin access.
  blob_properties {
    dynamic "cors_rule" {
      for_each = var.misconfig_storage_cors_allow_all ? [1] : []
      content {
        allowed_origins    = ["*"]
        allowed_methods    = ["GET", "PUT", "POST", "DELETE", "HEAD", "MERGE", "OPTIONS"]
        allowed_headers    = ["*"]
        exposed_headers    = ["*"]
        max_age_in_seconds = 3600
      }
    }
  }

  tags = local.tags
}

resource "azurerm_storage_container" "data" {
  name                 = "app-data"
  storage_account_id   = azurerm_storage_account.main.id
  # Secure default: private. misconfig_storage_public_container = true makes
  # it world-readable - the classic "public S3/blob bucket" finding.
  container_access_type = var.misconfig_storage_public_container ? "blob" : "private"
}

# --- Logging wiring ----------------------------------------------------
# misconfig_disable_storage_logging = true skips this block entirely, which
# is exactly what "missing logging" looks like to an auditor: the resource
# exists, but nothing downstream ever sees what happened to it.
resource "azurerm_monitor_diagnostic_setting" "storage_blob" {
  count = var.misconfig_disable_storage_logging ? 0 : 1

  name                       = "diag-${local.storage_account_name}-blob"
  target_resource_id         = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Transaction"
  }
}

# Secure default: SQL diagnostic logging ON. misconfig_disable_sql_logging
# = true skips this independently of the storage logging toggle above -
# a distinct "missing database-tier logging" finding.
resource "azurerm_monitor_diagnostic_setting" "sql_db" {
  count = var.misconfig_disable_sql_logging ? 0 : 1

  name                       = "diag-${local.sql_database_name}"
  target_resource_id         = azurerm_mssql_database.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SQLInsights"
  }
  enabled_log {
    category = "Errors"
  }

  enabled_metric {
    category = "Basic"
  }
}
