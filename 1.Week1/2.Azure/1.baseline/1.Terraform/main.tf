resource "azurerm_resource_group" "main" {
  name     = local.resource_group_name
  location = var.location
  tags     = local.tags
}

# Central logging destination - the "missing logging" control in the
# capstone's ISO 27001 problem statement maps to wiring services into this.
#
# Secure default: 30-day retention. misconfig_short_log_retention = true
# drops it to 7 days - the "insufficient log retention" finding.
resource "azurerm_log_analytics_workspace" "main" {
  name                = local.law_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days    = var.misconfig_short_log_retention ? 30 : 90
  tags                = local.tags
}
