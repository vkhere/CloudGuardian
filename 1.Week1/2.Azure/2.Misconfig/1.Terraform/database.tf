resource "azurerm_mssql_server" "main" {
  name                          = local.sql_server_name
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "12.0"
  administrator_login           = var.sql_admin_username
  administrator_login_password  = var.sql_admin_password

  # Secure default: 1.2. misconfig_sql_min_tls_version = true lowers this
  # to 1.0 - outdated transport encryption permitted.
  # Always 1.2: Azure retired TLS 1.0/1.1 support for SQL Database/Managed
  # Instance as of August 31, 2025 - minimum_tls_version below 1.2 is no
  # longer accepted at the platform level, regardless of provider settings.
  minimum_tls_version = "1.2"
  tags = local.tags
}

resource "azurerm_mssql_database" "main" {
  name        = local.sql_database_name
  server_id   = azurerm_mssql_server.main.id
  sku_name    = var.sql_sku_name
  max_size_gb = 2
  tags        = local.tags

  # Secure default: Transparent Data Encryption ON (this is also Azure SQL's
  # own default, but we make it explicit so it's a real controllable toggle).
  # misconfig_sql_disable_tde = true turns it off - "data at rest not
  # encrypted" is one of the most common audit findings, and is explicitly
  # named in your capstone's problem statement.
# Always ON: Azure does not allow disabling TDE on standard (non-Data-
  # Warehouse) SKUs - enforced at the platform level.
  transparent_data_encryption_enabled = true
}

# Lets Azure-internal services (e.g. your future remediation Function) reach
# the server. This is Azure's own "0.0.0.0" special-case rule, not a public
# internet rule - kept on by default, it's not the misconfig.
resource "azurerm_mssql_firewall_rule" "allow_azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Secure default: only your own IP can reach the SQL server from outside Azure.
resource "azurerm_mssql_firewall_rule" "allow_my_ip" {
  name             = "AllowMyIP"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = split("/", var.my_ip_cidr)[0]
  end_ip_address   = split("/", var.my_ip_cidr)[0]
}

# THE misconfig: a firewall rule spanning the entire IPv4 space, i.e. "DB
# reachable from the internet." Only created when you flip the toggle on.
resource "azurerm_mssql_firewall_rule" "misconfig_allow_all" {
  count            = var.misconfig_sql_allow_all_ips ? 1 : 0
  name             = "MISCONFIG-AllowAllIPs"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

# Allows the data subnet (service endpoint) to reach the server without
# traversing the public internet - useful once you add a real app tier.
resource "azurerm_mssql_virtual_network_rule" "data_subnet" {
  name      = "allow-data-subnet"
  server_id = azurerm_mssql_server.main.id
  subnet_id = azurerm_subnet.data.id
}
