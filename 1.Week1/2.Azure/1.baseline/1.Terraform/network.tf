resource "azurerm_virtual_network" "main" {
  name                = local.vnet_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = var.vnet_address_space
  tags                = local.tags
}

# --- Web tier subnet -------------------------------------------------------
resource "azurerm_subnet" "web" {
  name                 = local.web_subnet_name
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.web_subnet_prefix]
}

# --- Data tier subnet (service endpoints for SQL + Storage) ---------------
resource "azurerm_subnet" "data" {
  name                 = local.data_subnet_name
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.data_subnet_prefix]
  service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
}

# --- NSG for the web tier ---------------------------------------------------
resource "azurerm_network_security_group" "web" {
  name                = local.nsg_web_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  security_rule {
    name                       = "Allow-HTTPS-Internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-HTTP-Internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # --- SSH rule: this is intentionally controlled by a misconfig toggle ---
  # Secure default: only var.my_ip_cidr can reach port 22.
  # misconfig_ssh_open_to_internet = true -> port 22 open to 0.0.0.0/0,
  # i.e. exactly the "NSG allows ingress from 0.0.0.0/0 to port 22" finding
  # every CSPM tool (Prowler/Checkov/ScoutSuite) checks for.
  security_rule {
    name                       = "Allow-SSH"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.misconfig_ssh_open_to_internet ? "*" : var.my_ip_cidr
    destination_address_prefix = "*"
  }
}

# Secure default: NSG attached to the web subnet. misconfig_vm_remove_nsg_
# association = true skips creating this association entirely, leaving the
# subnet with no network-layer filtering at all - a "missing firewall"
# finding that's distinct from (and more severe than) the SSH-only one above.
resource "azurerm_subnet_network_security_group_association" "web" {
  count                      = var.misconfig_vm_remove_nsg_association ? 0 : 1
  subnet_id                  = azurerm_subnet.web.id
  network_security_group_id  = azurerm_network_security_group.web.id
}

# THE misconfig: a standalone rule allowing every protocol, every port, from
# every source. Kept as its own toggle/resource so you can demonstrate it
# independently of the SSH-only rule above - both show up as distinct
# Prowler findings.
resource "azurerm_network_security_rule" "misconfig_allow_any_any" {
  count                        = var.misconfig_nsg_allow_any_any ? 1 : 0
  name                         = "MISCONFIG-Allow-Any-Any"
  priority                     = 130
  direction                    = "Inbound"
  access                       = "Allow"
  protocol                     = "*"
  source_port_range            = "*"
  destination_port_range       = "*"
  source_address_prefix        = "*"
  destination_address_prefix   = "*"
  resource_group_name          = azurerm_resource_group.main.name
  network_security_group_name  = azurerm_network_security_group.web.name
}
