resource "azurerm_public_ip" "web" {
  name                = "pip-${local.vm_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "web" {
  name                = "nic-${local.vm_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.web.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.web.id
  }
}

resource "azurerm_linux_virtual_machine" "web" {
  name                = local.vm_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  size                = var.vm_size
  admin_username      = var.admin_username
  network_interface_ids = [
    azurerm_network_interface.web.id,
  ]
  tags = local.tags

  # Always-on system-assigned identity - having an identity isn't itself a
  # misconfig. What you grant that identity is. See the role assignment in
  # iam_and_extra_misconfigs.tf, gated behind misconfig_vm_identity_over_privileged.
  identity {
    type = "SystemAssigned"
  }

  # Secure default: key-only auth. misconfig_vm_allow_password_auth = true
  # flips this to allow password auth too (the "weak SSH auth" finding).
  # Azure requires admin_password whenever password auth is permitted, even
  # if you're also supplying an SSH key - hence the conditional below.
  disable_password_authentication = !var.misconfig_vm_allow_password_auth
  admin_password                  = var.misconfig_vm_allow_password_auth ? var.vm_admin_password : null

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Minimal bootstrap so port 80/443 actually answer something for your demo.
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y nginx
    echo "<h1>CloudGuardian web tier</h1>" > /var/www/html/index.html
  EOF
  )
}
