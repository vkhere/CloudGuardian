data "azurerm_client_config" "current" {}

# IAM misconfig: Owner role assigned at Resource Group scope to the
# deploying identity, instead of a narrower role like Contributor.
# "Excessive permissions assigned" is one of the most common CIS/Prowler
# IAM findings in real audits.
resource "azurerm_role_assignment" "misconfig_owner_at_rg" {
  count                = var.misconfig_iam_owner_role_at_rg_scope ? 1 : 0
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Owner"
  principal_id         = data.azurerm_client_config.current.object_id
}

# IAM misconfig: the web VM's own managed identity granted Contributor at
# the *subscription* scope - far broader than a web server needs.
# This is the "over-privileged service identity" finding.
resource "azurerm_role_assignment" "misconfig_vm_identity_contributor" {
  count                = var.misconfig_vm_identity_over_privileged ? 1 : 0
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.web.identity[0].principal_id
}

# --- A note on these two toggles -----------------------------------------
# Creating a role assignment needs Microsoft.Authorization/roleAssignments/
# write permission. On a free/student subscription, the account that signed
# up is normally the subscription's Owner, so this should just work - but
# if `terraform apply` returns AuthorizationFailed on either resource above,
# your account doesn't have that right on this subscription. In that case,
# document the same misconfig manually instead: Azure Portal -> your
# Resource Group -> Access control (IAM) -> Add role assignment -> Owner ->
# assign to yourself; screenshot it for your catalogue, and note in your
# report that the Terraform-driven version was blocked by subscription RBAC
# limits (the same pattern already documented for Prowler's AAD checks).
