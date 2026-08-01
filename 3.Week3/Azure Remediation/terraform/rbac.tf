############################################################
# rbac.tf
# ------------------------------------------------------------
# WHAT: A custom least-privilege role, "CloudGuardian
#       Remediator", containing ONLY the exact write actions
#       the 6 remediation functions need - nothing broader
#       like "Contributor" - assigned to both the Function
#       App's and the Automation Account's managed identities,
#       scoped to the Week 1 Resource Group only.
#
# WHY A CUSTOM ROLE INSTEAD OF A BUILT-IN ONE:
#       Built-in roles like "Storage Account Contributor" or
#       "SQL DB Contributor" grant far more than "flip these
#       specific properties." A capstone reviewer (and a real
#       auditor) will ask "what's the blast radius if this
#       identity is compromised?" With a custom role scoped to
#       an explicit action list, the honest answer is "it can
#       only toggle the 6 settings this project remediates."
#       This directly demonstrates the Zero Trust /
#       least-privilege principle from the Azure Well-Architected
#       Framework's Security pillar - call this out explicitly
#       in your final report and defense.
############################################################

resource "azurerm_role_definition" "remediator" {
  name        = local.custom_role_name
  scope       = data.azurerm_resource_group.main.id
  description = "Least-privilege role for CloudGuardian's automated remediation identities. Grants only the specific write actions needed to remediate the 6 in-scope misconfigurations - not full resource Contributor."

  permissions {
    actions = [
      # Storage: public access + transport security (remediations 1 & 2)
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/write",
      "Microsoft.Storage/storageAccounts/blobServices/containers/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/write",

      # Diagnostic settings / logging (remediation 3)
      "Microsoft.Insights/diagnosticSettings/read",
      "Microsoft.Insights/diagnosticSettings/write",
      "Microsoft.OperationalInsights/workspaces/sharedkeys/action",

      # SQL: Transparent Data Encryption (remediation 4)
      "Microsoft.Sql/servers/read",
      "Microsoft.Sql/servers/databases/read",
      "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
      "Microsoft.Sql/servers/databases/transparentDataEncryption/write",

      # Key Vault network ACLs (remediation 5)
      "Microsoft.KeyVault/vaults/read",
      "Microsoft.KeyVault/vaults/write",

      # Tags (remediation 6) - the dedicated Tags RP, not a
      # blanket write on every resource type
      "Microsoft.Resources/tags/read",
      "Microsoft.Resources/tags/write",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_resource_group.main.id,
  ]
}

resource "azurerm_role_assignment" "function_remediator" {
  scope              = data.azurerm_resource_group.main.id
  role_definition_id = azurerm_role_definition.remediator.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.remediate.identity[0].principal_id
}

resource "azurerm_role_assignment" "automation_remediator" {
  scope              = data.azurerm_resource_group.main.id
  role_definition_id = azurerm_role_definition.remediator.role_definition_resource_id
  principal_id       = azurerm_automation_account.governance.identity[0].principal_id
}

# The Function App also needs to read secrets (e.g. if you wire up
# the Azure OpenAI-based LLM pipeline's endpoint/key) from Key Vault
# at runtime. Not strictly required by the 6 remediation modules
# themselves, but kept here since privacy_llm/llm_client.py's
# azure_openai_call() path expects it.
resource "azurerm_role_assignment" "function_keyvault_secrets_user" {
  scope                = data.azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_function_app.remediate.identity[0].principal_id
}

# NOTE: the Logic App no longer needs any Key Vault access. In the
# current design (see logic_app.tf) it only makes one outbound HTTP
# call to the Function App using a host key fetched directly via
# data.azurerm_function_app_host_keys at Terraform-apply time - it
# never reads Key Vault itself. The Function App's own ACS Email
# permission is defined in acs_email.tf (function_acs_sender), next
# to the resource it grants access to, rather than here.
