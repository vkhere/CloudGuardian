provider "azurerm" {
  # On free/student subscriptions, the provider's default behaviour of
  # trying to pre-register ~200 resource providers on every run hits
  # 403 AuthorizationFailed for most of them. "none" tells it to skip that
  # entirely and assume the providers you actually need are already enabled
  # (true for every subscription type for Compute/Network/Storage/Sql/
  # OperationalInsights/Insights - the only ones this project touches).
  resource_provider_registrations = "none"

  features {
    resource_group {
      # Lets `terraform destroy` remove the RG even if it still contains
      # resources Terraform doesn't know about (handy when you're manually
      # poking at things while testing misconfigurations).
      prevent_deletion_if_contains_resources = false
    }
  }
}
