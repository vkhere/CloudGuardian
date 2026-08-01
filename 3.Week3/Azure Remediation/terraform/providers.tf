############################################################
# providers.tf
# ------------------------------------------------------------
# WHAT: Configures how Terraform authenticates to Azure.
# WHY:  Identical pattern to Week 1 - it reuses your existing
#       `az login` session. No secrets live in this file.
############################################################

provider "azurerm" {
  features {
    key_vault {
      # Week 3 reads an EXISTING Key Vault from Week 1 and only
      # adds a couple of secrets (function key, LLM endpoint).
      # We never want `terraform destroy` to purge it by accident.
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      # Same safety switch as Week 1: allows destroy to clean up
      # even if something inside the RG wasn't created by this
      # Terraform run (e.g. Week 1's own state).
      prevent_deletion_if_contains_resources = false
    }
  }
}
