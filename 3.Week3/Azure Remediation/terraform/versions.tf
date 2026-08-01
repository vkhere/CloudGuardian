############################################################
# versions.tf
# ------------------------------------------------------------
# WHAT: Declares the minimum Terraform version and the exact
#       provider versions this Week 3 stack was built against.
# WHY:  Same reason as Week 1 - reproducibility. If Azure or
#       HashiCorp ships a breaking provider change six months
#       from now, this file pins you to the version that is
#       known to work, so `terraform init` never silently
#       downloads something incompatible.
# WHERE THIS RUNS: automatically, every time you run any
#       terraform command in this folder. You will not edit it.
############################################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# HISTORY NOTE: an earlier version of this stack also required the
# `azapi` provider to deploy the Logic App as a raw JSON workflow
# (needed for an If/Else branch inside the Logic App itself). The
# current design moved that branching logic into the Function App
# (see functions/function_app.py's approval_decision endpoint),
# which let the Logic App shrink to a plain trigger + one HTTP
# action - fully expressible with native azurerm resources. If you
# see references to azapi anywhere else in older notes/screenshots,
# that reflects the earlier design, not this one.
