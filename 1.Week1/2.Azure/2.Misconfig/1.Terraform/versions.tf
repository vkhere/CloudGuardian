terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Local state by default - fine for a capstone lab.
  # For team use / CI, swap this for an azurerm backend block pointing at a
  # storage account + container dedicated to tfstate (see README "Remote state").
  # backend "azurerm" {}
}
