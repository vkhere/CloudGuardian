# ============================================================
# main.tf - Provider Configuration
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Defines required providers and AWS region
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.region
}
