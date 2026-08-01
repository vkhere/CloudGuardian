# ============================================================
# variables.tf - All Variables for CloudGuardian Project
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Central place for all configurable values
# ============================================================

# AWS Region where all resources will be deployed
variable "region" {
  default     = "ap-south-1"
  description = "AWS region for deployment"
}

# Project name - used as prefix for all resource names
variable "project" {
  default     = "cloudguardian"
  description = "Project name prefix"
}

# RDS Database password
variable "db_password" {
  default     = "TempPass123!"
  description = "RDS master password"
  sensitive   = true
}
