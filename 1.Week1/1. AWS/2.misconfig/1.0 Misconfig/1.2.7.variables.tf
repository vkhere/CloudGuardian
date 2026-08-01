# ============================================================
# variables.tf - All Variables for CloudGuardian Project
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Central place for all configurable values
# Status  : UNCHANGED FROM BASELINE
# ============================================================

variable "region" {
  default     = "ap-south-1"
  description = "AWS region for deployment"
}

variable "project" {
  default     = "cloudguardian"
  description = "Project name prefix"
}

variable "db_password" {
  default     = "TempPass123!"
  description = "RDS master password"
  sensitive   = true
}
