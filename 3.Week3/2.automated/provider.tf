provider "aws" {
  region = "ap-south-1"
}

variable "project" {
  description = "Project name prefix for resources"
  type        = string
  default     = "cloudguardian"
}
