# Copy this file to terraform.tfvars and fill in YOUR Week 1 resource
# names exactly as they appear in the Azure Portal / your Week 1
# terraform output. Nothing here is secret - do not put passwords
# or keys in this file.

existing_resource_group_name          = "rg-cloudguardian-lab"
existing_log_analytics_workspace_name = "log-cloudguardian-lab"
existing_key_vault_name               = "kv-cloudguardian-43944"   # includes Week 1's random suffix
existing_storage_account_name         = "stcloudguardianlab6jtwe"     # includes Week 1's random suffix
existing_sql_server_name              = "sql-cloudguardian-lab-6jtwe"
existing_sql_database_name            = "sqldb-cloudguardian-lab"

location     = "Central US"
project_name = "cloudguardian"
environment  = "lab"

approver_email      = "kedar.pavaskar@hotmail.com"
notification_email  = "kedar.pavaskar@hotmail.com"

auto_remediate_severities    = ["Low", "Medium"]
approval_required_severities = ["High", "Critical"]
drift_check_schedule_time    = "02:00:00"
		