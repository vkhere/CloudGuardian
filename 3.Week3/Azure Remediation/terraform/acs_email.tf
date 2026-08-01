############################################################
# acs_email.tf
# ------------------------------------------------------------
# WHAT: Azure Communication Services (ACS) Email - the thing
#       that actually sends the approval-request email and the
#       approve/reject confirmation email. Fully Azure-native,
#       fully Terraform-provisioned, and (this is the important
#       part) authenticated with the Function App's own
#       Managed Identity - NOT a connection string, and NOT an
#       Office 365 / Outlook mailbox.
#
# WHY THIS REPLACES THE OFFICE 365 OUTLOOK CONNECTOR FROM THE
# FIRST DRAFT OF THIS STACK:
#       The original design used the Office 365 Outlook
#       connector's "Send approval email" action, which embeds
#       clickable Approve/Reject buttons directly in the email
#       via Outlook's Actionable Messages feature. That action
#       REQUIRES a real Microsoft 365 / Exchange Online mailbox
#       behind the sending account - a personal Gmail address or
#       a bare Azure AD user with no Exchange license cannot use
#       it, and it also requires a one-time manual OAuth
#       "Authorize" click in the Portal that Terraform cannot
#       perform on your behalf.
#
#       ACS Email needs neither. It is a first-class Azure
#       resource, provisioned entirely by Terraform, sends from
#       an Azure-managed subdomain (no DNS setup, no mailbox,
#       no license), and - as of the current azure-communication-
#       email SDK - supports Microsoft Entra ID authentication via
#       DefaultAzureCredential, so the Function App's existing
#       System-Assigned Managed Identity is all the "credential"
#       this ever needs. Net effect: no M365 dependency, no
#       manual Portal step, one less secret in the whole system.
#
# THE ONE TRADE-OFF, STATED PLAINLY:
#       You lose Outlook's native Approve/Reject buttons inside
#       the email itself. This design replaces them with plain
#       hyperlinks that call back into the Function App (see
#       functions/function_app.py's `approval_decision` endpoint
#       and shared/notifications.py). See the security note in
#       that file about why GET-triggered links need a shared
#       secret, not just a Function key, to be safe against
#       corporate email-security link-prescanning.
############################################################

resource "azurerm_communication_service" "main" {
  name                = local.communication_service_name
  resource_group_name = data.azurerm_resource_group.main.name
  data_location        = var.acs_data_location

  tags = var.tags
}

resource "azurerm_email_communication_service" "main" {
  name                = local.email_service_name
  resource_group_name = data.azurerm_resource_group.main.name
  data_location        = var.acs_data_location

  tags = var.tags
}

# "AzureManaged" domain_management means Azure provisions a ready-
# to-send subdomain like <guid>.azurecomm.net automatically - no
# custom domain, no DNS TXT/MX/SPF records to add. This is the
# fastest path for a lab/demo; a real production deployment would
# use domain_management = "CustomerManaged" with your own verified
# domain for a recognizable "from" address.
resource "azurerm_email_communication_service_domain" "main" {
  name              = local.email_domain_name
  email_service_id  = azurerm_email_communication_service.main.id
  domain_management = "AzureManaged"

  tags = var.tags
}

# Links the Email Service's sending domain to the Communication
# Service resource the Function App actually authenticates against -
# both halves are required before EmailClient can send anything.
resource "azurerm_communication_service_email_domain_association" "main" {
  communication_service_id = azurerm_communication_service.main.id
  email_service_domain_id  = azurerm_email_communication_service_domain.main.id
}

# VERIFY BEFORE APPLY: the exact computed attribute name that
# exposes the generated "<guid>.azurecomm.net" sending domain
# varies across recent azurerm provider releases. If `terraform
# plan` errors with "Unsupported attribute" on the line below,
# open the current docs for azurerm_email_communication_service_domain
# (registry.terraform.io) and swap in whatever it calls this value -
# or simply run:
#   az communication email domain show --domain-name AzureManagedDomain \
#     --email-service-name <email_service_name> --resource-group <rg> \
#     --query mailFromSenderDomain -o tsv
# and hardcode the result into terraform.tfvars as acs_sender_domain_override
# instead (see variables.tf).
locals {
  acs_sender_domain = coalesce(
    var.acs_sender_domain_override,
    try(azurerm_email_communication_service_domain.main.mail_from_sender_domain, ""),
  )
  acs_sender_address = "DoNotReply@${local.acs_sender_domain}"

  # Communication Service connection strings are formatted
  # "endpoint=https://<name>.communication.azure.com/;accesskey=...".
  # Splitting this confirmed, documented attribute is more reliable
  # than guessing at a dedicated "endpoint"-style attribute name.
  acs_endpoint = trimprefix(
    split(";", azurerm_communication_service.main.primary_connection_string)[0],
    "endpoint=",
  )
}

# The Function App's Managed Identity needs write access to send
# email through this Communication Service. Scoped to ONLY this one
# resource (not the Resource Group) - this is the single broadest
# grant in the whole Week 3 stack, called out here deliberately
# because no narrower built-in role for "send email only" is
# confirmed to exist yet; tighten this if Microsoft ships one.
resource "azurerm_role_assignment" "function_acs_sender" {
  scope                = azurerm_communication_service.main.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_function_app.remediate.identity[0].principal_id
}

# A secret the Function App itself generates links with, checked by
# the approval_decision endpoint (see function_app.py). This is NOT
# the Functions-platform host key - see notifications.py's docstring
# for why a self-referencing host key would create a Terraform
# dependency cycle, and why a plain generated secret avoids it cleanly.
resource "random_password" "callback_secret" {
  length  = 32
  special = false
}
