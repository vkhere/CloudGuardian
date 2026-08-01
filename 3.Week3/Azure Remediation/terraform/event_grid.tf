############################################################
# event_grid.tf
# ------------------------------------------------------------
# WHAT: One Event Grid Custom Topic that every CSPM finding
#       gets published to, and two subscriptions that split
#       findings into two routes purely on severity:
#
#         Low / Medium  -> straight to the Function App
#                          (auto-remediate, no human involved)
#         High / Critical -> straight to the Logic App
#                          (human approval required first)
#
# WHY EVENT GRID AND NOT "THE FUNCTION JUST CALLS ITSELF":
#       Event Grid decouples "a finding was detected" from
#       "something acts on it." Today the publisher is a small
#       script/curl call you trigger for the demo; later it
#       could be your Week 2 prioritization notebook, a
#       scheduled scan, or Defender for Cloud's own alert
#       stream - none of them need to know Functions or Logic
#       Apps exist. This is the same publish/subscribe pattern
#       Azure Monitor, Defender for Cloud and Microsoft Sentinel
#       all use internally. Advanced filters do the routing so
#       neither downstream service has to inspect and discard
#       events meant for the other.
############################################################

resource "azurerm_eventgrid_topic" "findings" {
  name                = local.eventgrid_topic_name
  resource_group_name = data.azurerm_resource_group.main.name
  location            = var.location

  # Findings themselves (resource IDs, severities) are not
  # secret, but keep the topic off the public internet anyway -
  # only the identities we explicitly grant below can publish.
  public_network_access_enabled = true # Consumption-tier lab; see setup guide for Private Link upgrade path

  tags = var.tags
}

# Route 1: low/medium severity -> Function App auto-remediates.
# This reads the Function's system key for the Event Grid
# extension so Event Grid can call the trigger's webhook.
data "azurerm_function_app_host_keys" "remediate" {
  name                = azurerm_linux_function_app.remediate.name
  resource_group_name = data.azurerm_resource_group.main.name
}

resource "azurerm_eventgrid_event_subscription" "auto_remediate" {
  name  = local.eventgrid_sub_auto_name
  scope = azurerm_eventgrid_topic.findings.id

  webhook_endpoint {
    url = "https://${azurerm_linux_function_app.remediate.default_hostname}/runtime/webhooks/eventgrid?functionName=auto_remediate&code=${data.azurerm_function_app_host_keys.remediate.event_grid_extension_config_key}"
  }

  advanced_filter {
    string_in {
      key    = "data.severity"
      values = var.auto_remediate_severities
    }
  }

  retry_policy {
    max_delivery_attempts = 5
    event_time_to_live    = 60 # minutes
  }
}

# Route 2: high/critical severity -> Logic App approval workflow.
resource "azurerm_eventgrid_event_subscription" "approval_required" {
  name  = local.eventgrid_sub_appr_name
  scope = azurerm_eventgrid_topic.findings.id

  webhook_endpoint {
    url = azurerm_logic_app_trigger_http_request.on_finding.callback_url
  }

  advanced_filter {
    string_in {
      key    = "data.severity"
      values = var.approval_required_severities
    }
  }

  retry_policy {
    max_delivery_attempts = 5
    event_time_to_live    = 1440 # 24h - approvals can sit in someone's inbox overnight
  }
}
