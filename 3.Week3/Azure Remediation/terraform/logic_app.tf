############################################################
# logic_app.tf
# ------------------------------------------------------------
# WHAT: The orchestration layer between Event Grid and the human
#       approval gate. Deliberately thin: receive a High/Critical
#       finding from Event Grid, hand it to the Function App's
#       `request_approval` endpoint, done. The Function App does
#       the actual work (building the email, sending it via ACS,
#       handling the click) - see functions/function_app.py and
#       functions/shared/notifications.py.
#
# WHY THIS IS SIMPLER THAN THE FIRST DRAFT OF THIS FILE:
#       An earlier version of this stack tried to put the
#       Approve/Reject BRANCH logic inside the Logic App itself,
#       which needed an If/Else action that plain azurerm Logic
#       App resources can't express - forcing a raw-JSON workflow
#       definition deployed via the `azapi` provider. Moving the
#       email-sending AND the decision-handling into the Function
#       App (Section 6.5 privacy pipeline already lives there
#       too) means this Logic App is now just a trigger plus ONE
#       HTTP action - a flat sequence that native azurerm
#       resources express natively. Less moving infrastructure,
#       no azapi provider dependency, nothing to hand-author as
#       JSON. This is a legitimate architecture simplification,
#       not just a workaround - call this out in your report as
#       a design decision you made after hitting the limitation,
#       not something you started with.
#
# WHY WE STILL USE A LOGIC APP AT ALL, GIVEN HOW THIN IT IS:
#       The Week 3 brief explicitly asks you to demonstrate Logic
#       Apps as one of the orchestration technologies. This is a
#       genuine, correct use of one: Logic Apps' native strength
#       is being an event-driven glue layer between a trigger
#       (Event Grid) and a downstream action (calling the
#       Function) - exactly what it's doing here, not artificially
#       inflated with logic that belongs in code instead.
############################################################

resource "azurerm_logic_app_workflow" "approval" {
  name                = local.logic_app_name
  location            = var.location
  resource_group_name = data.azurerm_resource_group.main.name

  tags = var.tags
}

resource "azurerm_logic_app_trigger_http_request" "on_finding" {
  name         = "When_a_finding_needs_approval"
  logic_app_id = azurerm_logic_app_workflow.approval.id

  schema = jsonencode({
    type = "array"
    items = {
      type = "object"
      properties = {
        id        = { type = "string" }
        eventType = { type = "string" }
        subject   = { type = "string" }
        eventTime = { type = "string" }
        data = {
          type = "object"
          properties = {
            finding_id            = { type = "string" }
            control_id            = { type = "string" }
            severity              = { type = "string" }
            remediation_type      = { type = "string" }
            resource_id           = { type = "string" }
            plain_english_summary = { type = "string" }
          }
        }
      }
    }
  })
}

# Logic Apps' Request trigger automatically answers Event Grid's
# subscription-validation handshake on first connect - no extra
# action needed, same as the earlier design.

resource "azurerm_logic_app_action_http" "request_approval" {
  name         = "Request_approval"
  logic_app_id = azurerm_logic_app_workflow.approval.id

  method = "POST"
  # NOTE: the function key used to live here as a ?code=... query
  # string value. Moved to the x-functions-key header instead - see
  # the long comment on `headers` below for exactly why.
  uri = "https://${azurerm_linux_function_app.remediate.default_hostname}/api/request-approval"

  # NOTE: `headers` on this resource takes a native HCL map(string)
  # directly - NOT a jsonencode()'d string. (jsonencode() here was an
  # early mistake that Terraform will correctly reject with "map of
  # string required, but have string".)
  #
  # WHY THE FUNCTION KEY MOVED FROM A ?code= QUERY PARAMETER TO AN
  # x-functions-key HEADER: Azure Functions accepts a function-level
  # key via EITHER mechanism, but a query-string value ending in the
  # base64 padding characters "==" is fragile inside a Logic App HTTP
  # action's `uri` field - Logic Apps' native HTTP connector parses
  # and re-serializes the URI it's given (rather than sending the
  # exact literal string byte-for-byte), and trailing "=" characters
  # in a query VALUE are exactly the class of character that can get
  # re-percent-encoded on replay. The Portal's Parameters view then
  # shows the pretty-printed (decoded) form back to you, which looks
  # identical to a working curl test - masking the fact that the
  # bytes actually sent on the wire differ. A header value isn't run
  # through that same URI-encoding path, so this class of bug can't
  # recur here. This was diagnosed live by confirming (a) the key
  # embedded in the Logic App's run history exactly matched
  # `az functionapp keys list`'s current default key, and (b) an
  # identical direct curl call with that same key/URL succeeded
  # (202 Accepted, approval email sent) while the Logic App's own
  # calls kept failing with 401 Unauthorized across every run that
  # day - isolating the difference to how the Logic App transmits
  # the request, not the key's validity.
  headers = {
    "Content-Type"    = "application/json"
    "x-functions-key" = data.azurerm_function_app_host_keys.remediate.default_function_key
  }

  # @triggerBody() here is the raw array Event Grid posted; the
  # Function unpacks element [0] itself (functions/function_app.py),
  # matching the same "first array element" convention the Function
  # already uses for auto_remediate's Event Grid trigger.
  body = "@triggerBody()"
}
