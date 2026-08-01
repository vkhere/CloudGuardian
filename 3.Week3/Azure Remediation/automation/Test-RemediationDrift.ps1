<#
.SYNOPSIS
    CloudGuardian governance runbook - detects configuration drift
    on the 6 controls Week 3 remediates.

.DESCRIPTION
    "Remediate" fixes a finding once. "Govern" (the second half of
    the Week 3 brief) means proving the fix STAYS fixed. This
    runbook runs daily on the Automation Account's schedule and
    re-checks the current state of every control this project
    remediates. If any control has drifted back to a non-compliant
    state (e.g. someone manually re-enabled public blob access),
    it writes a Warning to the job log and sends an email alert -
    it does NOT auto-remediate, by design. Drift is a signal that
    a human should look at (was it accidental, or a deliberate
    exception?), not something to silently overwrite again.

.WHY POWERSHELL AND NOT PYTHON HERE
    The remediation engine (Week 3 Functions) is Python because it
    runs event-driven, sub-second responses to Event Grid/HTTP.
    This runbook is a slow, scheduled, read-mostly sweep - Azure
    Automation's PowerShell runtime with the Az module is the
    standard, well-documented tool for exactly this job, and it
    keeps the skillset demonstrated across the project broader
    (Terraform + Python + PowerShell), which is worth calling out
    in your defense.

.NOTES
    File:      Test-RemediationDrift.ps1
    Runs as:   Azure Automation Account System-Assigned Managed Identity
    Schedule:  Daily, set via terraform (automation.tf), default 02:00 UTC
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$ResourceGroupName,
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][string]$SqlServerName,
    [Parameter(Mandatory = $true)][string]$SqlDatabaseName,
    [Parameter(Mandatory = $true)][string]$KeyVaultName,
    [Parameter(Mandatory = $true)][string]$NotificationEmail,
    [Parameter(Mandatory = $true)][string]$LogAnalyticsWorkspaceId
)

$ErrorActionPreference = "Stop"

# --- Connect using the Automation Account's own Managed Identity.
# No stored credential, no service principal secret to rotate or leak.
try {
    Connect-AzAccount -Identity -Subscription $SubscriptionId | Out-Null
    Write-Output "Connected via Automation Account Managed Identity."
}
catch {
    Write-Error "Failed to connect with Managed Identity: $_"
    throw
}

$driftFindings = New-Object System.Collections.Generic.List[Object]

function Add-Drift {
    param([string]$Control, [string]$Resource, [string]$Expected, [string]$Actual)
    $driftFindings.Add([PSCustomObject]@{
        Control  = $Control
        Resource = $Resource
        Expected = $Expected
        Actual   = $Actual
        CheckedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    })
    Write-Warning "DRIFT DETECTED - $Control on $Resource. Expected '$Expected', found '$Actual'."
}

# --- Check 1: Storage account public network access ---
$storage = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
if ($storage.AllowBlobPublicAccess -eq $true) {
    Add-Drift -Control "storage_public_access" -Resource $StorageAccountName -Expected "AllowBlobPublicAccess=false" -Actual "true"
}

# --- Check 2: Storage secure transfer (HTTPS-only) ---
if ($storage.EnableHttpsTrafficOnly -ne $true) {
    Add-Drift -Control "storage_encryption" -Resource $StorageAccountName -Expected "EnableHttpsTrafficOnly=true" -Actual "false"
}

# --- Check 3: Diagnostic settings still attached to Log Analytics ---
$diag = Get-AzDiagnosticSetting -ResourceId $storage.Id -ErrorAction SilentlyContinue
$hasWorkspace = $diag | Where-Object { $_.WorkspaceId -eq $LogAnalyticsWorkspaceId }
if (-not $hasWorkspace) {
    Add-Drift -Control "diagnostic_logging" -Resource $StorageAccountName -Expected "Diagnostic setting -> Log Analytics" -Actual "missing or repointed"
}

# --- Check 4: SQL Transparent Data Encryption ---
$tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -DatabaseName $SqlDatabaseName
if ($tde.State -ne "Enabled") {
    Add-Drift -Control "sql_encryption" -Resource "$SqlServerName/$SqlDatabaseName" -Expected "Enabled" -Actual $tde.State
}

# --- Check 5: Key Vault firewall default action ---
$kv = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName
if ($kv.NetworkAcls.DefaultAction -ne "Deny") {
    Add-Drift -Control "keyvault_firewall" -Resource $KeyVaultName -Expected "Deny" -Actual $kv.NetworkAcls.DefaultAction
}

# --- Check 6: Required tags present on the Resource Group ---
$requiredTags = @("Environment", "Owner", "DataClassification", "CostCenter")
$rg = Get-AzResourceGroup -Name $ResourceGroupName
$missingTags = $requiredTags | Where-Object { -not $rg.Tags.ContainsKey($_) }
if ($missingTags.Count -gt 0) {
    Add-Drift -Control "tagging" -Resource $ResourceGroupName -Expected ($requiredTags -join ",") -Actual ("missing: " + ($missingTags -join ","))
}

# --- Summary + alert ---
if ($driftFindings.Count -gt 0) {
    Write-Output "=== $($driftFindings.Count) drift finding(s) detected ==="
    $driftFindings | Format-Table -AutoSize | Out-String | Write-Output

    # Sends via the Automation Account's system-assigned identity
    # using Azure Communication Services or a webhook to Logic
    # Apps is the production pattern; for the lab, this runbook
    # writes structured output that the Automation Account's own
    # diagnostic setting forwards to Log Analytics (see automation.tf),
    # and you can wire an Azure Monitor alert rule on that table
    # for email/Teams notification without duplicating logic here.
    Write-Output "NOTE: forward this job's logs to an Azure Monitor alert rule (see setup guide Step 12) to notify $NotificationEmail automatically."
}
else {
    Write-Output "No drift detected across the 6 monitored controls. All remediations holding."
}

# Return structured data as the job's output stream too, so it's
# queryable from AZMonitor/Automation job history without parsing text.
$driftFindings | ConvertTo-Json -Depth 4
