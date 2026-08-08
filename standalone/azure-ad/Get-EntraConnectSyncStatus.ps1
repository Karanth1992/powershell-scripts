<#
.SYNOPSIS
    Reports the health and sync status of an Entra Connect (Azure AD Connect) server.

.DESCRIPTION
    Connects to the local or a remote Entra Connect server and collects:

    - Last sync cycle time and result (delta / initial / export)
    - Connector export/import error counts per connector
    - Password hash sync status
    - Staging mode state
    - Auto-upgrade setting
    - Pending export objects (adds, updates, deletes) per connector

    Outputs a summary to the console and optionally exports a CSV.
    Requires the ADSync module installed on the Entra Connect server.

.PARAMETER ComputerName
    Name of the Entra Connect server. Defaults to the local machine.

.PARAMETER ExportPath
    Optional path to export connector results as CSV.
    Example: "C:\temp\EntraConnectStatus.csv"

.EXAMPLE
    .\Get-EntraConnectSyncStatus.ps1
    Runs against the local machine (must be executed on the Entra Connect server).

.EXAMPLE
    .\Get-EntraConnectSyncStatus.ps1 -ComputerName "AADCONN01" -ExportPath "C:\temp\sync.csv"
    Runs against a remote Entra Connect server and exports connector stats.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ADSync PowerShell module (installed with Entra Connect),
              run as local Administrator or ADSyncAdmins group member
#>

param (
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$ExportPath   = ""
)

# ============ HELPERS ============

function Write-Header {
    param([string]$Title)
    Write-Host "`n===== $Title =====" -ForegroundColor Cyan
}

function Write-StatusLine {
    param([string]$Label, $Value, [string]$OkValue = "")
    $color = if ($OkValue -and $Value -ne $OkValue) { 'Yellow' } else { 'White' }
    Write-Host ("  {0,-40} {1}" -f $Label, $Value) -ForegroundColor $color
}

# ============ REMOTE OR LOCAL EXECUTION ============

$isRemote = $ComputerName -ne $env:COMPUTERNAME

$syncScript = {
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Module -ListAvailable -Name ADSync)) {
        throw "ADSync module not found. Run this script on the Entra Connect server."
    }
    Import-Module ADSync

    # -- Global sync state --
    $scheduler   = Get-ADSyncScheduler
    $version     = (Get-ADSyncGlobalSettings).Parameters |
                   Where-Object Name -eq 'Microsoft.Synchronize.SynchronizationVersion' |
                   Select-Object -ExpandProperty Value

    # -- Connector summary --
    $connectors = Get-ADSyncConnector | ForEach-Object {
        $stats = Get-ADSyncConnectorStatistics -ConnectorName $_.Name

        [PSCustomObject]@{
            ConnectorName    = $_.Name
            Type             = $_.Type
            ExportErrors     = $stats.ExportErrors
            ImportErrors     = $stats.ImportErrors
            PendingExportAdd = $stats.PendingExportAdd
            PendingExportUpdate = $stats.PendingExportUpdate
            PendingExportDelete = $stats.PendingExportDelete
        }
    }

    # -- Password sync --
    $pwdSync = $null
    try {
        $pwdSync = Get-ADSyncAADPasswordSyncConfiguration -SourceConnector (
            $connectors | Where-Object Type -eq 'AD' | Select-Object -First 1 -ExpandProperty ConnectorName
        )
    } catch { }

    [PSCustomObject]@{
        Version              = $version
        StagingModeEnabled   = $scheduler.StagingModeEnabled
        AutoUpgradeState     = (Get-ADSyncAutoUpgrade).State
        SyncEnabled          = $scheduler.SyncEnabled
        NextSyncCycle        = $scheduler.NextSyncCyclePolicyType
        SchedulerSuspended   = $scheduler.SchedulerSuspended
        LastSuccessfulSync   = $scheduler.LastSyncRunStartTime
        PasswordSyncEnabled  = if ($pwdSync) { $pwdSync.Enabled } else { 'N/A' }
        Connectors           = $connectors
    }
}

# ============ EXECUTE ============

try {
    if ($isRemote) {
        Write-Host "Connecting to $ComputerName..." -ForegroundColor Cyan
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $syncScript
    } else {
        $result = & $syncScript
    }
} catch {
    Write-Error "Failed to retrieve Entra Connect status: $_"
    exit 1
}

# ============ OUTPUT ============

Write-Header "Entra Connect Global Status"
Write-StatusLine "Server"                 $ComputerName
Write-StatusLine "Entra Connect Version"  $result.Version
Write-StatusLine "Staging Mode"           $result.StagingModeEnabled   "False"
Write-StatusLine "Sync Enabled"           $result.SyncEnabled          "True"
Write-StatusLine "Scheduler Suspended"    $result.SchedulerSuspended   "False"
Write-StatusLine "Auto-Upgrade"           $result.AutoUpgradeState     "Enabled"
Write-StatusLine "Next Sync Policy"       $result.NextSyncCycle
Write-StatusLine "Last Successful Sync"   $result.LastSuccessfulSync
Write-StatusLine "Password Sync Enabled"  $result.PasswordSyncEnabled  "True"

Write-Header "Connector Summary"

$result.Connectors | Format-Table -AutoSize `
    ConnectorName, Type, ExportErrors, ImportErrors,
    PendingExportAdd, PendingExportUpdate, PendingExportDelete

$hasErrors = $result.Connectors | Where-Object { $_.ExportErrors -gt 0 -or $_.ImportErrors -gt 0 }
if ($hasErrors) {
    Write-Host "  ATTENTION: One or more connectors have sync errors." -ForegroundColor Red
    $hasErrors | Format-Table -AutoSize ConnectorName, ExportErrors, ImportErrors
} else {
    Write-Host "  All connectors report zero sync errors." -ForegroundColor Green
}

if ($result.StagingModeEnabled -eq $true) {
    Write-Host "`n  WARNING: Entra Connect is in STAGING MODE — no changes are being written to Azure AD." -ForegroundColor Yellow
}

# ============ EXPORT ============

if ($ExportPath -ne "") {
    $result.Connectors | Export-Csv -NoTypeInformation -Path $ExportPath
    Write-Host "`nConnector stats exported to $ExportPath" -ForegroundColor Green
}
