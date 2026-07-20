function Get-EntraConnectSyncStatus {
<#
.SYNOPSIS
    Reports the health and sync status of an Entra Connect (Azure AD Connect) server.

.DESCRIPTION
    Must be run locally on the Entra Connect server - it collects:

    - Last sync cycle time and result (delta / initial / export)
    - Connector export/import error counts per connector
    - Password hash sync status
    - Staging mode state
    - Auto-upgrade setting
    - Pending export objects (adds, updates, deletes) per connector

    Outputs a summary to the console and optionally exports a CSV.
    Requires the ADSync module installed on the Entra Connect server.

    Does not use PSRemoting/WinRM, which is assumed blocked in this
    environment. Remote execution against another server's ADSync state
    would require WinRM (Invoke-Command); that path has been intentionally
    removed. Run this function directly on the Entra Connect server itself
    (e.g. via a scheduled task or interactive session on that box).

.PARAMETER ComputerName
    Informational only - used for report labelling. Must match the local
    machine name; this function cannot query a remote Entra Connect server.

.PARAMETER ExportPath
    Optional path to export connector results as CSV.
    Example: "C:\temp\EntraConnectStatus.csv"

.EXAMPLE
    Get-EntraConnectSyncStatus
    Runs against the local machine (must be executed on the Entra Connect server).

.EXAMPLE
    Get-EntraConnectSyncStatus -ExportPath "C:\temp\sync.csv"
    Runs locally and exports connector stats to CSV.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  2.0
    Requires: ADSync PowerShell module (installed with Entra Connect),
              run as local Administrator or ADSyncAdmins group member,
              locally on the Entra Connect server. WinRM/PSRemoting is not
              used or required.
#>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$ExportPath   = "C:\ADOpsKit\Reports\Get-EntraConnectSyncStatus\$(Get-Date -Format 'yyyy-MM-dd')_EntraConnectStatus.csv"
    )

    if ($ComputerName -ne $env:COMPUTERNAME) {
        throw "Get-EntraConnectSyncStatus must be run locally on the Entra Connect server. " +
              "-ComputerName '$ComputerName' does not match the local machine name '$env:COMPUTERNAME', " +
              "and remote execution via WinRM/PSRemoting is not supported in this environment. " +
              "Run this function directly on '$ComputerName' instead."
    }

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

    # ============ LOCAL EXECUTION ============
    # $ComputerName is validated above to match the local machine - no
    # WinRM/PSRemoting is used here, only local module calls.

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
        } catch { <# Password sync not configured - skip #> }

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
        $result = & $syncScript
    } catch {
        Write-Error "Failed to retrieve Entra Connect status: $_"
        return
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
        Write-Host "`n  WARNING: Entra Connect is in STAGING MODE - no changes are being written to Azure AD." -ForegroundColor Yellow
    }

    # ============ EXPORT ============

    if ($ExportPath -ne "") {
        $exportDir = Split-Path $ExportPath
        if ($exportDir -and -not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
        $result.Connectors | Export-Csv -NoTypeInformation -Path $ExportPath
        Write-Host "`nConnector stats exported to $ExportPath" -ForegroundColor Green
    }
}
