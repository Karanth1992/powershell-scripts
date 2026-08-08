function Get-EntraConnectSyncStatus {
<#
.SYNOPSIS
    Reports the health and sync status of an Entra Connect (Azure AD Connect) server.

.DESCRIPTION
    Must be run locally on the Entra Connect server - it collects:

    - Last sync cycle time and result (delta / initial / export)
    - Connector export/import activity counts per connector (adds/updates/
      deletes/no-change) - ADSync's connector statistics API does not expose
      a per-connector error count; check the Synchronization Service Manager
      UI or Get-ADSyncRunProfileResult for actual sync errors
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

    Set-StrictMode -Version Latest

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

        # Global settings has no product-version parameter (an earlier version
        # of this script looked up 'Microsoft.Synchronize.SynchronizationVersion',
        # which does not exist and always evaluated to $null). The real product
        # version is the file version of the sync engine binary.
        $version = 'Unknown'
        try {
            $miiserverPath = Join-Path $env:ProgramFiles 'Microsoft Azure AD Sync\Bin\miiserver.exe'
            if (Test-Path -LiteralPath $miiserverPath) {
                $version = (Get-Item -LiteralPath $miiserverPath).VersionInfo.ProductVersion
            }
        } catch {
            Write-Verbose "Could not read miiserver.exe version; leaving Version as 'Unknown'. $($_.Exception.Message)"
        }

        # Scheduler has no "last successful sync" property - the closest real
        # signal is the most recent run's own result/timestamp from run history.
        $lastRunResult = $null
        try {
            $lastRunResult = Get-ADSyncRunProfileResult -NumberRequested 1 -ErrorAction Stop | Select-Object -First 1
        } catch {
            Write-Verbose "Run history unavailable; leaving LastRunResult as `$null. $($_.Exception.Message)"
        }

        # -- Connector summary --
        # Microsoft.IdentityManagement.PowerShell.ObjectModel.ConnectorStatistics
        # (the real type Get-ADSyncConnectorStatistics returns) only exposes
        # ExportAdds/Updates/Deletes and ImportAdds/Updates/Deletes/NoChange -
        # there is no per-connector error-count property on this object. An
        # earlier version of this script read ExportErrors/ImportErrors/
        # PendingExport* here, which don't exist on this type and always
        # silently evaluated to $null.
        $connectors = Get-ADSyncConnector | ForEach-Object {
            $stats = Get-ADSyncConnectorStatistics -ConnectorName $_.Name

            [PSCustomObject]@{
                ConnectorName  = $_.Name
                Type           = $_.Type
                ExportAdds     = $stats.ExportAdds
                ExportUpdates  = $stats.ExportUpdates
                ExportDeletes  = $stats.ExportDeletes
                ImportAdds     = $stats.ImportAdds
                ImportUpdates  = $stats.ImportUpdates
                ImportDeletes  = $stats.ImportDeletes
                ImportNoChange = $stats.ImportNoChange
            }
        }

        # -- Password sync --
        $pwdSync = $null
        try {
            $pwdSync = Get-ADSyncAADPasswordSyncConfiguration -SourceConnector (
                $connectors | Where-Object Type -eq 'AD' | Select-Object -First 1 -ExpandProperty ConnectorName
            )
        } catch {
            Write-Verbose "Password sync not configured for this source connector; skipping. $($_.Exception.Message)"
        }

        [PSCustomObject]@{
            Version              = $version
            StagingModeEnabled   = $scheduler.StagingModeEnabled
            # Get-ADSyncAutoUpgrade returns the state enum value directly
            # (AutoUpgradeConfigurationState), not an object with a .State
            # property - the earlier .State access always returned $null.
            AutoUpgradeState     = [string](Get-ADSyncAutoUpgrade)
            # The real scheduler property is SyncCycleEnabled - an earlier
            # version of this script read SyncEnabled, which doesn't exist.
            SyncEnabled          = $scheduler.SyncCycleEnabled
            NextSyncCycle        = $scheduler.NextSyncCyclePolicyType
            SchedulerSuspended   = $scheduler.SchedulerSuspended
            # LastSyncRunStartTime doesn't exist on the scheduler object - an
            # earlier version of this script read it there and always got
            # $null. Real run history comes from Get-ADSyncRunProfileResult.
            LastSuccessfulSync   = if ($lastRunResult) { $lastRunResult.StartDate } else { $null }
            LastSyncResult       = if ($lastRunResult) { $lastRunResult.Result } else { 'Unknown' }
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
    Write-StatusLine "Last Sync Run"          $result.LastSuccessfulSync
    Write-StatusLine "Last Sync Result"       $result.LastSyncResult       "success"
    Write-StatusLine "Password Sync Enabled"  $result.PasswordSyncEnabled  "True"

    Write-Header "Connector Summary"

    $result.Connectors | Format-Table -AutoSize `
        ConnectorName, Type, ExportAdds, ExportUpdates, ExportDeletes,
        ImportAdds, ImportUpdates, ImportDeletes, ImportNoChange

    # ADSync's ConnectorStatistics object has no per-connector error-count
    # property, so pending export/import activity is used as the "needs
    # attention" signal instead of a genuine error count. For real sync
    # errors, check the Synchronization Service Manager UI or
    # Get-ADSyncRunProfileResult for the relevant run history.
    $hasPendingExports = $result.Connectors | Where-Object { $_.ExportAdds -gt 0 -or $_.ExportUpdates -gt 0 -or $_.ExportDeletes -gt 0 }
    if ($hasPendingExports) {
        Write-Host "  ATTENTION: One or more connectors have pending export changes." -ForegroundColor Red
        Write-Warning "One or more Entra Connect connectors have pending export changes."
        $hasPendingExports | Format-Table -AutoSize ConnectorName, ExportAdds, ExportUpdates, ExportDeletes
    } else {
        Write-Host "  All connectors have zero pending export changes." -ForegroundColor Green
    }

    if ($result.StagingModeEnabled -eq $true) {
        Write-Host "`n  WARNING: Entra Connect is in STAGING MODE - no changes are being written to Azure AD." -ForegroundColor Yellow
    }

    # ============ EXPORT ============

    if ($ExportPath -ne "") {
        $exportDir = Split-Path -LiteralPath $ExportPath
        if ($exportDir -and -not (Test-Path -LiteralPath $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
        $result.Connectors | Export-Csv -NoTypeInformation -LiteralPath $ExportPath
        Write-Host "`nConnector stats exported to $ExportPath" -ForegroundColor Green
    }
}
