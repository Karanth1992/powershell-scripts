function Enable-DCPerformanceBaseline {
<#
.SYNOPSIS
    Deploys a performance baseline Data Collector Set across all domain controllers.

.DESCRIPTION
    Remotely creates and starts a logman Data Collector Set on every DC in the domain.
    Collects key performance counters including CPU, memory, disk, network, and NTDS/LDAP
    metrics at 5-minute intervals. Output is stored locally on each DC under
    C:\PerfLogs\DC_Baseline\ in a circular binary log capped at 500MB.

    Writes a small deployment script to each DC over SMB (C$) and launches it via
    WMI Win32_Process - no PSRemoting/WinRM required. The deployment script runs
    logman locally on the DC and records logman's real exit code and console output
    to a result file, which this function reads back over SMB so the reported
    success/failure/already-exists status reflects what logman actually did rather
    than a guess based on the WMI process-creation return code.

    Safe to re-run - reports "already exists"/"already running" from logman's own
    output rather than erroring out.

.EXAMPLE
    Enable-DCPerformanceBaseline
    Deploys the baseline collector to all DCs in the current domain.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  2.0
    Run as Domain Admin or equivalent with WMI/DCOM and SMB (C$) access to all DCs.
    Read-only against AD; makes changes on each DC's local filesystem and starts a
    local performance-monitoring service (Data Collector Set) on each DC.
#>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $ResultWaitSeconds = 30
    $remoteLogFolder = 'C:\PerfLogs\DC_Baseline'
    $remoteScriptPath = "$remoteLogFolder\Deploy-Baseline.ps1"

    # This becomes a real .ps1 file on the target DC, so normal PowerShell line
    # continuation and quoting work as expected - no WMI command-line escaping needed.
    $deployScriptContent = @'
$ErrorActionPreference = 'Stop'
$logFolder  = 'C:\PerfLogs\DC_Baseline'
$resultPath = Join-Path $logFolder 'Deploy-Baseline.result.json'

$result = [ordered]@{
    FolderReady             = $false
    CollectorCreateExitCode = $null
    CollectorCreateOutput   = $null
    CollectorStartExitCode  = $null
    CollectorStartOutput    = $null
    Error                   = $null
}

try {
    if (-not (Test-Path -LiteralPath $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    }
    $result.FolderReady = $true

    $createOutput = & logman.exe create counter DC_Baseline_Monitoring `
        -c "\Processor(_Total)\% Processor Time" `
           "\Memory\Available MBytes" `
           "\Memory\Pages/sec" `
           "\LogicalDisk(_Total)\% Free Space" `
           "\PhysicalDisk(_Total)\Disk Reads/sec" `
           "\PhysicalDisk(_Total)\Disk Writes/sec" `
           "\Network Interface(*)\Bytes Total/sec" `
           "\NTDS\LDAP Searches/sec" `
           "\NTDS\DS Directory Reads/sec" `
           "\NTDS\DS Directory Writes/sec" `
        -si 00:05:00 `
        -o "C:\PerfLogs\DC_Baseline\DC_Baseline_Monitoring" `
        -f bincirc `
        -max 500 `
        -v mmddhhmm `
        -cnf 01:00:00 2>&1 | Out-String
    $result.CollectorCreateExitCode = $LASTEXITCODE
    $result.CollectorCreateOutput   = $createOutput.Trim()

    $startOutput = & logman.exe start DC_Baseline_Monitoring 2>&1 | Out-String
    $result.CollectorStartExitCode = $LASTEXITCODE
    $result.CollectorStartOutput   = $startOutput.Trim()
}
catch {
    $result.Error = $_.Exception.Message
}
finally {
    ($result | ConvertTo-Json) | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
'@

    $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

    foreach ($DC in $DomainControllers) {
        Write-Host "`nConfiguring $DC..." -ForegroundColor Cyan

        if (-not $PSCmdlet.ShouldProcess($DC, 'Deploy and start performance baseline Data Collector Set')) {
            continue
        }

        try {
            $uncLogFolder   = "\\$DC\C$\PerfLogs\DC_Baseline"
            $uncScriptPath  = "\\$DC\C$\PerfLogs\DC_Baseline\Deploy-Baseline.ps1"
            $uncResultPath  = "\\$DC\C$\PerfLogs\DC_Baseline\Deploy-Baseline.result.json"

            if (Test-Path -LiteralPath $uncResultPath) {
                Remove-Item -LiteralPath $uncResultPath -Force -ErrorAction SilentlyContinue
            }
            if (-not (Test-Path -LiteralPath $uncLogFolder)) {
                New-Item -ItemType Directory -Path $uncLogFolder -Force | Out-Null
            }
            Set-Content -LiteralPath $uncScriptPath -Value $deployScriptContent -Encoding UTF8 -Force

            $wmi = [WMIClass]"\\$DC\root\cimv2:Win32_Process"
            $launch = $wmi.Create("powershell.exe -NonInteractive -ExecutionPolicy Bypass -File `"$remoteScriptPath`"")
            if ($launch.ReturnValue -ne 0) {
                Write-Warning "  [WARN] Could not launch deployment process on $DC (WMI ReturnValue: $($launch.ReturnValue))"
                continue
            }

            $waited = 0
            $pollIntervalSeconds = 2
            while (-not (Test-Path -LiteralPath $uncResultPath) -and $waited -lt $ResultWaitSeconds) {
                Start-Sleep -Seconds $pollIntervalSeconds
                $waited += $pollIntervalSeconds
            }

            if (-not (Test-Path -LiteralPath $uncResultPath)) {
                Write-Warning "  [WARN] Timed out after $ResultWaitSeconds second(s) waiting for deployment result from $DC"
                continue
            }

            $deployResult = Get-Content -LiteralPath $uncResultPath -Raw | ConvertFrom-Json

            if ($deployResult.Error) {
                Write-Warning "  [WARN] Deployment script reported an error on $DC : $($deployResult.Error)"
                continue
            }

            if ($deployResult.CollectorCreateExitCode -eq 0) {
                Write-Host "  [OK] Data Collector Set created on $DC"
            }
            else {
                Write-Warning "  [WARN] logman create exited $($deployResult.CollectorCreateExitCode) on $DC : $($deployResult.CollectorCreateOutput)"
            }

            if ($deployResult.CollectorStartExitCode -eq 0) {
                Write-Host "  [OK] Data Collector Set started on $DC"
            }
            else {
                Write-Warning "  [WARN] logman start exited $($deployResult.CollectorStartExitCode) on $DC : $($deployResult.CollectorStartOutput)"
            }
        }
        catch {
            Write-Error "Failed to contact $DC : $_"
        }
    }

    Write-Host "`nDone. Review warnings above for any DCs that need attention." -ForegroundColor Cyan
}
