<#
.SYNOPSIS
    Deploys a performance baseline Data Collector Set across all domain controllers.

.DESCRIPTION
    Remotely creates and starts a logman Data Collector Set on every DC in the domain.
    Collects key performance counters including CPU, memory, disk, network, and NTDS/LDAP
    metrics at 5-minute intervals. Output is stored locally on each DC under
    C:\PerfLogs\DC_Baseline\ in a circular binary log capped at 500MB.

    Uses WMI Win32_Process to execute commands remotely — no PSRemoting required.
    Safe to re-run — warns if the collector already exists rather than erroring out.

.EXAMPLE
    .\Enable-DCPerformanceBaseline.ps1
    Deploys the baseline collector to all DCs in the current domain.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ActiveDirectory module, WMI access to all DCs,
              run as Domain Admin or equivalent
#>

Import-Module ActiveDirectory

$logmanCreate = @'
logman create counter DC_Baseline_Monitoring `
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
  -cnf 01:00:00
'@

$logmanStart   = 'logman start DC_Baseline_Monitoring'
$prepareFolder = 'if (!(Test-Path C:\PerfLogs\DC_Baseline)) { New-Item -ItemType Directory -Path C:\PerfLogs\DC_Baseline | Out-Null }'

$DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($DC in $DomainControllers) {
    Write-Host "`nConfiguring $DC..." -ForegroundColor Cyan

    try {
        $wmi = [WMIClass]"\\$DC\root\cimv2:Win32_Process"

        # Step 1 — ensure log folder exists
        $result = $wmi.Create("powershell.exe -NonInteractive -Command `"$prepareFolder`"")
        if ($result.ReturnValue -eq 0) {
            Write-Host "  [OK] Log folder verified on $DC"
        }
        else {
            Write-Warning "  [WARN] Could not verify log folder on $DC (ReturnValue: $($result.ReturnValue))"
        }

        # Step 2 — create the Data Collector Set
        $result = $wmi.Create($logmanCreate)
        if ($result.ReturnValue -eq 0) {
            Write-Host "  [OK] Data Collector Set created on $DC"
        }
        else {
            Write-Warning "  [WARN] Collector may already exist on $DC (ReturnValue: $($result.ReturnValue))"
        }

        # Step 3 — start the Data Collector Set
        $result = $wmi.Create($logmanStart)
        if ($result.ReturnValue -eq 0) {
            Write-Host "  [OK] Data Collector Set started on $DC"
        }
        else {
            Write-Warning "  [WARN] Collector may already be running on $DC (ReturnValue: $($result.ReturnValue))"
        }
    }
    catch {
        Write-Error "Failed to contact $DC : $_"
    }
}

Write-Host "`nDone. Review warnings above for any DCs that need attention." -ForegroundColor Cyan