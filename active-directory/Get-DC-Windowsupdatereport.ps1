#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Audits Windows Updates on all AD Domain Controllers and produces a
    colour-coded HTML report.  NO WinRM / WSMan required.

.DESCRIPTION
    Transport layer — WMI over DCOM (RPC port 135 + dynamic high ports) and
    Remote Registry over SMB (port 445).  WinRM is never used.

    Per DC the script collects:
      * Installed updates in the last N days  — primary:   WUA via WMI process
                                                 injection; fallback: Win32_QuickFixEngineering
      * Pending (not-yet-installed) updates   — WUA via WMI process injection
      * Reboot-pending status                 — Remote Registry (4 common keys)
      * Basic connectivity                    — TCP port 135 test (no WSMan)

    HTML Colour scheme:
      GREEN  — all updates succeeded, no restart required, no pending updates
      YELLOW — restart pending | update failed/in-progress | pending updates exist
      RED    — DC unreachable (RPC port 135 blocked or host down)

.PARAMETER Domain
    AD domain FQDN to query.  Defaults to the current user's logged-on domain.

.PARAMETER DaysBack
    Lookback window in days for installed-update history.  Default: 7.

.PARAMETER ReportPath
    Full path for the output HTML file.  Defaults to the current working directory.

.PARAMETER ThrottleLimit
    Maximum concurrent background jobs.  Default: 10.

.NOTES
    Author      : Senior PowerShell Engineer
    Version     : 3.0  (WMI/DCOM + Remote Registry — WinRM-free)
    Tested on   : Windows Server 2016 / 2019 / 2022, PowerShell 5.1
    Requirements: RSAT ActiveDirectory module
                  RPC port 135 open (+ dynamic high ports for DCOM)
                  SMB port 445 open (Remote Registry)
                  Script account = Domain Admin or equivalent delegated rights

    Pending-update detection strategy
    ──────────────────────────────────
    The WUA COM object (Microsoft.Update.Session) cannot be instantiated
    across the network directly over DCOM.  This script uses WMI's
    Win32_Process.Create() to spawn a hidden PowerShell process ON the
    remote DC, which (a) queries WUA locally, (b) serialises results as a
    JSON string into a temporary registry value under HKLM, then exits.
    The script reads that registry value back via .NET Remote Registry
    (SMB/port 445), parses the JSON, and deletes the temp key.
    No file shares, no WinRM, no scheduled tasks are needed.
#>

[CmdletBinding()]
param (
    [string]$Domain        = $env:USERDNSDOMAIN,
    [int]   $DaysBack      = 7,
    [string]$ReportPath    = ".\DC_WindowsUpdate_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [int]   $ThrottleLimit = 10
)

# StrictMode intentionally omitted: WMI/COM objects and single-item pipeline
# results do not expose .Count in PS 5.1 strict mode, which causes
# PropertyNotFoundException on environments with only one DC or one update.
$ErrorActionPreference = 'Stop'

#region ── Helper functions ────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $colour = switch ($Level) {
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red'    }
        default { 'Cyan'   }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $colour
}

# ── TCP port test — replaces Test-WSMan completely ──────────────────────────
function Test-RpcConnectivity {
    param(
        [string]$ComputerName,
        [int]   $TimeoutMs = 2000
    )
    try {
        $tcp    = New-Object System.Net.Sockets.TcpClient
        $ar     = $tcp.BeginConnect($ComputerName, 135, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($waited -and $tcp.Connected) {
            $tcp.EndConnect($ar)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

# ── Reboot pending — Remote Registry (.NET) over SMB port 445 ───────────────
function Get-RebootPendingStatus {
    param([string]$ComputerName)
    try {
        $hklm    = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                       [Microsoft.Win32.RegistryHive]::LocalMachine,
                       $ComputerName)
        $pending = $false

        # 1. Component Based Servicing
        $k = $hklm.OpenSubKey(
                 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        if ($null -ne $k) { $pending = $true; $k.Close() }

        # 2. Windows Update Auto Update
        $k = $hklm.OpenSubKey(
                 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        if ($null -ne $k) { $pending = $true; $k.Close() }

        # 3. PendingFileRenameOperations
        $k = $hklm.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager')
        if ($null -ne $k) {
            $pfro = $k.GetValue('PendingFileRenameOperations')
            if ($null -ne $pfro -and $pfro.Length -gt 0) { $pending = $true }
            $k.Close()
        }

        # 4. SCCM / ConfigMgr client reboot request
        $k = $hklm.OpenSubKey('SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData')
        if ($null -ne $k) {
            if ($null -ne $k.GetValue('RebootBy')) { $pending = $true }
            $k.Close()
        }

        $hklm.Close()
        return $pending
    } catch {
        return $null   # $null = unknown (rendered as warning in report)
    }
}

# ── Fallback update source: Win32_QuickFixEngineering over WMI/DCOM ─────────
function Get-InstalledUpdatesWMI {
    param([string]$ComputerName, [int]$DaysBack)

    $cutoff  = (Get-Date).AddDays(-$DaysBack)
    $updates = @()
    try {
        $qfe = @(Get-WmiObject -Class Win32_QuickFixEngineering `
                               -ComputerName $ComputerName `
                               -ErrorAction Stop)
        foreach ($item in $qfe) {
            $dt = $null
            if ($item.InstalledOn) {
                try { $dt = [datetime]::Parse($item.InstalledOn) } catch {}
            }
            # Include if within window, or if date is unknown (be conservative)
            if ($null -eq $dt -or $dt -ge $cutoff) {
                $updates += [pscustomobject]@{
                    Title       = if ($item.Description) {
                                      "$($item.Description) ($($item.HotFixID))"
                                  } else { $item.HotFixID }
                    KB          = if ($item.HotFixID -match '^KB\d+$') { $item.HotFixID } else { 'N/A' }
                    InstalledOn = $dt
                    ResultCode  = 2
                    ResultText  = 'Succeeded'
                    IsSuccess   = $true
                    IsWarning   = $false
                    IsFailure   = $false
                    Source      = 'Win32_QuickFixEngineering'
                }
            }
        }
    } catch {
        # Caller will surface the empty array and log appropriately
    }
    return $updates
}

# ── Primary update source: WUA via WMI Win32_Process injection ───────────────
# Spawns a hidden PS process on the DC via WMI (no WinRM), queries WUA
# locally, writes JSON to a temporary HKLM registry value, which we then
# retrieve via Remote Registry and clean up.
function Get-WuaDataViaWmi {
    param([string]$ComputerName, [int]$DaysBack)

    $result = @{
        InstalledUpdates = @()
        PendingUpdates   = @()
        WuaAvailable     = $false
        ErrorMessage     = $null
    }

    # Temp registry path written by the remote process, read back by us
    $regKeyPath   = 'SOFTWARE\DCPatchAudit_Temp'
    $regValueName = 'WuaResult'

    # The PowerShell script that runs ON the remote DC.
    # Uses only built-in .NET types — no module imports needed.
    $remoteScript = @'
try {
    $days   = DAYS_PLACEHOLDER
    $cutoff = (Get-Date).AddDays(-$days)
    $sess   = New-Object -ComObject Microsoft.Update.Session
    $srch   = $sess.CreateUpdateSearcher()
    $total  = $srch.GetTotalHistoryCount()
    $inst   = @()
    if ($total -gt 0) {
        $hist = $srch.QueryHistory(0, $total)
        foreach ($h in $hist) {
            if ($h.Date -ge $cutoff) {
                $inst += @{
                    T  = [string]$h.Title
                    KB = if ($h.Title -match "(KB\d+)") { $Matches[1] } else { "N/A" }
                    D  = $h.Date.ToString("o")
                    RC = [int]$h.ResultCode
                }
            }
        }
    }
    $pend = @()
    try {
        $pr = $srch.Search("IsInstalled=0 and IsHidden=0")
        foreach ($u in $pr.Updates) {
            $pend += @{
                T    = [string]$u.Title
                KB   = if ($u.Title -match "(KB\d+)") { $Matches[1] } else { "N/A" }
                Sev  = if ($u.MsrcSeverity) { [string]$u.MsrcSeverity } else { "Unspecified" }
                Cat  = (($u.Categories | ForEach-Object { $_.Name }) -join ", ")
            }
        }
    } catch {}
    $json = @{ inst=$inst; pend=$pend } | ConvertTo-Json -Depth 5 -Compress
    $rk   = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SOFTWARE\DCPatchAudit_Temp")
    $rk.SetValue("WuaResult", $json, [Microsoft.Win32.RegistryValueKind]::String)
    $rk.Close()
} catch {
    $rk = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SOFTWARE\DCPatchAudit_Temp")
    $rk.SetValue("WuaResult", "ERR:$($_.Exception.Message)", [Microsoft.Win32.RegistryValueKind]::String)
    $rk.Close()
}
'@

    $remoteScript = $remoteScript -replace 'DAYS_PLACEHOLDER', $DaysBack

    # Base64-encode the script to safely pass it via cmd.exe command line
    $bytes  = [System.Text.Encoding]::Unicode.GetBytes($remoteScript)
    $b64    = [Convert]::ToBase64String($bytes)
    $cmdLine = "powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand $b64"

    try {
        # Invoke Win32_Process.Create on the remote DC — pure DCOM, no WinRM
        $wmiProc    = [wmiclass]"\\$ComputerName\root\cimv2:Win32_Process"
        $createResult = $wmiProc.Create($cmdLine)

        if ($createResult.ReturnValue -ne 0) {
            $result.ErrorMessage = "Win32_Process.Create() returned error code $($createResult.ReturnValue)"
            return $result
        }

        $remotePid = $createResult.ProcessId

        # Wait for the remote PowerShell process to exit (timeout: 120 s)
        $deadline = (Get-Date).AddSeconds(120)
        do {
            Start-Sleep -Seconds 2
            $alive = @(Get-WmiObject -Class Win32_Process `
                                     -ComputerName $ComputerName `
                                     -Filter "ProcessId = $remotePid" `
                                     -ErrorAction SilentlyContinue)
        } while ($alive.Count -gt 0 -and (Get-Date) -lt $deadline)

        # Read result from remote registry via SMB
        $hklm   = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                      [Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $tmpKey = $hklm.OpenSubKey($regKeyPath)

        if ($null -eq $tmpKey) {
            $result.ErrorMessage = 'WUA temp registry key not found — remote script may have timed out'
            $hklm.Close()
            return $result
        }

        $payload = $tmpKey.GetValue($regValueName)
        $tmpKey.Close()

        # Clean up the temp registry key on the remote DC (best effort)
        try { $hklm.DeleteSubKeyTree($regKeyPath) } catch {}
        $hklm.Close()

        if (-not $payload) {
            $result.ErrorMessage = 'WUA registry value was empty after remote execution'
            return $result
        }

        if ($payload -like 'ERR:*') {
            $result.ErrorMessage = "Remote WUA script error: $($payload -replace '^ERR:','')"
            return $result
        }

        # Parse the JSON and map into typed objects
        $data = $payload | ConvertFrom-Json
        $result.WuaAvailable = $true

        foreach ($i in $data.inst) {
            $rc = [int]$i.RC
            $dt = $null
            try { $dt = [datetime]::Parse($i.D) } catch {}

            $result.InstalledUpdates += [pscustomobject]@{
                Title       = [string]$i.T
                KB          = [string]$i.KB
                InstalledOn = $dt
                ResultCode  = $rc
                ResultText  = switch ($rc) {
                                1 { 'In Progress'           }
                                2 { 'Succeeded'             }
                                3 { 'Succeeded With Errors' }
                                4 { 'Failed'                }
                                5 { 'Aborted'               }
                                default { "Unknown ($rc)"   }
                              }
                IsSuccess   = ($rc -eq 2)
                IsWarning   = ($rc -in @(1, 3))
                IsFailure   = ($rc -in @(4, 5))
                Source      = 'WUA'
            }
        }

        foreach ($p in $data.pend) {
            $result.PendingUpdates += [pscustomobject]@{
                Title      = [string]$p.T
                KB         = [string]$p.KB
                Severity   = [string]$p.Sev
                Categories = [string]$p.Cat
            }
        }

    } catch {
        $result.ErrorMessage = "WUA-via-WMI exception: $($_.Exception.Message)"
    }

    return $result
}

# ── Master per-DC collection orchestrator ────────────────────────────────────
function Get-DCUpdateData {
    param([string]$DCName, [int]$DaysBack)

    $result = [ordered]@{
        DCName           = $DCName
        Status           = 'Unknown'
        ReachableRPC     = $false
        InstalledUpdates = @()
        PendingUpdates   = @()
        RebootRequired   = $null
        WuaAvailable     = $false
        DataSource       = 'N/A'
        ErrorMessage     = $null
        QueryTime        = $null
    }

    # Step 1 — RPC connectivity (port 135) ───────────────────────────────────
    Write-Log "[$DCName] Testing RPC connectivity (port 135) …"
    if (-not (Test-RpcConnectivity -ComputerName $DCName)) {
        $result.Status       = 'Error'
        $result.ErrorMessage = 'RPC port 135 unreachable — host is offline or DCOM is firewalled'
        Write-Log "[$DCName] RPC unreachable" -Level 'WARN'
        return $result
    }
    $result.ReachableRPC = $true
    $result.QueryTime    = Get-Date

    # Step 2 — WUA data via WMI process injection ────────────────────────────
    Write-Log "[$DCName] Querying Windows Update Agent via WMI (no WinRM) …"
    $wuaData = Get-WuaDataViaWmi -ComputerName $DCName -DaysBack $DaysBack

    if ($wuaData.WuaAvailable) {
        $result.InstalledUpdates = @($wuaData.InstalledUpdates)
        $result.PendingUpdates   = @($wuaData.PendingUpdates)
        $result.WuaAvailable     = $true
        $result.DataSource       = 'WUA (via WMI/DCOM)'
        Write-Log "[$DCName] WUA OK — Installed: $($result.InstalledUpdates.Count) | Pending: $($result.PendingUpdates.Count)"
    } else {
        # Step 2b — Fallback to Win32_QuickFixEngineering ────────────────────
        Write-Log "[$DCName] WUA unavailable ($($wuaData.ErrorMessage)) — trying Win32_QuickFixEngineering …" -Level 'WARN'
        $result.InstalledUpdates = @(Get-InstalledUpdatesWMI -ComputerName $DCName -DaysBack $DaysBack)
        $result.DataSource       = 'Win32_QuickFixEngineering (WMI fallback — no pending data)'

        if ($result.InstalledUpdates.Count -eq 0 -and $wuaData.ErrorMessage) {
            # Surface the original WUA error so the operator knows
            $result.ErrorMessage = "WUA: $($wuaData.ErrorMessage)"
        }
        Write-Log "[$DCName] QFE fallback — found $($result.InstalledUpdates.Count) update(s)"
    }

    # Step 3 — Reboot pending via Remote Registry ────────────────────────────
    Write-Log "[$DCName] Checking reboot-pending registry keys (Remote Registry / SMB 445) …"
    $result.RebootRequired = Get-RebootPendingStatus -ComputerName $DCName

    # Step 4 — Determine overall status ──────────────────────────────────────
    $hasFailure  = @($result.InstalledUpdates | Where-Object { $_.IsFailure }).Count -gt 0
    $hasPending  = $result.PendingUpdates.Count -gt 0
    $needsReboot = $result.RebootRequired -eq $true
    $rebootUnknown = $null -eq $result.RebootRequired

    if ($hasFailure -or $needsReboot -or $hasPending -or $rebootUnknown) {
        $result.Status = 'Warning'
    } else {
        $result.Status = 'Success'
    }

    Write-Log "[$DCName] Complete — Status=$($result.Status) | Source=$($result.DataSource) | Reboot=$($result.RebootRequired)"
    return $result
}

#endregion

#region ── Discovery & parallel data collection ────────────────────────────────

Write-Log "=== DC Windows Update Audit v3.0 (WMI/DCOM + Remote Registry — no WinRM) ==="
Write-Log "Domain: $Domain | Lookback: $DaysBack days | Throttle: $ThrottleLimit jobs"
Write-Log "Discovering Domain Controllers …"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainControllers = @(
        Get-ADDomainController -Filter * -Server $Domain |
        Sort-Object HostName |
        Select-Object -ExpandProperty HostName
    )
} catch {
    Write-Log "AD discovery failed: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

if (-not $domainControllers -or $domainControllers.Count -eq 0) {
    Write-Log "No domain controllers found for '$Domain'." -Level 'WARN'
    exit 0
}

Write-Log "Found $($domainControllers.Count) DC(s): $($domainControllers -join ' | ')"

# Serialise function bodies so background jobs can reconstruct them
$fnWriteLog      = ${function:Write-Log}.ToString()
$fnTestRpc       = ${function:Test-RpcConnectivity}.ToString()
$fnRebootCheck   = ${function:Get-RebootPendingStatus}.ToString()
$fnGetQfe        = ${function:Get-InstalledUpdatesWMI}.ToString()
$fnGetWua        = ${function:Get-WuaDataViaWmi}.ToString()
$fnGetDcData     = ${function:Get-DCUpdateData}.ToString()

$jobs    = [System.Collections.Generic.List[System.Management.Automation.Job]]::new()
$allData = [System.Collections.Generic.List[object]]::new()

foreach ($dc in $domainControllers) {

    # Honour throttle limit
    while (@(Get-Job -State Running).Count -ge $ThrottleLimit) {
        Start-Sleep -Milliseconds 500
    }

    $job = Start-Job -ScriptBlock {
        param($dcName, $days,
              $fnWriteLog, $fnTestRpc, $fnRebootCheck,
              $fnGetQfe,   $fnGetWua,  $fnGetDcData)

        Set-Item Function:\Write-Log               ([scriptblock]::Create($fnWriteLog))
        Set-Item Function:\Test-RpcConnectivity    ([scriptblock]::Create($fnTestRpc))
        Set-Item Function:\Get-RebootPendingStatus ([scriptblock]::Create($fnRebootCheck))
        Set-Item Function:\Get-InstalledUpdatesWMI ([scriptblock]::Create($fnGetQfe))
        Set-Item Function:\Get-WuaDataViaWmi       ([scriptblock]::Create($fnGetWua))
        Set-Item Function:\Get-DCUpdateData        ([scriptblock]::Create($fnGetDcData))

        Get-DCUpdateData -DCName $dcName -DaysBack $days

    } -ArgumentList $dc, $DaysBack,
        $fnWriteLog, $fnTestRpc, $fnRebootCheck,
        $fnGetQfe,   $fnGetWua,  $fnGetDcData

    $jobs.Add($job)
}

Write-Log "Waiting for $($jobs.Count) job(s) to finish …"
$jobs | Wait-Job | Out-Null

foreach ($job in $jobs) {
    $data = Receive-Job -Job $job -ErrorAction SilentlyContinue
    if ($data) { $allData.Add($data) }
    Remove-Job -Job $job -Force
}

#endregion

#region ── HTML Report ─────────────────────────────────────────────────────────

Write-Log "Assembling HTML report …"
Add-Type -AssemblyName System.Web

$reportDate   = Get-Date -Format 'dddd, dd MMMM yyyy HH:mm:ss'
$cutoffDate   = (Get-Date).AddDays(-$DaysBack).ToString('dd MMM yyyy')
$totalDCs     = $allData.Count
$successCount = @($allData | Where-Object { $_.Status -eq 'Success' }).Count
$warningCount = @($allData | Where-Object { $_.Status -eq 'Warning' }).Count
$errorCount   = @($allData | Where-Object { $_.Status -eq 'Error'   }).Count

# ── Per-DC collapsible card HTML ─────────────────────────────────────────────
$tableRows = foreach ($dc in ($allData | Sort-Object { $_.Status })) {

    $rowClass = switch ($dc.Status) {
        'Success' { 'row-success' }
        'Warning' { 'row-warning' }
        'Error'   { 'row-error'   }
        default   { 'row-unknown' }
    }

    $badge = switch ($dc.Status) {
        'Success' { '<span class="badge badge-success">&#10003; Healthy</span>' }
        'Warning' { '<span class="badge badge-warning">&#9888; Action Needed</span>' }
        'Error'   { '<span class="badge badge-error">&#10008; Unreachable</span>' }
        default   { '<span class="badge badge-unknown">? Unknown</span>' }
    }

    $rebootCell = if ($null -eq $dc.RebootRequired) {
        '<span class="reboot-unknown">&#8253; Reboot Status Unknown</span>'
    } elseif ($dc.RebootRequired) {
        '<span class="reboot-yes">&#9888; Restart Required</span>'
    } else {
        '<span class="reboot-no">&#10003; No Restart Needed</span>'
    }

    $srcCell  = "<span class='data-source' title='Data collection method'>&#128200; $([System.Web.HttpUtility]::HtmlEncode($dc.DataSource))</span>"
    $instList = @($dc.InstalledUpdates)
    $pendList = @($dc.PendingUpdates)

    # Installed updates inner table
    $instHtml = if ($instList.Count -eq 0) {
        "<p class='no-updates'>No updates found in the last $DaysBack days.</p>"
    } else {
        $rows = foreach ($u in ($instList | Sort-Object InstalledOn -Descending)) {
            $cls   = if ($u.IsFailure) { 'upd-fail' } elseif ($u.IsWarning) { 'upd-warn' } else { 'upd-ok' }
            $icon  = if ($u.IsFailure) { '&#10008;' } elseif ($u.IsWarning) { '&#9888;'  } else { '&#10003;' }
            $dtStr = if ($u.InstalledOn) { $u.InstalledOn.ToString('dd MMM yyyy HH:mm') } else { 'Unknown' }
            "<tr class='$cls'>
               <td>$icon</td>
               <td class='kb-cell'>$($u.KB)</td>
               <td class='title-cell'>$([System.Web.HttpUtility]::HtmlEncode($u.Title))</td>
               <td>$dtStr</td>
               <td>$($u.ResultText)</td>
             </tr>"
        }
        "<table class='inner-table'>
           <thead><tr><th></th><th>KB</th><th>Title</th><th>Installed On</th><th>Result</th></tr></thead>
           <tbody>$($rows -join '')</tbody>
         </table>"
    }

    # Pending updates inner table
    $pendHtml = if ($pendList.Count -eq 0) {
        "<p class='no-updates'>&#10003; No pending updates detected.</p>"
    } else {
        $rows = foreach ($p in $pendList) {
            "<tr class='upd-warn'>
               <td class='kb-cell'>$($p.KB)</td>
               <td class='title-cell'>$([System.Web.HttpUtility]::HtmlEncode($p.Title))</td>
               <td>$($p.Severity)</td>
               <td>$($p.Categories)</td>
             </tr>"
        }
        "<table class='inner-table'>
           <thead><tr><th>KB</th><th>Title</th><th>Severity</th><th>Category</th></tr></thead>
           <tbody>$($rows -join '')</tbody>
         </table>"
    }

    $errHtml      = if ($dc.ErrorMessage) {
        "<div class='error-box'>&#9888; $([System.Web.HttpUtility]::HtmlEncode($dc.ErrorMessage))</div>"
    } else { '' }

    $queryTimeStr = if ($dc.QueryTime) { $dc.QueryTime.ToString('HH:mm:ss') } else { 'N/A' }

    @"
    <div class="dc-card $rowClass">
      <div class="dc-header" onclick="toggleCard(this)">
        <div class="dc-title-group">
          <span class="dc-chevron">&#9660;</span>
          <span class="dc-name">$($dc.DCName)</span>
          $badge
        </div>
        <div class="dc-meta">
          <span class="meta-item">&#128196; Installed: <strong>$($instList.Count)</strong></span>
          <span class="meta-item">&#9203; Pending: <strong>$($pendList.Count)</strong></span>
          <span class="meta-item">$rebootCell</span>
          <span class="meta-item">$srcCell</span>
          <span class="meta-item time-item">Queried: $queryTimeStr</span>
        </div>
      </div>
      <div class="dc-body">
        $errHtml
        <div class="section-block">
          <h4 class="section-title">&#128196; Installed Updates — Last $DaysBack Days</h4>
          $instHtml
        </div>
        <div class="section-block">
          <h4 class="section-title">&#9203; Pending Updates — Awaiting Installation</h4>
          $pendHtml
        </div>
      </div>
    </div>
"@
}

# ── Full HTML page ────────────────────────────────────────────────────────────
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DC Windows Update Audit — $reportDate</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', 'Consolas', sans-serif;
      font-size: 13px; background: #0d1117; color: #c9d1d9; min-height: 100vh;
    }
    .banner {
      background: linear-gradient(135deg,#161b22,#1c2333);
      border-bottom: 2px solid #30363d;
      padding: 28px 40px 20px;
      display: flex; align-items: center; gap: 20px;
    }
    .banner-icon { font-size: 42px; line-height: 1; }
    .banner-title { flex: 1; }
    .banner-title h1 { font-size: 22px; font-weight: 700; color: #e6edf3; }
    .banner-title .subtitle { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .transport-badge {
      display: inline-block; margin-top: 8px;
      padding: 3px 12px; border-radius: 20px;
      background: #0d2b1e; border: 1px solid #238636;
      color: #3fb950; font-size: 11px; font-weight: 600; letter-spacing: 0.3px;
    }
    .banner-meta { text-align: right; font-size: 11px; color: #8b949e; line-height: 1.8; }
    .banner-meta strong { color: #58a6ff; }

    .summary-bar {
      display: flex; gap: 16px; padding: 20px 40px;
      background: #161b22; border-bottom: 1px solid #30363d; flex-wrap: wrap;
    }
    .summary-card {
      flex: 1; min-width: 140px; padding: 14px 18px;
      border-radius: 8px; border: 1px solid;
      display: flex; flex-direction: column; align-items: center;
    }
    .s-count { font-size: 32px; font-weight: 800; line-height: 1; }
    .s-label { font-size: 11px; margin-top: 5px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
    .card-total   { background:#1c2333; border-color:#30363d; color:#e6edf3; }
    .card-success { background:#0d2b1e; border-color:#238636; color:#3fb950; }
    .card-warning { background:#2b1d04; border-color:#9e6a03; color:#d29922; }
    .card-error   { background:#2b0e0e; border-color:#8b1a1a; color:#f85149; }

    .filter-bar {
      padding: 14px 40px; background: #0d1117;
      border-bottom: 1px solid #21262d;
      display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
    }
    .filter-bar label { font-size: 12px; color: #8b949e; }
    .filter-btn {
      padding: 5px 14px; border-radius: 20px; border: 1px solid #30363d;
      background: #161b22; color: #c9d1d9; cursor: pointer;
      font-size: 12px; font-family: inherit; transition: all 0.15s;
    }
    .filter-btn:hover { border-color: #58a6ff; color: #58a6ff; }
    .filter-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
    .search-box {
      margin-left: auto; padding: 5px 12px; border-radius: 6px;
      border: 1px solid #30363d; background: #161b22;
      color: #c9d1d9; font-size: 12px; font-family: inherit; width: 220px;
    }
    .search-box:focus { outline: none; border-color: #58a6ff; }

    .legend {
      display: flex; gap: 18px; padding: 10px 40px;
      background: #161b22; border-bottom: 1px solid #21262d;
      font-size: 11px; color: #8b949e; flex-wrap: wrap; align-items: center;
    }
    .legend-item { display: flex; align-items: center; gap: 6px; }
    .legend-dot  { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .dot-green   { background: #3fb950; }
    .dot-yellow  { background: #d29922; }
    .dot-red     { background: #f85149; }

    .content { padding: 24px 40px 40px; max-width: 1400px; margin: 0 auto; }

    .dc-card { border-radius: 10px; border: 1px solid; margin-bottom: 14px; overflow: hidden; transition: box-shadow 0.2s; }
    .dc-card:hover { box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
    .row-success { border-color: #238636; background: #0d1117; }
    .row-success .dc-header { background: linear-gradient(90deg,#0d2b1e,#0f1f15); }
    .row-warning { border-color: #9e6a03; background: #0d1117; }
    .row-warning .dc-header { background: linear-gradient(90deg,#2b1d04,#1a1408); }
    .row-error   { border-color: #8b1a1a; background: #0d1117; }
    .row-error   .dc-header { background: linear-gradient(90deg,#2b0e0e,#1a0a0a); }

    .dc-header {
      padding: 14px 18px; cursor: pointer;
      display: flex; justify-content: space-between; align-items: center;
      user-select: none; gap: 12px; flex-wrap: wrap;
    }
    .dc-header:hover { filter: brightness(1.12); }
    .dc-title-group { display: flex; align-items: center; gap: 10px; }
    .dc-chevron { font-size: 11px; color: #8b949e; transition: transform 0.25s; }
    .dc-chevron.open { transform: rotate(180deg); }
    .dc-name { font-size: 15px; font-weight: 700; color: #e6edf3; font-family: 'Consolas', monospace; }
    .dc-meta { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
    .meta-item { font-size: 12px; color: #8b949e; }
    .time-item { font-family: 'Consolas', monospace; font-size: 11px; }

    .badge {
      display: inline-flex; align-items: center; gap: 4px;
      padding: 3px 10px; border-radius: 20px;
      font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
    }
    .badge-success { background:#0d4429; color:#3fb950; border:1px solid #238636; }
    .badge-warning { background:#341a00; color:#d29922; border:1px solid #9e6a03; }
    .badge-error   { background:#3b0d0d; color:#f85149; border:1px solid #8b1a1a; }

    .reboot-yes     { color:#d29922; font-weight:600; font-size:12px; }
    .reboot-no      { color:#3fb950; font-size:12px; }
    .reboot-unknown { color:#8b949e; font-size:12px; font-style:italic; }
    .data-source    { color:#484f58; font-size:11px; font-style:italic; }

    .dc-body { padding: 0 18px 18px; display: none; border-top: 1px solid #21262d; }
    .dc-body.open { display: block; }

    .section-block { margin-top: 16px; }
    .section-title {
      font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
      color: #8b949e; font-weight: 600; margin-bottom: 10px;
      padding-bottom: 6px; border-bottom: 1px solid #21262d;
    }

    .inner-table { width:100%; border-collapse:collapse; font-size:12px; table-layout:fixed; }
    .inner-table th {
      text-align:left; padding:7px 10px; background:#161b22; color:#8b949e;
      font-weight:600; font-size:11px; border-bottom:1px solid #30363d;
      text-transform:uppercase; letter-spacing:0.5px;
    }
    .inner-table td {
      padding:7px 10px; border-bottom:1px solid #21262d;
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle;
    }
    .inner-table th:nth-child(1),.inner-table td:nth-child(1) { width:28px; text-align:center; }
    .inner-table th:nth-child(2),.inner-table td:nth-child(2) { width:92px; }
    .inner-table th:nth-child(4),.inner-table td:nth-child(4) { width:145px; }
    .inner-table th:nth-child(5),.inner-table td:nth-child(5) { width:158px; }
    .title-cell { color:#c9d1d9; }
    .inner-table tr:hover td { background:#161b22; }
    .upd-ok   td:first-child { color:#3fb950; font-size:14px; }
    .upd-warn td             { color:#d29922; }
    .upd-warn td:first-child { font-size:14px; }
    .upd-fail td             { color:#f85149; }
    .upd-fail td:first-child { font-size:14px; }
    .kb-cell { font-family:'Consolas',monospace; color:#58a6ff !important; font-weight:600; }

    .error-box {
      margin-top:14px; padding:10px 14px;
      background:#2b0e0e; border:1px solid #8b1a1a; border-radius:6px;
      color:#f85149; font-size:12px;
    }
    .no-updates { color:#8b949e; font-size:12px; font-style:italic; padding:6px 0; }

    .footer {
      text-align:center; padding:18px; font-size:11px; color:#484f58;
      border-top:1px solid #21262d;
    }

    ::-webkit-scrollbar { width:6px; height:6px; }
    ::-webkit-scrollbar-track { background:#0d1117; }
    ::-webkit-scrollbar-thumb { background:#30363d; border-radius:3px; }
  </style>
</head>
<body>

<div class="banner">
  <div class="banner-icon">&#127759;</div>
  <div class="banner-title">
    <h1>Active Directory Domain Controllers — Windows Update Audit</h1>
    <div class="subtitle">Domain: <strong>$Domain</strong> &nbsp;|&nbsp; Updates from <strong>$cutoffDate</strong> to today</div>
    <span class="transport-badge">&#128274; WinRM-Free &nbsp;&nbsp;&#124;&nbsp;&nbsp; WMI/DCOM (RPC 135) + Remote Registry (SMB 445)</span>
  </div>
  <div class="banner-meta">
    <div>Generated: <strong>$reportDate</strong></div>
    <div>Lookback: <strong>$DaysBack days</strong></div>
    <div>Host: <strong>$env:COMPUTERNAME</strong></div>
    <div>Run by: <strong>$env:USERDOMAIN\$env:USERNAME</strong></div>
  </div>
</div>

<div class="summary-bar">
  <div class="summary-card card-total">
    <span class="s-count">$totalDCs</span>
    <span class="s-label">Total DCs</span>
  </div>
  <div class="summary-card card-success">
    <span class="s-count">$successCount</span>
    <span class="s-label">&#10003; Healthy</span>
  </div>
  <div class="summary-card card-warning">
    <span class="s-count">$warningCount</span>
    <span class="s-label">&#9888; Action Needed</span>
  </div>
  <div class="summary-card card-error">
    <span class="s-count">$errorCount</span>
    <span class="s-label">&#10008; Unreachable</span>
  </div>
</div>

<div class="filter-bar">
  <label>Filter:</label>
  <button class="filter-btn active" onclick="filterCards('all',this)">All</button>
  <button class="filter-btn" onclick="filterCards('row-success',this)">&#10003; Healthy</button>
  <button class="filter-btn" onclick="filterCards('row-warning',this)">&#9888; Action Needed</button>
  <button class="filter-btn" onclick="filterCards('row-error',this)">&#10008; Unreachable</button>
  <button class="filter-btn" style="margin-left:8px;" onclick="expandAll()">Expand All</button>
  <button class="filter-btn" onclick="collapseAll()">Collapse All</button>
  <input type="text" class="search-box" placeholder="&#128269; Search DC name or KB …" oninput="searchCards(this.value)">
</div>

<div class="legend">
  <strong>LEGEND:</strong>
  <span class="legend-item"><span class="legend-dot dot-green"></span>All updates succeeded — no restart required</span>
  <span class="legend-item"><span class="legend-dot dot-yellow"></span>Restart pending | update failed | pending updates exist</span>
  <span class="legend-item"><span class="legend-dot dot-red"></span>DC unreachable (RPC port 135 blocked or host down)</span>
  &nbsp;|&nbsp; <em>WUA = rich data (result codes + pending); QFE = basic fallback</em>
</div>

<div class="content" id="dcContainer">
  $($tableRows -join "`n")
</div>

<div class="footer">
  <strong>Get-DCWindowsUpdateReport.ps1 v3.0</strong> &nbsp;|&nbsp;
  $reportDate &nbsp;|&nbsp; Domain: $Domain &nbsp;|&nbsp;
  $totalDCs DC(s) &nbsp;|&nbsp; Transport: WMI/DCOM (RPC 135) + Remote Registry (SMB 445) — no WinRM
</div>

<script>
  function toggleCard(h) {
    h.nextElementSibling.classList.toggle('open');
    h.querySelector('.dc-chevron').classList.toggle('open');
  }
  function expandAll() {
    document.querySelectorAll('.dc-body').forEach(b => b.classList.add('open'));
    document.querySelectorAll('.dc-chevron').forEach(c => c.classList.add('open'));
  }
  function collapseAll() {
    document.querySelectorAll('.dc-body').forEach(b => b.classList.remove('open'));
    document.querySelectorAll('.dc-chevron').forEach(c => c.classList.remove('open'));
  }
  function filterCards(cls, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.dc-card').forEach(c => {
      c.style.display = (cls === 'all' || c.classList.contains(cls)) ? '' : 'none';
    });
  }
  function searchCards(q) {
    q = q.toLowerCase().trim();
    document.querySelectorAll('.dc-card').forEach(c => {
      c.style.display = (!q || c.innerText.toLowerCase().includes(q)) ? '' : 'none';
    });
    if (q) document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  }
  // Auto-expand cards that need attention on page load
  document.querySelectorAll('.row-warning,.row-error').forEach(card => {
    const b = card.querySelector('.dc-body');
    const v = card.querySelector('.dc-chevron');
    if (b && v) { b.classList.add('open'); v.classList.add('open'); }
  });
</script>
</body>
</html>
"@

# ── Save the report ───────────────────────────────────────────────────────────
try {
    $html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Log "Report saved → $(Resolve-Path $ReportPath)"
} catch {
    Write-Log "Failed to write report: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

# ── Console summary ───────────────────────────────────────────────────────────
Write-Host ''
Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor DarkGray
Write-Host '  AUDIT COMPLETE  (v3.0 — WMI/DCOM + Remote Registry)' -ForegroundColor White
Write-Host "  Total DCs queried  : $totalDCs"     -ForegroundColor Cyan
Write-Host "  ✓  Healthy         : $successCount" -ForegroundColor Green
Write-Host "  ⚠  Action Needed  : $warningCount" -ForegroundColor Yellow
Write-Host "  ✗  Unreachable     : $errorCount"   -ForegroundColor Red
Write-Host "  Report             : $(Resolve-Path $ReportPath)" -ForegroundColor Cyan
Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor DarkGray
Write-Host ''

# Uncomment to auto-open the report in the default browser:
# Start-Process (Resolve-Path $ReportPath)

#endregion
