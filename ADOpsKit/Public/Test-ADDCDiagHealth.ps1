function Test-ADDCDiagHealth {
<#
.SYNOPSIS
    Runs the full dcdiag test suite against every domain controller and
    emails an alert only when a DC goes down or a test starts/stops failing.

.DESCRIPTION
    Designed to be run on a short repeating schedule (see
    Register-ADDCDiagHealthMonitor) so it behaves like a real-time
    monitoring agent for Active Directory domain controllers.

    For each domain controller:
        1. Checks basic reachability (ping + RPC endpoint mapper port 135)
           before running dcdiag, so an offline DC is reported immediately
           as 'Unreachable' instead of making dcdiag hang.
        2. Runs 'dcdiag.exe /s:<DC>' (the standard dcdiag test set) with a
           per-DC timeout, and parses every 'Starting test:' / 'passed
           test' / 'failed test' pair generically - not a fixed subset.
        3. Compares the result to the last known state, persisted as JSON
           in -StateFilePath.

    An alert is only raised when:
        - A DC's status changes (Healthy -> Failing/Unreachable, or
          Failing/Unreachable -> Healthy = recovery), or
        - A DC has been Failing/Unreachable for more than
          -RepeatAlertAfterHours since the last alert (a reminder, so a
          persistent outage does not go silent between the first and last
          run).

    This keeps alert volume low: a healthy forest produces no email at
    all, run after run.

    This function is READ-ONLY against Active Directory itself. Its only
    side effects are: writing the state file, appending to the alert log,
    and (optionally) sending an email. WinRM is NOT used or required -
    dcdiag talks to each DC directly over RPC/LDAP, and reachability is
    checked with ICMP ping and a raw TCP connect to port 135.

    LOAD NOTE: dcdiag itself is lightweight (a handful of LDAP binds, RPC
    calls, and event-log reads per DC, a few seconds each), so polling
    every few minutes is negligible against normal DC traffic. The one
    thing to avoid is registering the recurring task (via
    Register-ADDCDiagHealthMonitor) ON a domain controller itself - that
    DC would then carry the polling workload continuously in addition to
    its DC duties. Run this from a non-DC host (member server, jump box,
    or monitoring VM) that queries the DCs remotely instead.

.PARAMETER DomainController
    Explicit list of DC host names to check. Defaults to every domain
    controller in the current domain (Get-ADDomainController -Filter *).

.PARAMETER Tests
    Optional list of specific dcdiag test names to run (passed as
    /test:<name> per entry), instead of dcdiag's full default test set.
    Narrowing this reduces load per run - a lighter, still-meaningful set
    is: Connectivity, Advertising, NetLogons, Replications, KccEvent,
    Services. Leave unset to run the full default set (unchanged
    behavior).

.PARAMETER PerDCTimeoutSeconds
    Maximum time to wait for dcdiag to finish against a single DC before
    it is killed and treated as Unreachable. Default 60.

.PARAMETER RepeatAlertAfterHours
    How long a DC may stay in the same Failing/Unreachable state before a
    reminder alert is sent again. Default 4.

.PARAMETER StateFilePath
    Where per-DC last-known-status is persisted between runs so alerts
    are only sent on a change. Defaults to
    C:\ADOpsKit\State\Test-ADDCDiagHealth.state.json

.PARAMETER AlertLogPath
    CSV file that every sent alert is appended to, for a durable history
    independent of the mailbox. Defaults to
    C:\ADOpsKit\Reports\Test-ADDCDiagHealth\AlertLog.csv

.PARAMETER SmtpServer
    SMTP relay to send alert email through. If omitted, alerts are only
    written to the console (Write-Warning) and the alert log CSV - no
    email is sent.

.PARAMETER SmtpPort
    SMTP port. Default 25.

.PARAMETER UseSsl
    Use SSL/TLS when connecting to SmtpServer.

.PARAMETER SmtpCredential
    Optional credential for SMTP authentication. Most internal relays do
    not require this.

.PARAMETER From
    Alert email From address. Required when -SmtpServer is supplied.

.PARAMETER To
    Alert email recipient address(es). Required when -SmtpServer is
    supplied.

.EXAMPLE
    Test-ADDCDiagHealth
    Checks all DCs, updates state, and only writes console warnings for
    anything that changed (no email configured).

.EXAMPLE
    Test-ADDCDiagHealth -SmtpServer smtp.contoso.com -From adalerts@contoso.com -To 'you@contoso.com'
    Checks all DCs and emails an alert on any status change or
    persistent-failure reminder.

.EXAMPLE
    Test-ADDCDiagHealth -DomainController DC01,DC02 -PerDCTimeoutSeconds 30 -WhatIf
    Shows what would happen (including whether an alert email would be
    sent) without actually sending it.

.EXAMPLE
    Test-ADDCDiagHealth -Tests Connectivity,Advertising,NetLogons,Replications,KccEvent,Services
    Runs a lighter, targeted test list instead of dcdiag's full default
    set, reducing per-run load while still covering the tests most
    likely to catch a DC outage or replication break.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Read-only against AD. Makes changes only to its own state/log files
    and, optionally, sends email - wrapped in SupportsShouldProcess.
    WinRM: not used, not required.
    Data sources: dcdiag.exe (RPC/LDAP), ICMP ping, raw TCP connect to
    port 135, ActiveDirectory module (Get-ADDomainController) unless
    -DomainController is supplied.
    Run under an account with normal domain-authenticated read access;
    no special rights are required for the default dcdiag test set.
    For real-time alerting, register this to run every few minutes with
    Register-ADDCDiagHealthMonitor rather than a daily/weekly task.
#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$DomainController,

        [string[]]$Tests,

        [ValidateRange(5, 600)]
        [int]$PerDCTimeoutSeconds = 60,

        [ValidateRange(1, 24)]
        [int]$RepeatAlertAfterHours = 4,

        [string]$StateFilePath = 'C:\ADOpsKit\State\Test-ADDCDiagHealth.state.json',

        [string]$AlertLogPath = 'C:\ADOpsKit\Reports\Test-ADDCDiagHealth\AlertLog.csv',

        [string]$SmtpServer,

        [ValidateRange(1, 65535)]
        [int]$SmtpPort = 25,

        [switch]$UseSsl,

        [pscredential]$SmtpCredential,

        [ValidateNotNullOrEmpty()]
        [string]$From,

        [ValidateNotNullOrEmpty()]
        [string[]]$To
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($SmtpServer -and (-not $From -or -not $To)) {
        throw "Both -From and -To are required when -SmtpServer is supplied."
    }

    # Load before first use - HtmlEncode is used while building alert HTML further below.
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # ============ HELPERS (local to this function) ============

    function Invoke-ADOKDcDiagRaw {
        param(
            [Parameter(Mandatory = $true)] [string]$ComputerName,
            [Parameter(Mandatory = $true)] [int]$TimeoutSeconds,
            [string[]]$TestNames
        )
        $argList = [System.Collections.Generic.List[string]]::new()
        $argList.Add("/s:$ComputerName")
        foreach ($testName in $TestNames) { $argList.Add("/test:$testName") }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = 'dcdiag.exe'
        $psi.Arguments              = ($argList -join ' ')
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        $proc = $null
        try {
            $proc = [System.Diagnostics.Process]::Start($psi)
            $stdOutTask = $proc.StandardOutput.ReadToEndAsync()
            $exited     = $proc.WaitForExit($TimeoutSeconds * 1000)

            if (-not $exited) {
                try { $proc.Kill() } catch { Write-Verbose "Kill() on timed-out dcdiag against '$ComputerName' failed (process likely already exited): $($_.Exception.Message)" }
                return [pscustomobject]@{ Completed = $false; Lines = @() }
            }

            $output = $stdOutTask.GetAwaiter().GetResult()
            return [pscustomobject]@{ Completed = $true; Lines = ($output -split '[\r\n]') }
        }
        catch {
            return [pscustomobject]@{ Completed = $false; Lines = @() }
        }
        finally {
            if ($proc) { $proc.Dispose() }
        }
    }

    function ConvertFrom-ADOKDcDiagOutput {
        param([string[]]$Lines)
        $tests       = [ordered]@{}
        $currentTest = $null
        foreach ($line in $Lines) {
            if ($line -match 'Starting test:\s*(.+?)\s*$') {
                $currentTest = $Matches[1].Trim()
            }
            elseif ($currentTest -and $line -match 'passed test|failed test') {
                $tests[$currentTest] = if ($line -match 'passed test') { 'Passed' } else { 'Failed' }
                $currentTest = $null
            }
        }
        return $tests
    }

    function Get-ADOKStatusCellHtml {
        param([string]$Status)
        $color = switch ($Status) {
            'Healthy'     { '#1e7e34' }
            'Recovered'   { '#1e7e34' }
            'Failing'     { '#c0392b' }
            'Unreachable' { '#c0392b' }
            default       { '#6c757d' }
        }
        "<td style='color:$color;font-weight:600;'>$Status</td>"
    }

    # ============ RESOLVE TARGET DCs ============

    $targets = @(
        if ($DomainController) {
            $DomainController
        } else {
            (Get-ADDomainController -Filter * | Sort-Object HostName).HostName
        }
    )

    if ($targets.Count -eq 0) {
        Write-Warning "No domain controllers to check."
        return
    }

    # ============ LOAD PREVIOUS STATE ============

    $stateDir = Split-Path -Path $StateFilePath -Parent
    if ($stateDir -and -not (Test-Path -LiteralPath $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }

    $previousState = @{}
    if (Test-Path -LiteralPath $StateFilePath) {
        try {
            $raw = Get-Content -LiteralPath $StateFilePath -Raw | ConvertFrom-Json
            foreach ($prop in $raw.PSObject.Properties) {
                $previousState[$prop.Name] = $prop.Value
            }
        }
        catch {
            Write-Warning "Could not parse existing state file '$StateFilePath' - starting fresh. $($_.Exception.Message)"
        }
    }

    # ============ CHECK EACH DC ============

    $nowUtc     = [DateTime]::UtcNow
    $newState   = @{}
    $results    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $alertItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($dc in $targets) {
      try {

        $status       = 'Healthy'
        $failingTests = @()

        # A single dropped ping/TCP attempt on an otherwise-healthy DC would
        # otherwise flip status to Unreachable and fire an alert immediately,
        # then another when it flips back - an alert storm on any flaky link.
        # Retry once before concluding the DC is actually unreachable.
        $reachable = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($reachable) {
            $reachable = Test-ADOKTcpPort -ComputerName $dc -Port 135 -TimeoutSeconds 5
        }
        if (-not $reachable) {
            Start-Sleep -Seconds 2
            $reachable = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($reachable) {
                $reachable = Test-ADOKTcpPort -ComputerName $dc -Port 135 -TimeoutSeconds 5
            }
        }

        if (-not $reachable) {
            $status       = 'Unreachable'
            $failingTests = @('Unreachable (ping/RPC port 135 failed)')
        }
        else {
            $diag = Invoke-ADOKDcDiagRaw -ComputerName $dc -TimeoutSeconds $PerDCTimeoutSeconds -TestNames $Tests
            if (-not $diag.Completed) {
                $status       = 'Unreachable'
                $failingTests = @("dcdiag did not complete within $PerDCTimeoutSeconds seconds")
            }
            else {
                $testResults  = ConvertFrom-ADOKDcDiagOutput -Lines $diag.Lines
                $failingTests = @($testResults.GetEnumerator() | Where-Object { $_.Value -eq 'Failed' } | ForEach-Object { $_.Key })
                $status       = if ($failingTests.Count -gt 0) { 'Failing' } else { 'Healthy' }
            }
        }

        $prev         = $previousState[$dc]
        $prevStatus   = if ($prev) { [string]$prev.LastStatus } else { $null }
        $lastChangeUtc = if ($prev -and $prev.LastChangeUtc) { $prev.LastChangeUtc } else { $nowUtc.ToString('o') }
        $lastAlertUtc  = if ($prev -and $prev.LastAlertUtc)  { $prev.LastAlertUtc }  else { $null }

        $isTransition = $false
        $isReminder   = $false

        if ($prev) {
            if ($prevStatus -ne $status) {
                $isTransition = $true
            }
            elseif ($status -ne 'Healthy' -and $lastAlertUtc) {
                $parsedAlertUtc = [DateTime]::MinValue
                if ([DateTime]::TryParse($lastAlertUtc, [ref]$parsedAlertUtc)) {
                    $hoursSinceAlert = ($nowUtc - $parsedAlertUtc.ToUniversalTime()).TotalHours
                    if ($hoursSinceAlert -ge $RepeatAlertAfterHours) { $isReminder = $true }
                }
                else {
                    Write-Warning "Could not parse LastAlertUtc value '$lastAlertUtc' for DC '$dc' - treating as no prior alert."
                }
            }
        }
        elseif ($status -ne 'Healthy') {
            # first-ever run and already unhealthy - alert immediately
            $isTransition = $true
        }

        if ($isTransition) {
            $lastChangeUtc = $nowUtc.ToString('o')
        }

        if ($isTransition -or $isReminder) {
            $alertItems.Add([PSCustomObject]@{
                DomainController = $dc
                PreviousStatus   = if ($prevStatus) { $prevStatus } else { 'Unknown' }
                CurrentStatus    = $status
                FailingTests     = $failingTests
                IsRecovery       = ($isTransition -and $status -eq 'Healthy' -and $prevStatus -and $prevStatus -ne 'Healthy')
                IsReminder       = $isReminder
            })
            $lastAlertUtc = $nowUtc.ToString('o')
        }

        $newState[$dc] = @{
            LastStatus    = $status
            FailingTests  = $failingTests
            LastChangeUtc = $lastChangeUtc
            LastAlertUtc  = $lastAlertUtc
        }

        $results.Add([PSCustomObject]@{
            DomainController = $dc
            Status            = $status
            PreviousStatus    = if ($prevStatus) { $prevStatus } else { 'Unknown' }
            FailingTests      = $failingTests
            Alerted           = ($isTransition -or $isReminder)
            TimestampUtc      = $nowUtc
        })
      }
      catch {
        Write-Warning "Health check failed for DC '$dc': $($_.Exception.Message)"
        $newState[$dc] = @{
            LastStatus    = 'Unknown'
            FailingTests  = @("Health check threw an exception: $($_.Exception.Message)")
            LastChangeUtc = $nowUtc.ToString('o')
            LastAlertUtc  = $null
        }
        $results.Add([PSCustomObject]@{
            DomainController = $dc
            Status            = 'Unknown'
            PreviousStatus    = 'Unknown'
            FailingTests      = @("Health check threw an exception: $($_.Exception.Message)")
            Alerted           = $false
            TimestampUtc      = $nowUtc
        })
      }
    }

    # ============ PERSIST STATE ============

    # Write to a temp file and rename into place - a rename on the same volume
    # is atomic, so a process killed mid-write cannot leave a truncated/corrupt
    # state file behind for the next run to trip over.
    $stateTempPath = "$StateFilePath.tmp"
    ($newState | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $stateTempPath -Encoding UTF8
    Move-Item -LiteralPath $stateTempPath -Destination $StateFilePath -Force

    # ============ ALERT ============

    if ($alertItems.Count -gt 0) {

        $domainName = try { (Get-ADDomain).DNSRoot } catch { $env:USERDNSDOMAIN }

        $newFailures = @($alertItems | Where-Object { -not $_.IsReminder -and -not $_.IsRecovery })
        $recoveries  = @($alertItems | Where-Object { $_.IsRecovery })
        $reminders   = @($alertItems | Where-Object { $_.IsReminder })

        $severity = if ($newFailures.Count -gt 0) { 'ALERT' }
                    elseif ($reminders.Count -gt 0) { 'WARNING' }
                    else { 'OK' }

        $summaryParts = @()
        if ($newFailures.Count -gt 0) { $summaryParts += "$($newFailures.Count) DC(s) newly unhealthy" }
        if ($reminders.Count -gt 0)   { $summaryParts += "$($reminders.Count) DC(s) still unhealthy" }
        if ($recoveries.Count -gt 0)  { $summaryParts += "$($recoveries.Count) DC(s) recovered" }
        $resultSummary = $summaryParts -join ', '

        $dateStamp = Get-Date -Format 'M/d/yyyy'
        $subject   = "$severity`: Domain Controller DCDiag Health Check Report v1.0 - Domain: $domainName - $resultSummary - $dateStamp"

        $rowsHtml = foreach ($item in $alertItems) {
            $displayStatus = if ($item.IsRecovery) { 'Recovered' } else { $item.CurrentStatus }
            $testsText = if ($item.FailingTests.Count -gt 0) { ($item.FailingTests -join ', ') } else { '-' }
            "<tr>
                <td>$([System.Web.HttpUtility]::HtmlEncode($item.DomainController))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($item.PreviousStatus))</td>
                $(Get-ADOKStatusCellHtml -Status $displayStatus)
                <td>$([System.Web.HttpUtility]::HtmlEncode($testsText))</td>
                <td>$(if ($item.IsReminder) { 'Reminder - still unhealthy' } else { 'Status changed' })</td>
            </tr>"
        }

        $bodyHtml = @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;">
<div style="background-color:#27425D;padding:16px 24px;">
    <span style="color:#ffffff;font-size:18px;font-weight:600;">Domain Controller DCDiag Health Check Report v1.0</span><br/>
    <span style="color:#c9d4de;font-size:12px;">$dateStamp - Domain: $domainName</span>
</div>
<table style="border-collapse:collapse;margin-top:12px;width:100%;">
<tr style="background-color:#f0f0f0;">
    <th style="text-align:left;padding:6px 10px;border:1px solid #ddd;">Domain Controller</th>
    <th style="text-align:left;padding:6px 10px;border:1px solid #ddd;">Previous Status</th>
    <th style="text-align:left;padding:6px 10px;border:1px solid #ddd;">Current Status</th>
    <th style="text-align:left;padding:6px 10px;border:1px solid #ddd;">Failing Tests</th>
    <th style="text-align:left;padding:6px 10px;border:1px solid #ddd;">Reason</th>
</tr>
$($rowsHtml -join "`n")
</table>
</body></html>
"@

        foreach ($item in $alertItems) {
            $line = "[$severity] $($item.DomainController): $($item.PreviousStatus) -> $($item.CurrentStatus)$(if ($item.FailingTests.Count -gt 0) { ' (' + ($item.FailingTests -join '; ') + ')' })"
            Write-Warning $line
        }

        $logDir = Split-Path -Path $AlertLogPath -Parent
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $alertItems | ForEach-Object {
            [PSCustomObject]@{
                TimestampUtc      = $nowUtc.ToString('o')
                Severity          = $severity
                DomainController  = $_.DomainController
                PreviousStatus    = $_.PreviousStatus
                CurrentStatus     = $_.CurrentStatus
                FailingTests      = ($_.FailingTests -join '; ')
                IsRecovery        = $_.IsRecovery
                IsReminder        = $_.IsReminder
            }
        } | Export-Csv -LiteralPath $AlertLogPath -NoTypeInformation -Append

        if ($SmtpServer) {
            if ($PSCmdlet.ShouldProcess(($To -join ', '), "Send DC health alert email ($severity)")) {
                try {
                    $mailParams = @{
                        SmtpServer = $SmtpServer
                        Port       = $SmtpPort
                        From       = $From
                        To         = $To
                        Subject    = $subject
                        Body       = $bodyHtml
                        BodyAsHtml = $true
                        UseSsl     = $UseSsl.IsPresent
                    }
                    if ($SmtpCredential) { $mailParams['Credential'] = $SmtpCredential }
                    Send-MailMessage @mailParams
                }
                catch {
                    Write-Warning "Failed to send DC health alert email: $($_.Exception.Message). Alert was still logged to '$AlertLogPath'."
                }
            }
        }
        else {
            Write-Warning "No -SmtpServer configured - alert was logged to '$AlertLogPath' and the console only."
        }
    }

    return $results
}
