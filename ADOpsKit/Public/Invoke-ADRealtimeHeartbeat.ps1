function Invoke-ADRealtimeHeartbeat {
    <#
    .SYNOPSIS
        Performs central real-time heartbeat monitoring for Active Directory domain
        controllers and sends alert notifications to email and Slack.

    .DESCRIPTION
        Discovers domain controllers from Active Directory or accepts an explicit
        target list, then performs a lightweight heartbeat check from the machine
        running this script.

        The heartbeat check is intentionally narrower than a full `dcdiag /c`
        diagnostic sweep. It is designed for frequent scheduling, such as every
        30 to 60 seconds, without placing a heavy custom workload on each domain
        controller.

        The heartbeat check validates:
        - Core TCP reachability, such as LDAP, Kerberos, RPC endpoint mapper,
          SMB, and DNS
        - `SYSVOL` share reachability unless `-SkipSysvolCheck` is used
        - `NETLOGON` share reachability unless `-SkipNetlogonCheck` is used
        - Required AD-related Windows service state through WMI/DCOM unless
          `-SkipServiceChecks` is used

        The SYSVOL/NETLOGON share checks and the WMI/DCOM service checks are each
        bounded by `-DeepCheckTimeoutMs` and are skipped entirely (not attempted)
        when the TCP port they depend on (445 for shares, 135 for services)
        already failed, so an unreachable domain controller cannot stall a run
        with a second, redundant SMB or WMI timeout on top of the TCP one.

        This script is intended to be the real-time monitoring layer only.
        Heavier `dcdiag.exe` and `repadmin.exe` verification should be scheduled
        separately on a slower interval.

        Discovery uses ActiveDirectory PowerShell module cmdlets when an explicit
        `-ComputerName` list is not supplied. Domain controller discovery queries
        each target domain through that domain's PDC Emulator.

        The script is read-only with respect to Active Directory and remote domain
        controllers. It does not modify AD objects, services, registry values,
        SYSVOL, DNS, replication, firewall settings, or remote computer
        configuration.

        The script creates HTML and JSON heartbeat snapshots under the configured
        output folder and keeps an alert state file used to suppress duplicate
        notifications and send recovery messages.

        Alert behavior:
        - Reports are always written.
        - Failed heartbeat conditions generate alerts by default.
        - Warning-only conditions generate alerts only when `-AlertOnWarning` is
          used.
        - Recovery notifications are sent when an alerting condition clears.
        - Email is sent only when `-SendEmail` is specified.
        - Slack is sent only when `-SendSlack` is specified.
        - If the script itself fails unexpectedly (for example, AD discovery
          breaks or the output folder becomes unwritable), it makes a
          best-effort attempt to send an ALERT notification about the monitor
          failure through the same configured email/Slack channels, then exits
          with code `1`. A normal run - regardless of how many individual DCs
          are Failed or Warn, which is expected monitor output, not a script
          failure - exits with code `0`. This is meant to be visible as Last Run
          Result when scheduled as a Windows Scheduled Task.

        The whole script supports `-WhatIf` / `-Confirm`. Discovery and the
        heartbeat checks themselves still run for real - the console pipeline
        output reflects real per-DC results - but every action that touches
        something outside the process is previewed instead of performed: no
        report or state file is written (not even the output folder is
        created), no history file is deleted, and no email or Slack message is
        sent. This falls out of `Set-Content`/`New-Item`/`Remove-Item` all being
        `ShouldProcess`-aware cmdlets that automatically honor the inherited
        `-WhatIf`, on top of the explicit `ShouldProcess` gating added around
        the email/Slack sends.

        Output files created:
        - `latest.html`
        - `latest.json`
        - `history\ADRealtimeHeartbeat_v1.1_<ScopeValue>_<Timestamp>.html`
        - `history\ADRealtimeHeartbeat_v1.1_<ScopeValue>_<Timestamp>.json`
        - `ADRealtimeHeartbeat-State.json`

        Default output folder:
        - `C:\ADOpsKit\Reports\Invoke-ADRealtimeHeartbeat`

        HTML/email styling standard:
        - Dark navy banner comparable to `#27425D`
        - Light neutral panels and summary tiles
        - Green for healthy state, amber for warning state, red for failed state,
          and blue-gray for unknown state

        Email subject pattern:
        - `ALERT: AD Real-Time Monitor - DC: <DCName> - <IssueSummary> - <M/d/yyyy>`
        - `WARNING: AD Real-Time Monitor - DC: <DCName> - <IssueSummary> - <M/d/yyyy>`
        - `OK: AD Real-Time Monitor - DC: <DCName> - Alert condition cleared - <M/d/yyyy>`

        Slack message pattern:
        - Severity line, DC name, domain, issue summary, first seen time, last
          seen time, and run source

    .PARAMETER VersionInfo
        Returns script version metadata and exits without running discovery or
        heartbeat checks.

    .PARAMETER ForestName
        Optional target forest DNS name. If omitted and `-ComputerName` is not
        supplied, the current forest is used.

    .PARAMETER DomainName
        Optional AD DNS domain names to query for domain controller discovery. If
        omitted and `-ComputerName` is not supplied, all domains in the selected
        forest are used.

    .PARAMETER ComputerName
        Optional explicit list of domain controllers to test. When provided, the
        script skips AD discovery and uses these targets directly.

    .PARAMETER ScopeValue
        Optional scope text used in report filenames and report metadata. If
        omitted, the script derives a scope value from the explicit target mode,
        selected domain list, selected forest, or current forest mode.

    .PARAMETER OutputFolder
        Folder where HTML, JSON, history, and alert state files are written.
        Defaults to `C:\ADOpsKit\Reports\Invoke-ADRealtimeHeartbeat`.

    .PARAMETER ReportRetentionDays
        Deletes dated HTML and JSON history files older than this many days from
        the history folder.
        Defaults to `30`.

    .PARAMETER TcpTimeoutMs
        Timeout in milliseconds for each TCP connection attempt.
        Defaults to `3000`.

    .PARAMETER TcpPort
        TCP ports to test against each domain controller.
        Defaults to `53`, `88`, `135`, `389`, and `445`.

    .PARAMETER DeepCheckTimeoutMs
        Timeout in milliseconds enforced on each SYSVOL/NETLOGON share check and
        each WMI/DCOM service-state collection call. These checks are skipped
        entirely (not attempted) when the corresponding baseline TCP port already
        failed, so this timeout only bounds the case where TCP succeeded but the
        deeper SMB or WMI/DCOM call itself stalls.
        Defaults to `5000`.

    .PARAMETER RequiredService
        Windows services expected to be present and running on each domain
        controller when `-SkipServiceChecks` is not used.
        Defaults to `NTDS`, `Netlogon`, `KDC`, `DNS`, `DFSR`, and `W32Time`.

    .PARAMETER SkipSysvolCheck
        Skips `SYSVOL` share reachability testing.

    .PARAMETER SkipNetlogonCheck
        Skips `NETLOGON` share reachability testing.

    .PARAMETER SkipServiceChecks
        Skips WMI/DCOM service-state collection.

    .PARAMETER SuppressRepeatMinutes
        Number of minutes to suppress duplicate alerts when the same DC continues
        to fail with the same issue signature.
        Defaults to `15`.

    .PARAMETER AlertOnWarning
        Sends email and Slack notifications for warning-only conditions. Without
        this switch, warning-only results appear in the report but do not notify.

    .PARAMETER SendEmail
        Allows SMTP email alert delivery.

    .PARAMETER To
        Recipient address or addresses used when alert email is sent.

    .PARAMETER From
        Sender address used when alert email is sent.

    .PARAMETER SmtpServer
        SMTP server used when alert email is sent.

    .PARAMETER SmtpPort
        SMTP port used when alert email is sent.
        Defaults to `25`.

    .PARAMETER SendSlack
        Allows Slack alert delivery through an incoming webhook.

    .PARAMETER SlackWebhookUrl
        Slack incoming webhook URL used when `-SendSlack` is specified.
        If omitted, the script checks the `AD_MONITOR_SLACK_WEBHOOK_URL`
        environment variable.

    .EXAMPLE
        Invoke-ADRealtimeHeartbeat -SendEmail -To 'adops@example.com' -From 'ad-monitor@example.com' -SmtpServer 'smtp.example.com'

        Discovers all domain controllers in the current forest, performs the
        heartbeat checks, writes report output to the default folder, and sends
        email only for failed conditions.

    .EXAMPLE
        Invoke-ADRealtimeHeartbeat -ComputerName 'DC01.corp.contoso.com','DC02.corp.contoso.com' -SendSlack -SlackWebhookUrl 'https://hooks.slack.com/services/...'

        Tests two explicit domain controllers and sends Slack alerts for failed
        conditions.

    .EXAMPLE
        Invoke-ADRealtimeHeartbeat -DomainName 'corp.contoso.com' -AlertOnWarning -SendEmail -To 'adops@example.com' -From 'ad-monitor@example.com' -SmtpServer 'smtp.example.com'

        Tests all domain controllers in one domain and sends alert messages for
        both warning and failed conditions.

    .EXAMPLE
        Invoke-ADRealtimeHeartbeat -SendEmail -To 'adops@example.com' -From 'ad-monitor@example.com' -SmtpServer 'smtp.example.com' -WhatIf

        Runs real discovery and heartbeat checks and previews what would happen
        - alert email(s), history-file deletions - without writing any report,
        state, or history file, and without sending anything.

    .NOTES
        Author:   K Shankar R Karanth
        Website:  https://karanth.ovh
        Version:  1.1

        Version 1.1 changes:
        - Fixed a crash on every run without -SlackWebhookUrl configured:
          Assert-Configuration and Send-SlackAlertMessage both declared their
          webhook URL parameter as Mandatory [string] with no default, and
          Windows PowerShell 5.1 rejects an explicit $null for that combination.
          Since Slack is opt-in, the resolved URL is $null whenever -SendSlack is
          not used - the default case - so the script threw before running any
          checks. The Send-SlackAlertMessage instance was worse: it only threw
          when there was an actual alert to send, aborting the run before
          Save-AlertState could persist the alert state for that run.
        - Fixed a matching crash in Get-IssueSummary / Get-IssueSignature: both
          declared a Mandatory [object[]] parameter with no
          AllowEmptyCollection, and both were called with an empty array
          whenever a DC had zero issues - i.e. whenever a DC was fully healthy,
          the single most common case. Found by running the script, not by
          reading it.
        - Added -DeepCheckTimeoutMs and an enforced timeout around the SYSVOL/
          NETLOGON share checks and the WMI/DCOM service checks (previously
          unbounded, unlike the TCP checks), plus a short-circuit that skips
          those checks entirely when the underlying TCP port already failed.
        - Added SupportsShouldProcess to the script and to every function with a
          real external side effect (email, Slack, history-file deletion), so
          -WhatIf gives a true dry run.
        - Wrapped the main body in try/catch: an unhandled failure now makes a
          best-effort attempt to send an ALERT notification about the monitor
          itself through the configured channels, then exits 1. A normal run
          exits 0 regardless of individual DC status. Previously an unhandled
          failure just crashed with no notification of the crash itself.
        - Renamed Ensure-Folder -> Initialize-ADRHFolder and Load-AlertState ->
          Import-AlertState (unapproved PowerShell verbs).

        Requires:
        - Windows PowerShell 5.1
        - ActiveDirectory PowerShell module when `-ComputerName` is not supplied
        - WMI/DCOM access and permissions for remote service checks
        - SMB access to `SYSVOL` and `NETLOGON` when share checks are enabled
        - SMTP access when email alerts are enabled
        - HTTPS access to the Slack webhook when Slack alerts are enabled

        WinRM:
        - Assumed blocked by default
        - Not required
        - Not used
        - No PowerShell remoting session is used

        Collection methods:
        - ActiveDirectory module cmdlets for discovery
        - Direct TCP socket checks from the monitoring host
        - WMI/DCOM through `Get-WmiObject` for service-state checks
        - SMB path checks for `SYSVOL` and `NETLOGON`

        Safety:
        - Read-only for Active Directory and remote domain controllers
        - Does not run `dcdiag.exe` or `repadmin.exe`
        - Does not change AD or remote systems
        - Updates `latest.html`, `latest.json`, and `ADRealtimeHeartbeat-State.json`
          in the configured output folder
        - Deletes only dated `ADRealtimeHeartbeat_v1.1_*.html` and
          `ADRealtimeHeartbeat_v1.1_*.json` files older than the configured
          retention period from the configured history folder
        - Every email send, Slack post, and history-file deletion is wrapped in
          `ShouldProcess`; run with `-WhatIf` for a dry run
        - Exit code `0` on a normal run (regardless of individual DC status);
          exit code `1` only if the monitor script itself fails unexpectedly
    #>

    #requires -Version 5.1

    # PSReviewUnusedParameter false-positives on every parameter below:
    # they are read inside nested helper functions (Resolve-ScopeValue,
    # Assert-Configuration, Get-TargetDomainControllers, etc.) via
    # PowerShell's normal scope capture rather than being passed as
    # explicit arguments, which the analyzer's static check does not trace.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Alias('VER')]
        [switch]$VersionInfo,

        [string]$ForestName,

        [string[]]$DomainName,

        [AllowEmptyCollection()]
        [string[]]$ComputerName,

        [string]$ScopeValue,

        [ValidateNotNullOrEmpty()]
        [string]$OutputFolder = 'C:\ADOpsKit\Reports\Invoke-ADRealtimeHeartbeat',

        [ValidateRange(1, 3650)]
        [int]$ReportRetentionDays = 30,

        [ValidateRange(250, 60000)]
        [int]$TcpTimeoutMs = 3000,

        [ValidateNotNullOrEmpty()]
        [int[]]$TcpPort = @(53, 88, 135, 389, 445),

        [ValidateRange(500, 60000)]
        [int]$DeepCheckTimeoutMs = 5000,

        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredService = @('NTDS', 'Netlogon', 'KDC', 'DNS', 'DFSR', 'W32Time'),

        [switch]$SkipSysvolCheck,

        [switch]$SkipNetlogonCheck,

        [switch]$SkipServiceChecks,

        [ValidateRange(1, 1440)]
        [int]$SuppressRepeatMinutes = 15,

        [switch]$AlertOnWarning,

        [switch]$SendEmail,

        [string[]]$To,

        [string]$From,

        [string]$SmtpServer,

        [ValidateRange(1, 65535)]
        [int]$SmtpPort = 25,

        [switch]$SendSlack,

        [string]$SlackWebhookUrl
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $script:ScriptVersion = '1.1'
    $script:ScriptName = 'Invoke-ADRealtimeHeartbeat'
    $script:ReportBaseName = 'ADRealtimeHeartbeat'
    $script:ShortMonitorName = 'AD Real-Time Monitor'
    $script:HistoryFolderName = 'history'
    $script:InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $script:RunUtc = (Get-Date).ToUniversalTime()
    $script:RunLocal = Get-Date
    $script:RunUser = "$($env:USERDOMAIN)\$($env:USERNAME)".Trim('\')
    $script:RunComputer = $env:COMPUTERNAME

    function Get-VersionMetadata {
        [CmdletBinding()]
        param()

        [pscustomobject]@{
            ScriptName    = $script:ScriptName
            Version       = $script:ScriptVersion
            PowerShell    = $PSVersionTable.PSVersion.ToString()
            RunComputer   = $script:RunComputer
            RunUser       = $script:RunUser
            GeneratedTime = (Get-Date)
        }
    }

    function ConvertTo-HtmlText {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$Value
        )

        if ($null -eq $Value) {
            return ''
        }

        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    function ConvertTo-SafeFileComponent {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Text
        )

        $safe = $Text -replace '[\\/:*?"<>|]', '_'
        $safe = $safe -replace '\s+', '_'
        $safe = $safe.Trim(' ._')

        if ([string]::IsNullOrWhiteSpace($safe)) {
            return 'UnknownScope'
        }

        return $safe
    }

    function Initialize-ADRHFolder {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    }

    function Remove-ExpiredHistoryFiles {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)]
            [string]$HistoryFolder,

            [Parameter(Mandatory)]
            [int]$RetentionDays
        )

        if (-not (Test-Path -LiteralPath $HistoryFolder)) {
            return
        }

        $cutoff = (Get-Date).AddDays(-$RetentionDays)

        Get-ChildItem -LiteralPath $HistoryFolder -File -ErrorAction Stop |
            Where-Object {
                $_.BaseName -like "$($script:ReportBaseName)_v$($script:ScriptVersion)_*" -and
                $_.LastWriteTime -lt $cutoff -and
                $_.Extension -in '.html', '.json'
            } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete expired history file')) {
                    Remove-Item -LiteralPath $_.FullName -Force
                }
            }
    }

    function Resolve-ScopeValue {
        [CmdletBinding()]
        param()

        if (-not [string]::IsNullOrWhiteSpace($ScopeValue)) {
            return $ScopeValue
        }

        if ($ComputerName -and @($ComputerName).Count -gt 0) {
            return 'ExplicitTargets'
        }

        if ($DomainName -and @($DomainName).Count -gt 0) {
            return ($DomainName -join '_')
        }

        if (-not [string]::IsNullOrWhiteSpace($ForestName)) {
            return $ForestName
        }

        return 'CurrentForest'
    }

    function Resolve-SlackWebhookUrl {
        [CmdletBinding()]
        param()

        if (-not [string]::IsNullOrWhiteSpace($SlackWebhookUrl)) {
            return $SlackWebhookUrl
        }

        if (-not [string]::IsNullOrWhiteSpace($env:AD_MONITOR_SLACK_WEBHOOK_URL)) {
            return $env:AD_MONITOR_SLACK_WEBHOOK_URL
        }

        return $null
    }

    function Assert-Configuration {
        [CmdletBinding()]
        param(
            [string]$ResolvedSlackWebhookUrl = ''
        )

        if ($SendEmail) {
            if (-not $To -or @($To).Count -eq 0) {
                throw 'SendEmail was specified but no -To recipient addresses were provided.'
            }

            if ([string]::IsNullOrWhiteSpace($From)) {
                throw 'SendEmail was specified but -From is empty.'
            }

            if ([string]::IsNullOrWhiteSpace($SmtpServer)) {
                throw 'SendEmail was specified but -SmtpServer is empty.'
            }
        }

        if ($SendSlack -and [string]::IsNullOrWhiteSpace($ResolvedSlackWebhookUrl)) {
            throw 'SendSlack was specified but no Slack webhook URL was supplied through -SlackWebhookUrl or the AD_MONITOR_SLACK_WEBHOOK_URL environment variable.'
        }
    }

    function Get-TargetDomainControllers {
        [CmdletBinding()]
        param()

        $targets = [System.Collections.Generic.List[object]]::new()

        if ($ComputerName -and @($ComputerName).Count -gt 0) {
            foreach ($name in $ComputerName) {
                if ([string]::IsNullOrWhiteSpace($name)) {
                    continue
                }

                $domainValue = ''
                if ($name -match '\.') {
                    $domainValue = ($name -split '\.', 2)[1]
                }

                $targets.Add([pscustomobject]@{
                    ComputerName    = $name.Trim()
                    Domain          = $domainValue
                    Site            = ''
                    DiscoverySource = 'ExplicitParameter'
                })
            }

            return $targets
        }

        Write-Verbose 'Importing ActiveDirectory module for domain controller discovery.'
        Import-Module ActiveDirectory -ErrorAction Stop

        $domainsToQuery = [System.Collections.Generic.List[string]]::new()

        if ($DomainName -and @($DomainName).Count -gt 0) {
            foreach ($domain in $DomainName) {
                if (-not [string]::IsNullOrWhiteSpace($domain)) {
                    $domainsToQuery.Add($domain.Trim())
                }
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($ForestName)) {
            $forest = Get-ADForest -Identity $ForestName -ErrorAction Stop
            foreach ($domain in @($forest.Domains)) {
                $domainsToQuery.Add([string]$domain)
            }
        }
        else {
            $forest = Get-ADForest -ErrorAction Stop
            foreach ($domain in @($forest.Domains)) {
                $domainsToQuery.Add([string]$domain)
            }
        }

        foreach ($domain in $domainsToQuery) {
            Write-Verbose "Discovering domain controllers for domain $domain."

            $domainInfo = Get-ADDomain -Identity $domain -Server $domain -ErrorAction Stop
            $queryServer = $domainInfo.PDCEmulator

            if ([string]::IsNullOrWhiteSpace($queryServer)) {
                throw "Could not determine the PDC Emulator for domain $domain."
            }

            $domainControllers = @(Get-ADDomainController -Filter * -Server $queryServer -ErrorAction Stop)

            foreach ($dc in $domainControllers) {
                $targets.Add([pscustomobject]@{
                    ComputerName    = $dc.HostName
                    Domain          = $domain
                    Site            = $dc.Site
                    DiscoverySource = "PDC:$queryServer"
                })
            }
        }

        return $targets
    }

    function Test-TcpPort {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ComputerName,

            [Parameter(Mandatory)]
            [int]$Port,

            [Parameter(Mandatory)]
            [int]$TimeoutMs
        )

        $tcpClient = $null

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)

            if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                $tcpClient.Close()

                return [pscustomobject]@{
                    CheckType = 'Port'
                    CheckName = "TCP/$Port"
                    Status    = 'Failed'
                    Summary   = "TCP port $Port did not open within $TimeoutMs ms."
                    Detail    = "TCP connection to $ComputerName port $Port timed out after $TimeoutMs ms."
                }
            }

            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()

            return [pscustomobject]@{
                CheckType = 'Port'
                CheckName = "TCP/$Port"
                Status    = 'Passed'
                Summary   = "TCP port $Port responded."
                Detail    = "TCP connection to $ComputerName port $Port succeeded."
            }
        }
        catch {
            if ($tcpClient) {
                $tcpClient.Close()
            }

            return [pscustomobject]@{
                CheckType = 'Port'
                CheckName = "TCP/$Port"
                Status    = 'Failed'
                Summary   = "TCP port $Port is not reachable."
                Detail    = $_.Exception.Message
            }
        }
    }

    function Resolve-ExceptionStatus {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Message
        )

        if ($Message -match 'access is denied|unauthorized') {
            return 'Warn'
        }

        return 'Failed'
    }

    # Bounded-timeout scriptblock execution is now shared in Private/Helpers.ps1
    # as Invoke-ADOKWithTimeout (this function used to duplicate it locally).

    function Test-SharePath {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ComputerName,

            [Parameter(Mandatory)]
            [string]$ShareName,

            [Parameter(Mandatory)]
            [int]$TimeoutMs
        )

        $path = "\\$ComputerName\$ShareName"

        $probe = Invoke-ADOKWithTimeout -TimeoutMs $TimeoutMs -ArgumentList @($path) -ScriptBlock {
            param($SharePath)
            Get-Item -LiteralPath $SharePath -ErrorAction Stop
        }

        if ($probe.TimedOut) {
            return [pscustomobject]@{
                CheckType = 'Share'
                CheckName = $ShareName
                Status    = 'Failed'
                Summary   = "$ShareName share check timed out."
                Detail    = "Checking path $path did not complete within $TimeoutMs ms."
            }
        }

        if ($probe.ErrorMessages.Count -gt 0) {
            $message = $probe.ErrorMessages[0]
            $status = Resolve-ExceptionStatus -Message $message

            return [pscustomobject]@{
                CheckType = 'Share'
                CheckName = $ShareName
                Status    = $status
                Summary   = "$ShareName share could not be verified."
                Detail    = $message
            }
        }

        $item = $probe.Output | Select-Object -First 1

        return [pscustomobject]@{
            CheckType = 'Share'
            CheckName = $ShareName
            Status    = 'Passed'
            Summary   = "$ShareName share is reachable."
            Detail    = "Path $($item.FullName) is reachable."
        }
    }

    function Get-ServiceProbeResults {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ComputerName,

            [Parameter(Mandatory)]
            [string[]]$ServiceName,

            [Parameter(Mandatory)]
            [int]$TimeoutMs
        )

        $results = [System.Collections.Generic.List[object]]::new()
        $filter = ($ServiceName | ForEach-Object { "Name='$($_.Replace("'", "''"))'" }) -join ' OR '

        $probe = Invoke-ADOKWithTimeout -TimeoutMs $TimeoutMs -ArgumentList @($ComputerName, $filter) -ScriptBlock {
            param($TargetComputerName, $WmiFilter)
            Get-WmiObject -Class Win32_Service -ComputerName $TargetComputerName -Filter $WmiFilter -ErrorAction Stop
        }

        if ($probe.TimedOut) {
            $results.Add([pscustomobject]@{
                CheckType = 'Service'
                CheckName = 'ServiceCollection'
                Status    = 'Failed'
                Summary   = 'Service-state collection timed out.'
                Detail    = "Collecting service state from $ComputerName did not complete within $TimeoutMs ms."
            })

            return $results
        }

        if ($probe.ErrorMessages.Count -gt 0) {
            $message = $probe.ErrorMessages[0]
            $status = Resolve-ExceptionStatus -Message $message

            $results.Add([pscustomobject]@{
                CheckType = 'Service'
                CheckName = 'ServiceCollection'
                Status    = $status
                Summary   = 'Service-state collection could not be completed.'
                Detail    = $message
            })

            return $results
        }

        $services = @($probe.Output)
        $serviceLookup = @{}

        foreach ($service in $services) {
            $serviceLookup[$service.Name] = $service
        }

        foreach ($name in $ServiceName) {
            if (-not $serviceLookup.ContainsKey($name)) {
                $results.Add([pscustomobject]@{
                    CheckType = 'Service'
                    CheckName = $name
                    Status    = 'Failed'
                    Summary   = "Service $name was not found."
                    Detail    = "Service $name was not returned by Win32_Service on $ComputerName."
                })

                continue
            }

            $service = $serviceLookup[$name]
            $status = if ($service.State -eq 'Running') { 'Passed' } else { 'Failed' }
            $summary = if ($status -eq 'Passed') {
                "Service $name is running."
            }
            else {
                "Service $name is $($service.State)."
            }

            $results.Add([pscustomobject]@{
                CheckType = 'Service'
                CheckName = $name
                Status    = $status
                Summary   = $summary
                Detail    = "StartMode=$($service.StartMode); State=$($service.State); Status=$($service.Status)"
            })
        }

        return $results
    }

    function Get-IssueSummary {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Issue
        )

        if (-not $Issue -or @($Issue).Count -eq 0) {
            return 'Healthy'
        }

        $summaryParts = @($Issue | ForEach-Object { "$($_.CheckType):$($_.CheckName)" })

        if ($summaryParts.Count -le 3) {
            return ($summaryParts -join ', ')
        }

        return '{0}, {1}, {2} (+{3} more)' -f $summaryParts[0], $summaryParts[1], $summaryParts[2], ($summaryParts.Count - 3)
    }

    function Get-IssueSignature {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Issue
        )

        if (-not $Issue -or @($Issue).Count -eq 0) {
            return ''
        }

        return (@(
                $Issue |
                    Sort-Object CheckType, CheckName, Status |
                    ForEach-Object { '{0}|{1}|{2}' -f $_.CheckType, $_.CheckName, $_.Status }
            ) -join ';')
    }

    function Get-HeartbeatResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Target
        )

        Write-Verbose "Running heartbeat checks for $($Target.ComputerName)."

        $portResults = [System.Collections.Generic.List[object]]::new()
        $shareResults = [System.Collections.Generic.List[object]]::new()
        $serviceResults = [System.Collections.Generic.List[object]]::new()
        $issues = [System.Collections.Generic.List[object]]::new()

        foreach ($port in $TcpPort) {
            $portResult = Test-TcpPort -ComputerName $Target.ComputerName -Port $port -TimeoutMs $TcpTimeoutMs
            $portResults.Add($portResult)

            if ($portResult.Status -ne 'Passed') {
                $issues.Add($portResult)
            }
        }

        # Skip the SMB share checks and WMI/DCOM service checks entirely when the
        # baseline TCP port they depend on already failed. Get-Item on a UNC path
        # and Get-WmiObject have no reachability short-circuit of their own, so
        # attempting them against an already-unreachable DC would just add a
        # second, redundant multi-second stall on top of the TCP timeout that
        # already proved the point - directly working against the 30-60 second
        # polling interval this script is designed for.
        $smbPortUnreachable = @($portResults | Where-Object { $_.CheckName -eq 'TCP/445' -and $_.Status -ne 'Passed' }).Count -gt 0
        $rpcPortUnreachable = @($portResults | Where-Object { $_.CheckName -eq 'TCP/135' -and $_.Status -ne 'Passed' }).Count -gt 0

        if (-not $SkipSysvolCheck) {
            if ($smbPortUnreachable) {
                $shareResults.Add([pscustomobject]@{
                    CheckType = 'Share'
                    CheckName = 'SYSVOL'
                    Status    = 'Skipped'
                    Summary   = 'SYSVOL check skipped - TCP/445 already failed.'
                    Detail    = 'Skipped to avoid a redundant SMB stall after TCP port 445 was already unreachable.'
                })
            }
            else {
                $sysvolResult = Test-SharePath -ComputerName $Target.ComputerName -ShareName 'SYSVOL' -TimeoutMs $DeepCheckTimeoutMs
                $shareResults.Add($sysvolResult)

                if ($sysvolResult.Status -ne 'Passed') {
                    $issues.Add($sysvolResult)
                }
            }
        }

        if (-not $SkipNetlogonCheck) {
            if ($smbPortUnreachable) {
                $shareResults.Add([pscustomobject]@{
                    CheckType = 'Share'
                    CheckName = 'NETLOGON'
                    Status    = 'Skipped'
                    Summary   = 'NETLOGON check skipped - TCP/445 already failed.'
                    Detail    = 'Skipped to avoid a redundant SMB stall after TCP port 445 was already unreachable.'
                })
            }
            else {
                $netlogonResult = Test-SharePath -ComputerName $Target.ComputerName -ShareName 'NETLOGON' -TimeoutMs $DeepCheckTimeoutMs
                $shareResults.Add($netlogonResult)

                if ($netlogonResult.Status -ne 'Passed') {
                    $issues.Add($netlogonResult)
                }
            }
        }

        if (-not $SkipServiceChecks) {
            if ($rpcPortUnreachable) {
                $serviceResults.Add([pscustomobject]@{
                    CheckType = 'Service'
                    CheckName = 'ServiceCollection'
                    Status    = 'Skipped'
                    Summary   = 'Service checks skipped - TCP/135 already failed.'
                    Detail    = 'Skipped to avoid a redundant WMI/DCOM stall after TCP port 135 (RPC endpoint mapper) was already unreachable.'
                })
            }
            else {
                foreach ($serviceResult in @(Get-ServiceProbeResults -ComputerName $Target.ComputerName -ServiceName $RequiredService -TimeoutMs $DeepCheckTimeoutMs)) {
                    $serviceResults.Add($serviceResult)

                    if ($serviceResult.Status -ne 'Passed') {
                        $issues.Add($serviceResult)
                    }
                }
            }
        }

        $failedIssues = @($issues | Where-Object { $_.Status -eq 'Failed' })
        $warnIssues = @($issues | Where-Object { $_.Status -eq 'Warn' })

        $overallStatus = if ($failedIssues.Count -gt 0) {
            'Failed'
        }
        elseif ($warnIssues.Count -gt 0) {
            'Warn'
        }
        else {
            'Passed'
        }

        $openPorts = @($portResults | Where-Object { $_.Status -eq 'Passed' }).Count
        $sharePassed = @($shareResults | Where-Object { $_.Status -eq 'Passed' }).Count
        $servicePassed = @($serviceResults | Where-Object { $_.Status -eq 'Passed' }).Count

        [pscustomobject]@{
            OverallStatus    = $overallStatus
            Domain           = $Target.Domain
            Server           = $Target.ComputerName
            Site             = $Target.Site
            DiscoverySource  = $Target.DiscoverySource
            TcpSummary       = '{0}/{1}' -f $openPorts, @($portResults).Count
            ShareSummary     = if ($shareResults.Count -gt 0) { '{0}/{1}' -f $sharePassed, @($shareResults).Count } else { 'Skipped' }
            ServiceSummary   = if ($serviceResults.Count -gt 0) { '{0}/{1}' -f $servicePassed, @($serviceResults).Count } else { 'Skipped' }
            IssueCount       = @($issues).Count
            IssueSummary     = Get-IssueSummary -Issue @($issues)
            IssueSignature   = Get-IssueSignature -Issue @($issues)
            Issues           = @($issues)
            PortResults      = @($portResults)
            ShareResults     = @($shareResults)
            ServiceResults   = @($serviceResults)
            RunTimeUtc       = $script:RunUtc
        }
    }

    function Get-StatusCssClass {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Status
        )

        switch ($Status) {
            'Passed' { return 'status-passed' }
            'Failed' { return 'status-failed' }
            'Warn' { return 'status-warn' }
            default { return 'status-unknown' }
        }
    }

    function New-HeartbeatHtmlReport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object[]]$Result,

            [Parameter(Mandatory)]
            [string]$ScopeText
        )

        $passedCount = @($Result | Where-Object { $_.OverallStatus -eq 'Passed' }).Count
        $warnCount = @($Result | Where-Object { $_.OverallStatus -eq 'Warn' }).Count
        $failedCount = @($Result | Where-Object { $_.OverallStatus -eq 'Failed' }).Count

        $rowBuilder = New-Object System.Text.StringBuilder

        foreach ($item in $Result) {
            $statusClass = Get-StatusCssClass -Status $item.OverallStatus
            $null = $rowBuilder.AppendLine('<tr>')
            $null = $rowBuilder.AppendLine("  <td><span class=""status-badge $statusClass"">$([System.Net.WebUtility]::HtmlEncode($item.OverallStatus))</span></td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.Domain))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.Server))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.Site))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.TcpSummary))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.ShareSummary))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.ServiceSummary))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.IssueSummary))</td>")
            $null = $rowBuilder.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$item.DiscoverySource))</td>")
            $null = $rowBuilder.AppendLine('</tr>')
        }

        $generatedLocal = $script:RunLocal.ToString('yyyy-MM-dd HH:mm:ss')
        $generatedUtc = $script:RunUtc.ToString('yyyy-MM-dd HH:mm:ss')

        @"
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <title>AD Real-Time Monitor v$($script:ScriptVersion)</title>
      <style>
        body { font-family: Segoe UI, Tahoma, Arial, sans-serif; margin: 0; background: #eef2f6; color: #22313f; }
        .banner { background: #27425D; color: #ffffff; padding: 28px 32px; display: flex; justify-content: space-between; gap: 24px; }
        .banner h1 { margin: 0 0 10px 0; font-size: 28px; font-weight: 700; }
        .banner .meta { color: #d9e4ef; font-size: 13px; line-height: 1.6; }
        .panel-grid { display: flex; gap: 16px; flex-wrap: wrap; padding: 20px 32px 0 32px; }
        .tile { background: #ffffff; border: 1px solid #d7dee7; border-radius: 10px; padding: 16px 18px; min-width: 170px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
        .tile h2 { margin: 0 0 8px 0; font-size: 13px; color: #5b6773; text-transform: uppercase; letter-spacing: 0.04em; }
        .tile .value { font-size: 28px; font-weight: 700; color: #22313f; }
        .content { padding: 20px 32px 32px 32px; }
        .section { background: #ffffff; border: 1px solid #d7dee7; border-radius: 10px; padding: 18px 20px 22px 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
        .section h2 { margin: 0 0 14px 0; font-size: 20px; color: #22313f; }
        .section p { margin: 0 0 14px 0; color: #465464; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #e7ecf2; color: #22313f; text-align: left; padding: 10px 12px; border-bottom: 1px solid #d7dee7; }
        td { padding: 10px 12px; border-bottom: 1px solid #e5ebf1; vertical-align: top; }
        tr:nth-child(even) td { background: #fafbfd; }
        .status-badge { display: inline-block; min-width: 76px; padding: 4px 10px; border-radius: 999px; text-align: center; font-size: 12px; font-weight: 700; }
        .status-passed { background: #dff3e3; color: #1f6f37; }
        .status-failed { background: #f8d7da; color: #8a1f2d; }
        .status-warn { background: #fff3cd; color: #8a6700; }
        .status-unknown { background: #dce3ea; color: #51606e; }
      </style>
    </head>
    <body>
      <div class="banner">
        <div>
          <h1>AD Real-Time Monitor v$($script:ScriptVersion)</h1>
          <div class="meta">
            <div>Generated Local: $generatedLocal</div>
            <div>Generated UTC: $generatedUtc</div>
            <div>Scope: $([System.Net.WebUtility]::HtmlEncode($ScopeText))</div>
          </div>
        </div>
        <div class="meta">
          <div>Ran By: $([System.Net.WebUtility]::HtmlEncode($script:RunUser))</div>
          <div>Run From Computer: $([System.Net.WebUtility]::HtmlEncode($script:RunComputer))</div>
          <div>Target Count: $(@($Result).Count)</div>
        </div>
      </div>
      <div class="panel-grid">
        <div class="tile">
          <h2>Passed</h2>
          <div class="value">$passedCount</div>
        </div>
        <div class="tile">
          <h2>Warning</h2>
          <div class="value">$warnCount</div>
        </div>
        <div class="tile">
          <h2>Failed</h2>
          <div class="value">$failedCount</div>
        </div>
        <div class="tile">
          <h2>Monitor Type</h2>
          <div class="value" style="font-size:20px;">Heartbeat</div>
        </div>
      </div>
      <div class="content">
        <div class="section">
          <h2>Health Details</h2>
          <p>
            This heartbeat report avoids WinRM. Discovery uses ActiveDirectory
            cmdlets unless explicit targets are supplied. TCP reachability is
            tested from the monitoring host, service state uses WMI/DCOM, and share
            reachability uses direct SMB path checks.
          </p>
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Domain</th>
                <th>Server</th>
                <th>Site</th>
                <th>Ports</th>
                <th>Shares</th>
                <th>Services</th>
                <th>Findings</th>
                <th>Discovery Source</th>
              </tr>
            </thead>
            <tbody>
    $($rowBuilder.ToString())
            </tbody>
          </table>
        </div>
      </div>
    </body>
    </html>
"@
    }

    function Import-AlertState {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $state = @{}

        if (-not (Test-Path -LiteralPath $Path)) {
            return $state
        }

        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $state
        }

        try {
            $json = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        }
        catch {
            # A truncated/corrupt state file (e.g. the process was killed mid-write
            # on a prior run) must not permanently wedge the monitor - every future
            # run would otherwise fail here forever. Treat it as "no prior state"
            # instead; Save-AlertState below now writes atomically so this should
            # only happen for files written before that fix, or from external
            # interference with the file.
            Write-Warning "Could not parse alert state file '$Path' - treating as no prior state. $($_.Exception.Message)"
            return $state
        }

        foreach ($entry in @($json.Entries)) {
            $key = ([string]$entry.ComputerName).ToLowerInvariant()
            $state[$key] = [pscustomobject]@{
                ComputerName    = [string]$entry.ComputerName
                Domain          = [string]$entry.Domain
                IsActive        = [bool]$entry.IsActive
                Severity        = [string]$entry.Severity
                IssueSignature  = [string]$entry.IssueSignature
                FirstSeenUtc    = [string]$entry.FirstSeenUtc
                LastSeenUtc     = [string]$entry.LastSeenUtc
                LastNotifiedUtc = [string]$entry.LastNotifiedUtc
                LastSummary     = [string]$entry.LastSummary
            }
        }

        return $state
    }

    function Save-AlertState {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [hashtable]$State,

            [Parameter(Mandatory)]
            [string]$Path
        )

        $entries = [System.Collections.Generic.List[object]]::new()

        foreach ($key in @($State.Keys | Sort-Object)) {
            $entry = $State[$key]
            $entries.Add([pscustomobject]@{
                ComputerName    = $entry.ComputerName
                Domain          = $entry.Domain
                IsActive        = $entry.IsActive
                Severity        = $entry.Severity
                IssueSignature  = $entry.IssueSignature
                FirstSeenUtc    = $entry.FirstSeenUtc
                LastSeenUtc     = $entry.LastSeenUtc
                LastNotifiedUtc = $entry.LastNotifiedUtc
                LastSummary     = $entry.LastSummary
            })
        }

        $payload = [pscustomobject]@{
            SchemaVersion = '1.0'
            ScriptName    = $script:ScriptName
            Version       = $script:ScriptVersion
            UpdatedUtc    = $script:RunUtc.ToString('o')
            Entries       = $entries
        }

        $json = $payload | ConvertTo-Json -Depth 6

        # Write to a temp file and rename into place rather than writing $Path
        # directly - a rename on the same volume is atomic, so a process killed
        # mid-write (Task Scheduler timeout, power loss) can never leave a
        # truncated/corrupt state file behind.
        $tempPath = "$Path.tmp"
        Set-Content -LiteralPath $tempPath -Value $json -Encoding UTF8
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    }

    function New-NotificationPlan {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object[]]$Result,

            [Parameter(Mandatory)]
            [hashtable]$ExistingState
        )

        $notifications = [System.Collections.Generic.List[object]]::new()
        $updatedState = @{}
        $suppressWindow = [TimeSpan]::FromMinutes($SuppressRepeatMinutes)

        foreach ($item in $Result) {
            $key = ([string]$item.Server).ToLowerInvariant()
            $existing = $null

            if ($ExistingState.ContainsKey($key)) {
                $existing = $ExistingState[$key]
            }

            $alertEligible = $item.OverallStatus -eq 'Failed' -or ($AlertOnWarning -and $item.OverallStatus -eq 'Warn')

            if ($alertEligible) {
                $severityLabel = if ($item.OverallStatus -eq 'Failed') { 'ALERT' } else { 'WARNING' }
                $shouldNotify = $false
                $reason = ''
                $firstSeenUtc = $script:RunUtc.ToString('o')
                $lastNotifiedUtc = ''

                if (-not $existing -or -not $existing.IsActive) {
                    $shouldNotify = $true
                    $reason = 'New'
                }
                elseif ($existing.IssueSignature -ne $item.IssueSignature) {
                    $shouldNotify = $true
                    $reason = 'Changed'
                    $firstSeenUtc = if ([string]::IsNullOrWhiteSpace($existing.FirstSeenUtc)) { $script:RunUtc.ToString('o') } else { $existing.FirstSeenUtc }
                }
                else {
                    $firstSeenUtc = if ([string]::IsNullOrWhiteSpace($existing.FirstSeenUtc)) { $script:RunUtc.ToString('o') } else { $existing.FirstSeenUtc }

                    if ([string]::IsNullOrWhiteSpace($existing.LastNotifiedUtc)) {
                        $shouldNotify = $true
                        $reason = 'Repeated'
                    }
                    else {
                        $lastNotificationTime = [datetime]::Parse($existing.LastNotifiedUtc, $script:InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)

                        if (($script:RunUtc - $lastNotificationTime) -ge $suppressWindow) {
                            $shouldNotify = $true
                            $reason = 'Repeated'
                        }
                    }
                }

                if ($shouldNotify) {
                    $lastNotifiedUtc = $script:RunUtc.ToString('o')

                    $notifications.Add([pscustomobject]@{
                        Action          = 'Alert'
                        Reason          = $reason
                        Severity        = $severityLabel
                        OverallStatus   = $item.OverallStatus
                        Domain          = $item.Domain
                        ComputerName    = $item.Server
                        IssueSummary    = $item.IssueSummary
                        Issues          = @($item.Issues)
                        FirstSeenUtc    = $firstSeenUtc
                        LastSeenUtc     = $script:RunUtc.ToString('o')
                        DiscoverySource = $item.DiscoverySource
                    })
                }
                else {
                    $lastNotifiedUtc = $existing.LastNotifiedUtc
                }

                $updatedState[$key] = [pscustomobject]@{
                    ComputerName    = $item.Server
                    Domain          = $item.Domain
                    IsActive        = $true
                    Severity        = $severityLabel
                    IssueSignature  = $item.IssueSignature
                    FirstSeenUtc    = $firstSeenUtc
                    LastSeenUtc     = $script:RunUtc.ToString('o')
                    LastNotifiedUtc = $lastNotifiedUtc
                    LastSummary     = $item.IssueSummary
                }
            }
            else {
                if ($existing -and $existing.IsActive) {
                    $notifications.Add([pscustomobject]@{
                        Action          = 'Recovery'
                        Reason          = 'Cleared'
                        Severity        = 'OK'
                        OverallStatus   = $item.OverallStatus
                        Domain          = $item.Domain
                        ComputerName    = $item.Server
                        IssueSummary    = 'Alert condition cleared.'
                        Issues          = @()
                        FirstSeenUtc    = $existing.FirstSeenUtc
                        LastSeenUtc     = $script:RunUtc.ToString('o')
                        DiscoverySource = $item.DiscoverySource
                    })
                }

                $updatedState[$key] = [pscustomobject]@{
                    ComputerName    = $item.Server
                    Domain          = $item.Domain
                    IsActive        = $false
                    Severity        = $item.OverallStatus
                    IssueSignature  = $item.IssueSignature
                    FirstSeenUtc    = ''
                    LastSeenUtc     = $script:RunUtc.ToString('o')
                    LastNotifiedUtc = if ($existing) { $existing.LastNotifiedUtc } else { '' }
                    LastSummary     = $item.IssueSummary
                }
            }
        }

        foreach ($key in $ExistingState.Keys) {
            if (-not $updatedState.ContainsKey($key)) {
                $updatedState[$key] = $ExistingState[$key]
            }
        }

        [pscustomobject]@{
            Notifications = $notifications
            UpdatedState  = $updatedState
        }
    }

    function New-NotificationSubject {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Notification
        )

        $dateText = $script:RunLocal.ToString('M/d/yyyy')

        if ($Notification.Action -eq 'Recovery') {
            return 'OK: {0} - DC: {1} - Alert condition cleared - {2}' -f $script:ShortMonitorName, $Notification.ComputerName, $dateText
        }

        return '{0}: {1} - DC: {2} - {3} - {4}' -f $Notification.Severity, $script:ShortMonitorName, $Notification.ComputerName, $Notification.IssueSummary, $dateText
    }

    function New-NotificationHtmlBody {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Notification
        )

        $issueRows = New-Object System.Text.StringBuilder

        foreach ($issue in @($Notification.Issues)) {
            $null = $issueRows.AppendLine('<tr>')
            $null = $issueRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$issue.CheckType))</td>")
            $null = $issueRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$issue.CheckName))</td>")
            $null = $issueRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$issue.Status))</td>")
            $null = $issueRows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode([string]$issue.Detail))</td>")
            $null = $issueRows.AppendLine('</tr>')
        }

        if ($issueRows.Length -eq 0) {
            $null = $issueRows.AppendLine('<tr><td colspan="4">No active issue rows. This is a recovery notification.</td></tr>')
        }

        @"
    <html>
      <body style="font-family:Segoe UI,Tahoma,Arial,sans-serif;background:#eef2f6;color:#22313f;">
        <div style="max-width:900px;margin:0 auto;padding:20px;">
          <div style="background:#27425D;color:#ffffff;padding:20px 24px;border-radius:10px 10px 0 0;">
            <h1 style="margin:0 0 8px 0;font-size:24px;">$([System.Net.WebUtility]::HtmlEncode($script:ShortMonitorName))</h1>
            <div style="color:#d9e4ef;">$([System.Net.WebUtility]::HtmlEncode((New-NotificationSubject -Notification $Notification)))</div>
          </div>
          <div style="background:#ffffff;padding:20px 24px;border:1px solid #d7dee7;border-top:none;border-radius:0 0 10px 10px;">
            <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
              <tr><td style="padding:6px 0;font-weight:700;width:180px;">Severity</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.Severity))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">Domain</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.Domain))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">Domain Controller</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.ComputerName))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">Summary</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.IssueSummary))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">First Seen UTC</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.FirstSeenUtc))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">Last Seen UTC</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$Notification.LastSeenUtc))</td></tr>
              <tr><td style="padding:6px 0;font-weight:700;">Run Source</td><td style="padding:6px 0;">$([System.Net.WebUtility]::HtmlEncode([string]$script:RunComputer))</td></tr>
            </table>
            <table style="width:100%;border-collapse:collapse;">
              <thead>
                <tr>
                  <th style="text-align:left;background:#e7ecf2;padding:10px;border-bottom:1px solid #d7dee7;">Check Type</th>
                  <th style="text-align:left;background:#e7ecf2;padding:10px;border-bottom:1px solid #d7dee7;">Check Name</th>
                  <th style="text-align:left;background:#e7ecf2;padding:10px;border-bottom:1px solid #d7dee7;">Status</th>
                  <th style="text-align:left;background:#e7ecf2;padding:10px;border-bottom:1px solid #d7dee7;">Detail</th>
                </tr>
              </thead>
              <tbody>
    $($issueRows.ToString())
              </tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
"@
    }

    function New-NotificationSlackText {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Notification
        )

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add((New-NotificationSubject -Notification $Notification))
        $lines.Add("Severity: $($Notification.Severity)")
        $lines.Add("Domain: $($Notification.Domain)")
        $lines.Add("Domain Controller: $($Notification.ComputerName)")
        $lines.Add("Summary: $($Notification.IssueSummary)")
        $lines.Add("First Seen UTC: $($Notification.FirstSeenUtc)")
        $lines.Add("Last Seen UTC: $($Notification.LastSeenUtc)")
        $lines.Add("Run Source: $($script:RunComputer)")

        if ($Notification.Action -eq 'Alert' -and @($Notification.Issues).Count -gt 0) {
            $lines.Add('Checks:')

            foreach ($issue in @($Notification.Issues)) {
                $lines.Add("- $($issue.CheckType) $($issue.CheckName): $($issue.Status)")
            }
        }

        return ($lines -join [Environment]::NewLine)
    }

    function Send-AlertEmailMessage {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Notification
        )

        if (-not $SendEmail) {
            return
        }

        $mailParams = @{
            To         = $To
            From       = $From
            SmtpServer = $SmtpServer
            Port       = $SmtpPort
            Subject    = New-NotificationSubject -Notification $Notification
            Body       = New-NotificationHtmlBody -Notification $Notification
            BodyAsHtml = $true
        }

        if ($PSCmdlet.ShouldProcess(($To -join ', '), "Send AD Real-Time Monitor alert email for $($Notification.ComputerName)")) {
            Write-Verbose "Sending email notification for $($Notification.ComputerName)."
            Send-MailMessage @mailParams
        }
    }

    function Send-SlackAlertMessage {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Notification,

            [string]$ResolvedSlackWebhookUrl = ''
        )

        if (-not $SendSlack) {
            return
        }

        $payload = @{
            text = New-NotificationSlackText -Notification $Notification
        } | ConvertTo-Json -Depth 4

        if ($PSCmdlet.ShouldProcess($ResolvedSlackWebhookUrl, "Send AD Real-Time Monitor Slack alert for $($Notification.ComputerName)")) {
            Write-Verbose "Sending Slack notification for $($Notification.ComputerName)."
            Invoke-RestMethod -Method Post -Uri $ResolvedSlackWebhookUrl -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
        }
    }

    if ($VersionInfo) {
        Get-VersionMetadata
        return
    }

    # Defined before the try block so it is always available - even on a
    # failure so early that Resolve-SlackWebhookUrl never ran - to the
    # self-failure notification in the catch block below.
    $resolvedSlackWebhookUrl = ''

    try {

    $resolvedScopeValue = Resolve-ScopeValue
    $safeScopeValue = ConvertTo-SafeFileComponent -Text $resolvedScopeValue
    $resolvedSlackWebhookUrl = Resolve-SlackWebhookUrl

    Assert-Configuration -ResolvedSlackWebhookUrl $resolvedSlackWebhookUrl

    Initialize-ADRHFolder -Path $OutputFolder

    $historyFolder = Join-Path -Path $OutputFolder -ChildPath $script:HistoryFolderName
    Initialize-ADRHFolder -Path $historyFolder

    $historyTimestamp = $script:RunLocal.ToString('yyyyMMdd_HHmmss')
    $historyHtmlPath = Join-Path -Path $historyFolder -ChildPath ('{0}_v{1}_{2}_{3}.html' -f $script:ReportBaseName, $script:ScriptVersion, $safeScopeValue, $historyTimestamp)
    $historyJsonPath = Join-Path -Path $historyFolder -ChildPath ('{0}_v{1}_{2}_{3}.json' -f $script:ReportBaseName, $script:ScriptVersion, $safeScopeValue, $historyTimestamp)
    $latestHtmlPath = Join-Path -Path $OutputFolder -ChildPath 'latest.html'
    $latestJsonPath = Join-Path -Path $OutputFolder -ChildPath 'latest.json'
    $stateFilePath = Join-Path -Path $OutputFolder -ChildPath 'ADRealtimeHeartbeat-State.json'

    Remove-ExpiredHistoryFiles -HistoryFolder $historyFolder -RetentionDays $ReportRetentionDays

    Write-Verbose 'Discovering target domain controllers.'
    $targets = @(Get-TargetDomainControllers)

    if (@($targets).Count -eq 0) {
        throw 'No domain controllers were discovered or supplied.'
    }

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $targets) {
        try {
            $results.Add((Get-HeartbeatResult -Target $target))
        }
        catch {
            $failureIssue = [pscustomobject]@{
                CheckType = 'Collection'
                CheckName = 'HeartbeatRun'
                Status    = 'Failed'
                Summary   = 'Heartbeat collection failed.'
                Detail    = $_.Exception.Message
            }

            $results.Add([pscustomobject]@{
                OverallStatus    = 'Failed'
                Domain           = $target.Domain
                Server           = $target.ComputerName
                Site             = $target.Site
                DiscoverySource  = $target.DiscoverySource
                TcpSummary       = '0/0'
                ShareSummary     = '0/0'
                ServiceSummary   = '0/0'
                IssueCount       = 1
                IssueSummary     = 'Collection:HeartbeatRun'
                IssueSignature   = 'Collection|HeartbeatRun|Failed'
                Issues           = @($failureIssue)
                PortResults      = @()
                ShareResults     = @()
                ServiceResults   = @()
                RunTimeUtc       = $script:RunUtc
            })
        }
    }

    $resultsArray = @($results)

    $reportHtml = New-HeartbeatHtmlReport -Result $resultsArray -ScopeText $resolvedScopeValue
    $reportJsonObject = [pscustomobject]@{
        ScriptName      = $script:ScriptName
        Version         = $script:ScriptVersion
        GeneratedLocal  = $script:RunLocal
        GeneratedUtc    = $script:RunUtc
        ScopeValue      = $resolvedScopeValue
        RunComputer     = $script:RunComputer
        RunUser         = $script:RunUser
        TargetCount     = $resultsArray.Count
        Result          = $resultsArray
    }
    $reportJson = $reportJsonObject | ConvertTo-Json -Depth 8

    Set-Content -LiteralPath $historyHtmlPath -Value $reportHtml -Encoding UTF8
    Set-Content -LiteralPath $latestHtmlPath -Value $reportHtml -Encoding UTF8
    Set-Content -LiteralPath $historyJsonPath -Value $reportJson -Encoding UTF8
    Set-Content -LiteralPath $latestJsonPath -Value $reportJson -Encoding UTF8

    $existingState = Import-AlertState -Path $stateFilePath
    $notificationPlan = New-NotificationPlan -Result $resultsArray -ExistingState $existingState

    # Each send is isolated so one failed email/Slack delivery (bad SMTP relay,
    # webhook timeout, etc.) does not skip the remaining notifications in this
    # run or - critically - the Save-AlertState call below. Losing that call
    # would make every DC in this run look "new" again on the next run and
    # re-fire alerts that already went out, or silently drop LastSeenUtc
    # updates for DCs that were never even attempted.
    $failedNotifications = [System.Collections.Generic.List[string]]::new()
    foreach ($notification in @($notificationPlan.Notifications)) {
        try {
            Send-AlertEmailMessage -Notification $notification
        }
        catch {
            Write-Warning "Failed to send alert email for $($notification.ComputerName): $($_.Exception.Message)"
            $failedNotifications.Add("$($notification.ComputerName) (email)")
        }
        try {
            Send-SlackAlertMessage -Notification $notification -ResolvedSlackWebhookUrl $resolvedSlackWebhookUrl
        }
        catch {
            Write-Warning "Failed to send Slack alert for $($notification.ComputerName): $($_.Exception.Message)"
            $failedNotifications.Add("$($notification.ComputerName) (Slack)")
        }
    }
    if ($failedNotifications.Count -gt 0) {
        Write-Warning "$($failedNotifications.Count) notification(s) failed to send: $($failedNotifications -join ', ')"
    }

    Save-AlertState -State $notificationPlan.UpdatedState -Path $stateFilePath

    $resultsArray |
        Select-Object OverallStatus, Domain, Server, Site, TcpSummary, ShareSummary, ServiceSummary, IssueCount, IssueSummary, DiscoverySource

    }
    catch {
        # The monitor failing to run at all (AD discovery broke, the output
        # folder is unwritable, etc.) is a more urgent condition than any single
        # DC being down, and would otherwise fail silently except for a
        # non-zero process exit code that only Task Scheduler's Last Run Result
        # would show. Make a best-effort attempt to notify through the same
        # channels as a normal DC alert before exiting non-zero.
        $failureMessage = $_.Exception.Message
        Write-Error "AD Real-Time Monitor failed: $failureMessage"

        $selfFailureNotification = [pscustomobject]@{
            Action          = 'Alert'
            Reason          = 'MonitorFailure'
            Severity        = 'ALERT'
            OverallStatus   = 'Failed'
            Domain          = 'N/A'
            ComputerName    = "$script:ScriptName (host: $script:RunComputer)"
            IssueSummary    = "The monitor script itself failed: $failureMessage"
            Issues          = @([pscustomobject]@{
                CheckType = 'Monitor'
                CheckName = 'ScriptExecution'
                Status    = 'Failed'
                Summary   = 'The monitor script terminated with an unhandled error.'
                Detail    = $failureMessage
            })
            FirstSeenUtc    = $script:RunUtc.ToString('o')
            LastSeenUtc     = $script:RunUtc.ToString('o')
            DiscoverySource = 'N/A'
        }

        try {
            Send-AlertEmailMessage -Notification $selfFailureNotification -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not send self-failure email notification: $($_.Exception.Message)"
        }

        try {
            Send-SlackAlertMessage -Notification $selfFailureNotification -ResolvedSlackWebhookUrl $resolvedSlackWebhookUrl -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not send self-failure Slack notification: $($_.Exception.Message)"
        }

        throw
    }

}
