<#
.SYNOPSIS
    Creates an HTML report of recently installed Windows updates on domain controllers.

.DESCRIPTION
    Discovers all domain controllers in the current domain, or in the domain
    provided with -DomainName, and queries each domain controller using
    WMI/DCOM. It does not use WinRM.

    The report includes:
    - Updates installed within the selected lookback window
    - Full update names from Windows Update Client events when available
    - Last restart time
    - Pending restart status and reason
    - Error message when a computer cannot be queried
    - HTML color coding for installed, failed, pending restart, and no recent updates

.PARAMETER DaysBack
    Number of days of installed update history to include. Defaults to 15.

.PARAMETER DomainName
    Optional domain DNS name used for domain-controller discovery.
    If omitted, the current logon domain is used.

.PARAMETER ComputerName
    Optional manual list of computers. If supplied, AD domain-controller
    discovery is skipped. Use this to test one or two DCs first.

.PARAMETER ReportPath
    HTML report output path.

.PARAMETER SendEmail
    Sends the HTML report by email when set to $true.

.PARAMETER SmtpServer
    SMTP server used when -SendEmail is enabled.

.PARAMETER SmtpPort
    SMTP port used when -SendEmail is enabled.

.PARAMETER From
    Sender email address used when -SendEmail is enabled.

.PARAMETER To
    Recipient email address list used when -SendEmail is enabled.

.PARAMETER Subject
    Email subject used when -SendEmail is enabled.

.EXAMPLE
    .\Get-DomainControllerWindowsUpdateReport-GitHub.ps1

.EXAMPLE
    .\Get-DomainControllerWindowsUpdateReport-GitHub.ps1 -DaysBack 14

.EXAMPLE
    .\Get-DomainControllerWindowsUpdateReport-GitHub.ps1 -ComputerName DC01,DC02

.EXAMPLE
    .\Get-DomainControllerWindowsUpdateReport-GitHub.ps1 -SendEmail:$true -SmtpServer smtp.example.com -From dc-report@example.com -To admin@example.com

.NOTES
    Requires:
    - Windows PowerShell 5.1
    - WMI/DCOM access to each target domain controller
    - Administrator rights on each target domain controller
    - Active Directory module for discovery, or .NET domain discovery fallback
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    # ==============================
    # Email settings
    # GitHub/public version uses placeholders. Update these for your environment.
    # Email is disabled by default so the script can be tested safely after download.
    # ==============================
    [bool]$SendEmail = $false,

    [string]$SmtpServer = 'smtp.example.com',

    [int]$SmtpPort = 25,

    [string]$From = 'dc-update-report@example.com',

    [string[]]$To = @('recipient@example.com'),

    [string]$Subject = "Domain Controller Windows Update Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')",

    # ==============================
    # Report and target settings
    # ==============================
    [ValidateRange(1, 3650)]
    [int]$DaysBack = 15,

    [string]$DomainName,

    [string[]]$ComputerName,

    [string]$ReportPath = 'C:\Temp\Domain_Controller_Windows_Update_Report.html'
)

$ErrorActionPreference = 'Stop'

# Converts values before inserting them into the HTML report.
# This prevents special characters in update names or error messages from breaking the HTML table.
function ConvertTo-HtmlText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# Converts the InstalledOn value returned by Win32_QuickFixEngineering into a real DateTime.
# QFE data is not always returned in one consistent format, so this function handles several common date formats.
function ConvertFrom-QfeInstalledOn {
    param(
        [AllowNull()]
        [object]$InstalledOn
    )

    if ($null -eq $InstalledOn) {
        return $null
    }

    if ($InstalledOn -is [datetime]) {
        return $InstalledOn
    }

    $text = ([string]$InstalledOn).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    if ($text -match '^\d{14}\.') {
        try {
            return [Management.ManagementDateTimeConverter]::ToDateTime($text)
        }
        catch {
            # Continue with normal parsing.
        }
    }

    $formats = @(
        'M/d/yyyy',
        'M/d/yy',
        'MM/dd/yyyy',
        'MM/dd/yy',
        'd/M/yyyy',
        'd/M/yy',
        'dd/MM/yyyy',
        'dd/MM/yy',
        'M-d-yyyy',
        'M-d-yy',
        'MM-dd-yyyy',
        'MM-dd-yy',
        'd-M-yyyy',
        'd-M-yy',
        'dd-MM-yyyy',
        'dd-MM-yy',
        'yyyy-MM-dd',
        'yyyy/MM/dd',
        'yyyyMMdd'
    )

    $cultures = @(
        [Globalization.CultureInfo]::CurrentCulture,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.CultureInfo]::GetCultureInfo('en-US'),
        [Globalization.CultureInfo]::GetCultureInfo('en-GB')
    ) | Sort-Object -Property Name -Unique

    foreach ($culture in $cultures) {
        $parsed = [datetime]::MinValue

        if ([datetime]::TryParseExact($text, $formats, $culture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)) {
            return $parsed
        }

        if ([datetime]::TryParse($text, $culture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)) {
            return $parsed
        }
    }

    return $null
}

# Formats dates consistently for the report. If a date is missing, the report shows N/A.
function ConvertTo-ReportDate {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'N/A'
    }

    if ($Value -is [datetime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss')
    }

    return [string]$Value
}

# Extracts all KB numbers from text such as update titles or QFE descriptions.
function Get-HotFixIdListFromText {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    return @(
        [regex]::Matches($Text, 'KB\d{4,8}', [Text.RegularExpressions.RegexOptions]::IgnoreCase) |
            ForEach-Object { $_.Value.ToUpperInvariant() } |
            Sort-Object -Unique
    )
}

# Returns KB numbers as a single display string for the HTML report.
function Get-HotFixIdFromText {
    param(
        [AllowNull()]
        [string]$Text
    )

    $kbIds = @(Get-HotFixIdListFromText -Text $Text)

    if ($kbIds.Count -eq 0) {
        return 'N/A'
    }

    return $kbIds -join ', '
}

# Pulls the readable update title from Windows Update Client event messages.
# Example: "Installation Successful: Windows successfully installed the following update: <title>"
function Get-UpdateTitleFromEventMessage {
    param(
        [AllowNull()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return ''
    }

    $normalizedMessage = ([string]$Message -replace '\s+', ' ').Trim()
    $titleMatch = [regex]::Match($normalizedMessage, '(?i)following update:\s*(?<Title>.+)$')

    if ($titleMatch.Success) {
        return $titleMatch.Groups['Title'].Value.Trim()
    }

    return $normalizedMessage
}

# Gets recently installed updates from a target computer.
# Win32_QuickFixEngineering is the primary source for report rows.
# Windows Update Client event 19 is used only to improve the update name when its KB matches a QFE record.
function Get-InstalledUpdateRecords {
    param(
        [Parameter(Mandatory)]
        [string]$TargetComputer,

        [Parameter(Mandatory)]
        [datetime]$StartDate
    )

    $records = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $eventTitleByHotFixId = @{}
    $eventQueryError = ''
    $qfeQueryError = ''

    # Read Windows Update Client install-success events from the remote System log.
    # These events often contain the full update title, which QFE may not include.
    try {
        $dmtfStartDate = [Management.ManagementDateTimeConverter]::ToDmtfDateTime($StartDate)
        $eventFilter = "Logfile = 'System' AND SourceName = 'Microsoft-Windows-WindowsUpdateClient' AND EventCode = 19 AND TimeGenerated >= '$dmtfStartDate'"

        foreach ($event in @(Get-WmiObject -Class Win32_NTLogEvent -ComputerName $TargetComputer -Filter $eventFilter -ErrorAction Stop)) {
            $installedDate = [Management.ManagementDateTimeConverter]::ToDateTime($event.TimeGenerated)
            $updateTitle = Get-UpdateTitleFromEventMessage -Message $event.Message

            if ([string]::IsNullOrWhiteSpace($updateTitle)) {
                $updateTitle = 'Windows Update installation event'
            }

            $hotFixIds = @(Get-HotFixIdListFromText -Text $updateTitle)

            foreach ($hotFixId in $hotFixIds) {
                if (-not $eventTitleByHotFixId.ContainsKey($hotFixId)) {
                    $eventTitleByHotFixId[$hotFixId] = $updateTitle
                }
            }
        }
    }
    catch {
        $eventQueryError = $_.Exception.Message
        $warnings.Add("Windows Update event log query failed: $eventQueryError")
    }

    # Read installed KB/hotfix records from QFE. These records control how many update rows appear in the report.
    try {
        foreach ($quickFix in @(Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $TargetComputer -ErrorAction Stop)) {
            $installedDate = ConvertFrom-QfeInstalledOn -InstalledOn $quickFix.InstalledOn

            if ($null -ne $installedDate -and $installedDate -ge $StartDate) {
                $hotFixId = if ([string]::IsNullOrWhiteSpace($quickFix.HotFixID)) {
                    Get-HotFixIdFromText -Text $quickFix.Description
                }
                else {
                    $quickFix.HotFixID.ToUpperInvariant()
                }

                $description = if ([string]::IsNullOrWhiteSpace($quickFix.Description)) {
                    'Quick Fix Engineering record'
                }
                else {
                    $quickFix.Description
                }

                $source = 'Win32_QuickFixEngineering'

                # If the event log had a better title for this KB, use that title but keep this as a QFE row.
                if ($hotFixId -ne 'N/A' -and $eventTitleByHotFixId.ContainsKey($hotFixId)) {
                    $description = $eventTitleByHotFixId[$hotFixId]
                    $source = 'Win32_QuickFixEngineering; WindowsUpdateClient event 19'
                }

                $records.Add([PSCustomObject]@{
                    HotFixID        = $hotFixId
                    Description     = $description
                    InstalledOn     = $quickFix.InstalledOn
                    InstalledOnDate = $installedDate
                    InstalledBy     = $quickFix.InstalledBy
                    Source          = $source
                })
            }
        }
    }
    catch {
        $qfeQueryError = $_.Exception.Message
        $warnings.Add("QuickFixEngineering query failed: $qfeQueryError")
    }

    # If QFE itself failed, stop reporting this computer as successful and return a useful error.
    if ($records.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($qfeQueryError)) {
        $errorMessage = "Unable to query update data. QuickFixEngineering query failed: $qfeQueryError"

        if (-not [string]::IsNullOrWhiteSpace($eventQueryError)) {
            $errorMessage = "$errorMessage. Windows Update event query failed: $eventQueryError"
        }

        throw $errorMessage
    }

    $seenUpdateKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $uniqueRecords = [System.Collections.Generic.List[object]]::new()

    # Remove duplicate QFE records using HotFixID + installed date.
    foreach ($record in @($records | Sort-Object -Property InstalledOnDate -Descending)) {
        $key = if ($record.HotFixID -ne 'N/A') {
            "$($record.HotFixID)|$($record.InstalledOnDate.ToString('yyyy-MM-dd'))"
        }
        else {
            "$($record.Description)|$($record.InstalledOnDate.ToString('yyyy-MM-dd HH:mm:ss'))"
        }

        if ($seenUpdateKeys.Add($key)) {
            $uniqueRecords.Add($record)
        }
    }

    # Return the update list and any non-fatal warning collected during event-log enrichment.
    [PSCustomObject]@{
        Updates = @($uniqueRecords | Sort-Object -Property InstalledOnDate -Descending)
        Warning = (@($warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
    }
}

# Creates a consistent pending-restart object for Yes, No, or Unknown results.
function New-PendingRestartResult {
    param(
        [AllowNull()]
        [object]$IsPending,

        [string[]]$Reasons
    )

    $display = if ($null -eq $IsPending) {
        'Unknown'
    }
    elseif ([bool]$IsPending) {
        'Yes'
    }
    else {
        'No'
    }

    [PSCustomObject]@{
        IsPending = $IsPending
        Display   = $display
        Reasons   = (@($Reasons) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
    }
}

# Checks whether a remote registry key exists by using StdRegProv over WMI/DCOM.
function Test-RemoteRegistryKey {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryProvider,

        [Parameter(Mandatory)]
        [uint32]$Hive,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $result = $RegistryProvider.EnumKey($Hive, $Path)

    switch ([int]$result.ReturnValue) {
        0 { return $true }
        2 { return $false }
        default { throw "Registry key query failed for HKLM\$Path. ReturnValue: $($result.ReturnValue)" }
    }
}

# Reads a remote registry string value by using StdRegProv over WMI/DCOM.
function Get-RemoteRegistryStringValue {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryProvider,

        [Parameter(Mandatory)]
        [uint32]$Hive,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $result = $RegistryProvider.GetStringValue($Hive, $Path, $Name)

    switch ([int]$result.ReturnValue) {
        0 { return $result.sValue }
        2 { return $null }
        default { throw "Registry value query failed for HKLM\$Path\$Name. ReturnValue: $($result.ReturnValue)" }
    }
}

# Reads a remote registry DWORD value by using StdRegProv over WMI/DCOM.
function Get-RemoteRegistryDwordValue {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryProvider,

        [Parameter(Mandatory)]
        [uint32]$Hive,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $result = $RegistryProvider.GetDWORDValue($Hive, $Path, $Name)

    switch ([int]$result.ReturnValue) {
        0 { return $result.uValue }
        2 { return $null }
        default { throw "Registry DWORD query failed for HKLM\$Path\$Name. ReturnValue: $($result.ReturnValue)" }
    }
}

# Reads a remote registry multi-string value by using StdRegProv over WMI/DCOM.
function Get-RemoteRegistryMultiStringValue {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryProvider,

        [Parameter(Mandatory)]
        [uint32]$Hive,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $result = $RegistryProvider.GetMultiStringValue($Hive, $Path, $Name)

    switch ([int]$result.ReturnValue) {
        0 { return @($result.sValue) }
        2 { return @() }
        default { throw "Registry multi-string query failed for HKLM\$Path\$Name. ReturnValue: $($result.ReturnValue)" }
    }
}

# Checks common Windows locations that indicate a reboot is pending.
# This uses WMI/DCOM remote registry access and does not require WinRM.
function Get-PendingRestartState {
    param(
        [Parameter(Mandatory)]
        [string]$TargetComputer
    )

    $hklm = [uint32]2147483650
    $reasons = [System.Collections.Generic.List[string]]::new()

    # StdRegProv lets the script read registry keys remotely through WMI/DCOM.
    $registryProvider = Get-WmiObject -List -Namespace 'root\default' -Class 'StdRegProv' -ComputerName $TargetComputer -ErrorAction Stop

    # Component servicing reboot marker, commonly set after cumulative updates or servicing stack activity.
    if (Test-RemoteRegistryKey -RegistryProvider $registryProvider -Hive $hklm -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('Component Based Servicing reboot pending')
    }

    # Windows Update reboot marker.
    if (Test-RemoteRegistryKey -RegistryProvider $registryProvider -Hive $hklm -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('Windows Update reboot required')
    }

    # Pending file rename operations usually require a restart to complete file replacement or deletion.
    $sessionManagerPath = 'SYSTEM\CurrentControlSet\Control\Session Manager'
    $pendingFileRenames = Get-RemoteRegistryMultiStringValue -RegistryProvider $registryProvider -Hive $hklm -Path $sessionManagerPath -Name 'PendingFileRenameOperations'

    if (@($pendingFileRenames).Count -gt 0) {
        $reasons.Add('Pending file rename operations')
    }

    # Some older update installers leave this value when a reboot is required.
    $updateExeVolatile = Get-RemoteRegistryDwordValue -RegistryProvider $registryProvider -Hive $hklm -Path 'SOFTWARE\Microsoft\Updates' -Name 'UpdateExeVolatile'

    if ($null -ne $updateExeVolatile -and [int]$updateExeVolatile -ne 0) {
        $reasons.Add("UpdateExeVolatile=$updateExeVolatile")
    }

    # A mismatch here means the computer was renamed but has not yet restarted.
    $activeComputerName = Get-RemoteRegistryStringValue -RegistryProvider $registryProvider -Hive $hklm -Path 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName'
    $pendingComputerName = Get-RemoteRegistryStringValue -RegistryProvider $registryProvider -Hive $hklm -Path 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName'

    if (-not [string]::IsNullOrWhiteSpace($activeComputerName) -and
        -not [string]::IsNullOrWhiteSpace($pendingComputerName) -and
        $activeComputerName -ne $pendingComputerName) {
        $reasons.Add("Computer rename pending: $activeComputerName -> $pendingComputerName")
    }

    New-PendingRestartResult -IsPending ($reasons.Count -gt 0) -Reasons $reasons.ToArray()
}

# Builds the list of target domain controllers.
# If -ComputerName is supplied, the script uses that list for testing; otherwise it discovers all DCs automatically.
function Resolve-DomainControllerTargets {
    param(
        [string[]]$ManualComputerName,
        [string]$TargetDomainName
    )

    $targets = [System.Collections.Generic.List[object]]::new()

    if (@($ManualComputerName).Count -gt 0) {
        # Manual mode is useful when testing the report against one or two DCs first.
        foreach ($name in $ManualComputerName) {
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $targets.Add([PSCustomObject]@{
                    ComputerName = $name.Trim()
                    Site         = 'Manual'
                    Domain       = if ($TargetDomainName) { $TargetDomainName } else { 'Manual' }
                })
            }
        }
    }
    else {
        # Preferred discovery path: use the Active Directory PowerShell module.
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $adParams = @{
                Filter      = '*'
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($TargetDomainName)) {
                $adParams['Server'] = $TargetDomainName
            }

            foreach ($domainController in @(Get-ADDomainController @adParams)) {
                $targets.Add([PSCustomObject]@{
                    ComputerName = if ($domainController.HostName) { $domainController.HostName } else { $domainController.Name }
                    Site         = $domainController.Site
                    Domain       = $domainController.Domain
                })
            }
        }
        catch {
            $adModuleError = $_.Exception.Message

            # Fallback discovery path when the ActiveDirectory module is unavailable.
            try {
                if ([string]::IsNullOrWhiteSpace($TargetDomainName)) {
                    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                }
                else {
                    $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList 'Domain', $TargetDomainName
                    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                }

                foreach ($domainController in $domain.DomainControllers) {
                    $targets.Add([PSCustomObject]@{
                        ComputerName = $domainController.Name
                        Site         = $domainController.SiteName
                        Domain       = $domain.Name
                    })
                }
            }
            catch {
                throw "Unable to discover domain controllers. ActiveDirectory module error: $adModuleError. DirectoryServices fallback error: $($_.Exception.Message). You can bypass discovery with -ComputerName DC01,DC02."
            }
        }
    }

    $uniqueTargets = @(
        # Remove duplicate computer names if both discovery methods or AD data return repeated entries.
        $targets |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.ComputerName) } |
            Group-Object -Property ComputerName |
            ForEach-Object { $_.Group[0] } |
            Sort-Object -Property ComputerName
    )

    if ($uniqueTargets.Count -eq 0) {
        throw 'No target domain controllers were discovered or provided.'
    }

    return $uniqueTargets
}

# Calculate the report time window. Only updates installed on or after $startDate are included.
$generatedOn = Get-Date
$startDate = $generatedOn.AddDays(-1 * $DaysBack)

# Discover the DC list or use the manually supplied -ComputerName list.
Write-Host "Discovering target domain controllers..."
$targets = Resolve-DomainControllerTargets -ManualComputerName $ComputerName -TargetDomainName $DomainName
Write-Host "Found $($targets.Count) target computer(s). Collecting updates installed since $($startDate.ToString('yyyy-MM-dd HH:mm:ss'))..."

# Query each DC and create one or more report rows for that DC.
$results = foreach ($target in $targets) {
    $server = $target.ComputerName
    $lastRestart = 'N/A'
    $pendingRestart = New-PendingRestartResult -IsPending $null -Reasons @('Not checked')
    $pendingRestartError = ''

    Write-Host "Querying $server..."

    try {
        # Get OS details first. This proves WMI/DCOM connectivity and gives the last boot time.
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $server -ErrorAction Stop
        $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.LastBootUpTime)
        $lastRestart = ConvertTo-ReportDate -Value $lastBoot

        # Check whether this DC has any pending reboot indicators.
        try {
            $pendingRestart = Get-PendingRestartState -TargetComputer $server
        }
        catch {
            $pendingRestart = New-PendingRestartResult -IsPending $null -Reasons @("Pending restart check failed: $($_.Exception.Message)")
            $pendingRestartError = "Pending restart check failed: $($_.Exception.Message)"
        }

        # Collect update records for this DC and combine non-fatal warnings into the ErrorMessage column.
        $updateQuery = Get-InstalledUpdateRecords -TargetComputer $server -StartDate $startDate
        $recentUpdates = @($updateQuery.Updates)
        $queryWarnings = @(
            $pendingRestartError
            $updateQuery.Warning
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $queryWarningText = $queryWarnings -join '; '

        if ($recentUpdates.Count -eq 0) {
            # No updates in the selected time window is reported as its own row.
            [PSCustomObject]@{
                ComputerName          = $server
                Site                  = $target.Site
                Domain                = $target.Domain
                Status                = 'No Recent Updates'
                HotFixID              = 'N/A'
                Description           = "No updates found in the last $DaysBack day(s)"
                Source                = 'N/A'
                InstalledOn           = 'N/A'
                InstalledBy           = 'N/A'
                LastRestart           = $lastRestart
                PendingRestart        = $pendingRestart.Display
                PendingRestartReasons = $pendingRestart.Reasons
                ErrorMessage          = $queryWarningText
            }
        }
        else {
            # Create one row per installed update found in the selected time window.
            foreach ($update in $recentUpdates) {
                [PSCustomObject]@{
                    ComputerName          = $server
                    Site                  = $target.Site
                    Domain                = $target.Domain
                    Status                = if ($pendingRestart.Display -eq 'Yes') { 'Installed - Restart Pending' } else { 'Installed' }
                    HotFixID              = $update.HotFixID
                    Description           = $update.Description
                    Source                = $update.Source
                    InstalledOn           = ConvertTo-ReportDate -Value $update.InstalledOnDate
                    InstalledBy           = $update.InstalledBy
                    LastRestart           = $lastRestart
                    PendingRestart        = $pendingRestart.Display
                    PendingRestartReasons = $pendingRestart.Reasons
                    ErrorMessage          = $queryWarningText
                }
            }
        }
    }
    catch {
        # If the DC cannot be queried, still add a row so the failure appears in the report.
        [PSCustomObject]@{
            ComputerName          = $server
            Site                  = $target.Site
            Domain                = $target.Domain
            Status                = 'Failed'
            HotFixID              = 'N/A'
            Description           = 'Unable to connect or query update data'
            Source                = 'N/A'
            InstalledOn           = 'N/A'
            InstalledBy           = 'N/A'
            LastRestart           = $lastRestart
            PendingRestart        = $pendingRestart.Display
            PendingRestartReasons = $pendingRestart.Reasons
            ErrorMessage          = $_.Exception.Message
        }
    }
}

# Summary counters used at the top of the HTML report.
$failedComputers = @($results | Where-Object { $_.Status -eq 'Failed' } | Select-Object -ExpandProperty ComputerName -Unique)
$pendingRestartComputers = @($results | Where-Object { $_.PendingRestart -eq 'Yes' } | Select-Object -ExpandProperty ComputerName -Unique)
$recentUpdateRows = @($results | Where-Object { $_.Status -like 'Installed*' })
$noRecentUpdateComputers = @($results | Where-Object { $_.Status -eq 'No Recent Updates' } | Select-Object -ExpandProperty ComputerName -Unique)

# CSS controls the color coding:
# green = installed, red = failed, yellow = pending restart, gray = no recent updates.
$HtmlStyle = @"
<style>
body {
    font-family: Arial, sans-serif;
    font-size: 13px;
}
h1 {
    color: #2f5597;
}
.summary {
    margin: 10px 0 16px 0;
}
.summary span {
    display: inline-block;
    margin: 0 12px 8px 0;
    padding: 6px 10px;
    border: 1px solid #ddd;
    background-color: #f7f7f7;
}
table {
    border-collapse: collapse;
    width: 100%;
}
th {
    background-color: #2f5597;
    color: white;
    padding: 8px;
    border: 1px solid #ddd;
    text-align: left;
}
td {
    padding: 8px;
    border: 1px solid #ddd;
    vertical-align: top;
}
tr.installed {
    background-color: #d9ead3;
}
tr.failed {
    background-color: #f4cccc;
}
tr.pending {
    background-color: #fff2cc;
}
tr.noupdates {
    background-color: #eeeeee;
}
</style>
"@

# Convert each result object into an HTML table row.
# Values are HTML-encoded before being inserted into the page.
$rows = foreach ($item in $results) {
    $class = if ($item.Status -eq 'Failed') {
        'failed'
    }
    elseif ($item.PendingRestart -eq 'Yes') {
        'pending'
    }
    elseif ($item.Status -eq 'No Recent Updates') {
        'noupdates'
    }
    else {
        'installed'
    }

    $computerNameHtml = ConvertTo-HtmlText -Value $item.ComputerName
    $siteHtml = ConvertTo-HtmlText -Value $item.Site
    $domainHtml = ConvertTo-HtmlText -Value $item.Domain
    $statusHtml = ConvertTo-HtmlText -Value $item.Status
    $hotFixHtml = ConvertTo-HtmlText -Value $item.HotFixID
    $descriptionHtml = ConvertTo-HtmlText -Value $item.Description
    $sourceHtml = ConvertTo-HtmlText -Value $item.Source
    $installedOnHtml = ConvertTo-HtmlText -Value $item.InstalledOn
    $installedByHtml = ConvertTo-HtmlText -Value $item.InstalledBy
    $lastRestartHtml = ConvertTo-HtmlText -Value $item.LastRestart
    $pendingRestartHtml = ConvertTo-HtmlText -Value $item.PendingRestart
    $pendingReasonHtml = ConvertTo-HtmlText -Value $item.PendingRestartReasons
    $errorMessageHtml = ConvertTo-HtmlText -Value $item.ErrorMessage

@"
<tr class="$class">
<td>$computerNameHtml</td>
<td>$siteHtml</td>
<td>$domainHtml</td>
<td>$statusHtml</td>
<td>$hotFixHtml</td>
<td>$descriptionHtml</td>
<td>$sourceHtml</td>
<td>$installedOnHtml</td>
<td>$installedByHtml</td>
<td>$lastRestartHtml</td>
<td>$pendingRestartHtml</td>
<td>$pendingReasonHtml</td>
<td>$errorMessageHtml</td>
</tr>
"@
}

$rowsHtml = $rows -join [Environment]::NewLine

# Build the final HTML document with a summary section and detailed update table.
$HtmlReport = @"
<html>
<head>
<title>Domain Controller Windows Update Report</title>
$HtmlStyle
</head>
<body>
<h1>Domain Controller Windows Update Report</h1>
<p>Generated on: $(ConvertTo-HtmlText -Value $generatedOn)</p>
<p>Update lookback window: last $DaysBack day(s), starting $(ConvertTo-HtmlText -Value (ConvertTo-ReportDate -Value $startDate))</p>

<div class="summary">
<span>Total computers: $($targets.Count)</span>
<span>Recent update rows: $($recentUpdateRows.Count)</span>
<span>Pending restart computers: $($pendingRestartComputers.Count)</span>
<span>No recent updates: $($noRecentUpdateComputers.Count)</span>
<span>Failed computers: $($failedComputers.Count)</span>
</div>

<table>
<tr>
<th>Computer Name</th>
<th>Site</th>
<th>Domain</th>
<th>Status</th>
<th>Update / HotFix ID</th>
<th>Update Name / Description</th>
<th>Source</th>
<th>Installed On</th>
<th>Installed By</th>
<th>Last Restart</th>
<th>Pending Restart</th>
<th>Pending Restart Reason</th>
<th>Error Message</th>
</tr>
$rowsHtml
</table>

</body>
</html>
"@

# Create the report folder if it does not exist.
$folder = Split-Path -Path $ReportPath -Parent
if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

# Write the HTML report to disk.
$HtmlReport | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "Report created: $ReportPath"

# Optionally email the HTML body and attach the saved report file.
if ($SendEmail -eq $true) {
    try {
        Send-MailMessage `
            -From $From `
            -To $To `
            -Subject $Subject `
            -Body $HtmlReport `
            -BodyAsHtml `
            -SmtpServer $SmtpServer `
            -Port $SmtpPort `
            -Attachments $ReportPath `
            -ErrorAction Stop

        Write-Host "Email sent to: $($To -join ', ')"
    }
    catch {
        Write-Warning "Report was created, but email failed: $($_.Exception.Message)"
    }
}
