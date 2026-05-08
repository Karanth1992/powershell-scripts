<#
.SYNOPSIS
    Builds an Active Directory architecture inventory and issue report.

.DESCRIPTION
    Collects domain, forest, domain-controller, user, computer, group, OU,
    site, subnet, site-link, replication, GPO, port, and service posture data.

    The script is intentionally read-only. It does not disable services,
    change firewall rules, modify AD objects, or change WSUS configuration.

    Port checks are TCP reachability checks from the machine running this
    script to each domain controller. They are not a full vulnerability scan
    and they do not test UDP or the full dynamic RPC range.

    Service checks use WMI/DCOM through Get-WmiObject, not WinRM.

.PARAMETER DomainName
    Optional AD DNS domain name. If omitted, the current logon domain is used.

.PARAMETER DomainController
    Optional domain controller to query for AD data.
    If omitted, the script uses the domain PDC emulator.

.PARAMETER OutputFolder
    Folder where the HTML, JSON, and CSV output files are created.

.PARAMETER StaleUserDays
    Enabled user accounts with LastLogonDate older than this value are flagged.
    Accounts with no LastLogonDate are also counted as stale.

.PARAMETER StaleComputerDays
    Enabled computer accounts with LastLogonDate older than this value are flagged.
    Computer accounts with no LastLogonDate are also counted as stale.

.PARAMETER TcpPortsToTest
    TCP ports tested on each domain controller. The defaults cover common
    AD, DNS, LDAP, Kerberos, ADWS, WinRM, and WSUS-related ports.

.PARAMETER PortTimeoutMs
    Timeout per TCP connection attempt.

.PARAMETER SkipPortChecks
    Skips TCP port reachability testing.

.PARAMETER SkipServiceChecks
    Skips WMI/DCOM service posture checks on each domain controller.

.PARAMETER IncludeGpoScan
    Performs a deeper GPO XML scan to identify GPOs that appear to configure
    WSUS or Windows Update client policy. This can take longer in large domains.

.EXAMPLE
    .\Get-ADArchitectureAssessment.ps1

.EXAMPLE
    .\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com"

.EXAMPLE
    .\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com" -DomainController "DC01.corp.contoso.com"

.EXAMPLE
    .\Get-ADArchitectureAssessment.ps1 -OutputFolder "D:\Reports\ADAssessment" -StaleUserDays 120 -StaleComputerDays 120

.NOTES
    Requires:
    - Windows PowerShell 5.1
    - ActiveDirectory PowerShell module
    - GroupPolicy PowerShell module for GPO summary/deep WSUS GPO scan
    - WMI/DCOM and administrator rights on DCs for remote service checks
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DomainName,

    [string]$DomainController,

    [string]$OutputFolder = 'C:\Temp\ADArchitectureAssessment',

    [ValidateRange(1, 3650)]
    [int]$StaleUserDays = 90,

    [ValidateRange(1, 3650)]
    [int]$StaleComputerDays = 90,

    [ValidateRange(1, 65535)]
    [int[]]$TcpPortsToTest = @(53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5985, 5986, 8530, 8531, 9389),

    [ValidateRange(100, 30000)]
    [int]$PortTimeoutMs = 1000,

    [switch]$SkipPortChecks,

    [switch]$SkipServiceChecks,

    [switch]$IncludeGpoScan
)

$ErrorActionPreference = 'Stop'
$script:ScriptVersion = '1.6'
$script:Findings = New-Object System.Collections.ArrayList
$script:CollectionWarnings = New-Object System.Collections.ArrayList
$script:QueryServer = $null

trap {
    Write-Host ''
    Write-Host 'AD architecture assessment failed.' -ForegroundColor Red
    Write-Host ("Script version : {0}" -f $script:ScriptVersion)
    Write-Host ("Error message  : {0}" -f $_.Exception.Message)
    Write-Host ("Error type     : {0}" -f $_.Exception.GetType().FullName)

    if ($_.InvocationInfo) {
        Write-Host ("Script name    : {0}" -f $_.InvocationInfo.ScriptName)
        Write-Host ("Line number    : {0}" -f $_.InvocationInfo.ScriptLineNumber)
        Write-Host ("Line text      : {0}" -f $_.InvocationInfo.Line)
        Write-Host ("Position       : {0}" -f $_.InvocationInfo.PositionMessage)
    }

    if ($_.ScriptStackTrace) {
        Write-Host 'Script stack trace:'
        Write-Host $_.ScriptStackTrace
    }

    Write-Host ''
    Write-Host 'Full error record:'
    $_ | Format-List * -Force
    break
}

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Area,

        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [Parameter(Mandatory = $true)]
        [string]$Finding,

        [string]$Evidence,

        [string]$Recommendation
    )

    $null = $script:Findings.Add([pscustomobject]@{
        Severity       = $Severity
        Area           = $Area
        ObjectName     = $ObjectName
        Finding        = $Finding
        Evidence       = $Evidence
        Recommendation = $Recommendation
    })
}

function Add-CollectionWarning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Area,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $null = $script:CollectionWarnings.Add([pscustomobject]@{
        Area    = $Area
        Warning = $Message
    })

    Write-Warning ("{0}: {1}" -f $Area, $Message)
}

function ConvertTo-HtmlText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [datetime]) {
        return [System.Net.WebUtility]::HtmlEncode($Value.ToString('yyyy-MM-dd HH:mm:ss'))
    }

    if ($Value -is [array]) {
        $Value = ($Value | ForEach-Object { [string]$_ }) -join ', '
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-FirstValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        try {
            foreach ($item in $Value) {
                return $item
            }
        }
        catch {
            try {
                return $Value[0]
            }
            catch {
                try {
                    return (($Value | Out-String) -replace '\s+$', '')
                }
                catch {
                    return $null
                }
            }
        }

        return $null
    }

    return $Value
}

function ConvertTo-SafeString {
    param(
        [AllowNull()]
        [object]$Value
    )

    $firstValue = Get-FirstValue -Value $Value

    if ($null -eq $firstValue) {
        return ''
    }

    try {
        return [string]$firstValue
    }
    catch {
        return (($firstValue | Out-String) -replace '\s+$', '')
    }
}

function ConvertTo-SafeBoolean {
    param(
        [AllowNull()]
        [object]$Value
    )

    $firstValue = Get-FirstValue -Value $Value

    if ($null -eq $firstValue) {
        return $false
    }

    if ($firstValue -is [bool]) {
        return $firstValue
    }

    try {
        return [System.Convert]::ToBoolean($firstValue)
    }
    catch {
        return $false
    }
}

function ConvertTo-SafeDateTime {
    param(
        [AllowNull()]
        [object]$Value
    )

    $firstValue = Get-FirstValue -Value $Value

    if ($null -eq $firstValue) {
        return $null
    }

    if ($firstValue -is [datetime]) {
        return $firstValue
    }

    try {
        return [datetime]$firstValue
    }
    catch {
        return $null
    }
}

function ConvertTo-SafeInt64 {
    param(
        [AllowNull()]
        [object]$Value,

        [int64]$DefaultValue = 0
    )

    $firstValue = Get-FirstValue -Value $Value

    if ($null -eq $firstValue) {
        return $DefaultValue
    }

    try {
        return [int64]$firstValue
    }
    catch {
        return $DefaultValue
    }
}

function Join-SafeValues {
    param(
        [AllowNull()]
        [object]$Value,

        [string]$Separator = ', '
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | ForEach-Object { ConvertTo-SafeString $_ }) -join $Separator)
    }

    return (ConvertTo-SafeString $Value)
}

function ConvertTo-HtmlTable {
    param(
        [AllowNull()]
        [object[]]$Data,

        [string[]]$Properties,

        [string]$EmptyMessage = 'No data collected.'
    )

    $rows = @($Data)
    if ($rows.Count -eq 0) {
        return "<p class='muted'>$([System.Net.WebUtility]::HtmlEncode($EmptyMessage))</p>"
    }

    if (-not $Properties -or $Properties.Count -eq 0) {
        $Properties = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
    }

    $html = New-Object System.Text.StringBuilder
    $null = $html.AppendLine('<table>')
    $null = $html.AppendLine('<thead><tr>')

    foreach ($property in $Properties) {
        $null = $html.AppendLine(("<th>{0}</th>" -f (ConvertTo-HtmlText $property)))
    }

    $null = $html.AppendLine('</tr></thead>')
    $null = $html.AppendLine('<tbody>')

    foreach ($row in $rows) {
        $rowClass = ''
        $severityProperty = $row.PSObject.Properties | Where-Object { $_.Name -eq 'Severity' } | Select-Object -First 1
        if ($severityProperty -and $severityProperty.Value) {
            $rowClass = " class='sev-$(([string]$severityProperty.Value).ToLowerInvariant())'"
        }

        $null = $html.AppendLine("<tr$rowClass>")

        foreach ($property in $Properties) {
            $valueProperty = $row.PSObject.Properties | Where-Object { $_.Name -eq $property } | Select-Object -First 1
            $value = if ($valueProperty) { $valueProperty.Value } else { $null }
            $null = $html.AppendLine(("<td>{0}</td>" -f (ConvertTo-HtmlText $value)))
        }

        $null = $html.AppendLine('</tr>')
    }

    $null = $html.AppendLine('</tbody></table>')
    return $html.ToString()
}

function Get-SeverityRank {
    param(
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 1 }
        'High'     { return 2 }
        'Medium'   { return 3 }
        'Low'      { return 4 }
        'Info'     { return 5 }
        default    { return 99 }
    }
}

function Get-FindingExecutiveCategory {
    param(
        [AllowNull()]
        [string]$Area,

        [AllowNull()]
        [string]$Severity
    )

    $areaText = if ($Area) { $Area } else { '' }

    switch -Regex ($areaText) {
        '^(Domain Controllers|Global Catalog|FSMO|Forest Recovery|Domain Functional Level|Forest Functional Level|SYSVOL Replication|DC Port Reachability)$' {
            return 'Critical architecture risks'
        }

        '^(Account Policy|Privileged Accounts|Privileged Groups|DC Services|Legacy Protocols|WSUS Role Separation)$' {
            return 'Security hardening items'
        }

        '^(AD Sites|AD Site Links|Replication|DNS)$' {
            return 'AD topology/replication issues'
        }

        '^(User Accounts|Computer Accounts|OU Design|Group Design|GPO Hygiene)$' {
            return 'Cleanup/hygiene tasks'
        }

        default {
            if ($Severity -in @('Critical', 'High')) {
                return 'Critical architecture risks'
            }

            return 'Cleanup/hygiene tasks'
        }
    }
}

function Get-ParentDn {
    param(
        [AllowNull()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return ''
    }

    $parts = @($DistinguishedName -split '(?<!\\),')
    if ($parts.Count -le 1) {
        return ''
    }

    return ($parts | Select-Object -Skip 1) -join ','
}

function ConvertFrom-EscapedDnValue {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return (($Value -replace '\\,', ',') -replace '\\\\', '\')
}

function Convert-DnToReadablePath {
    param(
        [AllowNull()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return ''
    }

    $parts = @($DistinguishedName -split '(?<!\\),')
    $domainParts = New-Object 'System.Collections.Generic.List[string]'
    $containerParts = New-Object 'System.Collections.Generic.List[string]'

    foreach ($part in $parts) {
        if ($part -match '^DC=(.+)$') {
            $null = $domainParts.Add((ConvertFrom-EscapedDnValue $matches[1]))
        }
        elseif ($part -match '^(OU|CN)=(.+)$') {
            $null = $containerParts.Add(("{0}={1}" -f $matches[1], (ConvertFrom-EscapedDnValue $matches[2])))
        }
    }

    $domainPath = ($domainParts | ForEach-Object { $_ }) -join '.'
    $containers = @($containerParts | ForEach-Object { $_ })

    if ($containers.Count -gt 0) {
        [array]::Reverse($containers)
        if ([string]::IsNullOrWhiteSpace($domainPath)) {
            return ($containers -join '/')
        }

        return ("{0}/{1}" -f $domainPath, ($containers -join '/'))
    }

    return $domainPath
}

function Get-RdnNameFromDn {
    param(
        [AllowNull()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return ''
    }

    if ($DistinguishedName -match '^[^=]+=([^,]+)') {
        return (ConvertFrom-EscapedDnValue $matches[1])
    }

    return $DistinguishedName
}

function Get-SiteNameFromServerReference {
    param(
        [AllowNull()]
        [object]$ServerReference
    )

    $serverReferenceText = ConvertTo-SafeString $ServerReference

    if ([string]::IsNullOrWhiteSpace($serverReferenceText)) {
        return ''
    }

    if ($serverReferenceText -match ',CN=Servers,CN=([^,]+),CN=Sites,') {
        return (ConvertFrom-EscapedDnValue $matches[1])
    }

    return ''
}

function Convert-GuidToKey {
    param(
        [AllowNull()]
        [object]$Guid
    )

    if ($null -eq $Guid) {
        return ''
    }

    try {
        return ([guid]$Guid).ToString().ToLowerInvariant()
    }
    catch {
        return ([string]$Guid).Trim('{}').ToLowerInvariant()
    }
}

function Get-GuidFromGpLink {
    param(
        [AllowNull()]
        [string]$GpLink
    )

    if ([string]::IsNullOrWhiteSpace($GpLink)) {
        return @()
    }

    return [regex]::Matches($GpLink, '\{[0-9A-Fa-f-]{36}\}') |
        ForEach-Object { $_.Value.Trim('{}').ToLowerInvariant() }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateRange(100, 30000)]
        [int]$TimeoutMs = 1000
    )

    $started = Get-Date
    $client = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null

    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $connected) {
            return [pscustomobject]@{
                ComputerName = $ComputerName
                Port         = $Port
                Open         = $false
                Status       = 'ClosedOrFiltered'
                ResponseMs   = $null
                Error        = 'Connection timed out'
            }
        }

        $client.EndConnect($asyncResult)
        $elapsedMs = [int]((Get-Date) - $started).TotalMilliseconds

        return [pscustomobject]@{
            ComputerName = $ComputerName
            Port         = $Port
            Open         = $true
            Status       = 'Open'
            ResponseMs   = $elapsedMs
            Error        = ''
        }
    }
    catch {
        return [pscustomobject]@{
            ComputerName = $ComputerName
            Port         = $Port
            Open         = $false
            Status       = 'ClosedOrFiltered'
            ResponseMs   = $null
            Error        = $_.Exception.Message
        }
    }
    finally {
        if ($asyncResult -and $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }

        if ($client) {
            $client.Close()
        }
    }
}

function Export-CsvIfData {
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @($Data)
    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

$portPurpose = @{
    '53'   = 'DNS'
    '88'   = 'Kerberos'
    '135'  = 'RPC Endpoint Mapper'
    '139'  = 'NetBIOS Session Service'
    '389'  = 'LDAP'
    '445'  = 'SMB/SYSVOL/NETLOGON'
    '464'  = 'Kerberos Password Change'
    '636'  = 'LDAPS'
    '3268' = 'Global Catalog LDAP'
    '3269' = 'Global Catalog LDAPS'
    '5985' = 'WinRM HTTP'
    '5986' = 'WinRM HTTPS'
    '8530' = 'WSUS HTTP'
    '8531' = 'WSUS HTTPS'
    '9389' = 'Active Directory Web Services'
}

$serviceGuidance = @{
    'NTDS'           = 'Required on writable and read-only domain controllers'
    'Netlogon'       = 'Required for domain logon and secure channel processing'
    'Kdc'            = 'Required for Kerberos authentication on domain controllers'
    'W32Time'        = 'Required for domain time hierarchy'
    'ADWS'           = 'Required for modern AD PowerShell and management tools'
    'RPCSS'          = 'Required Windows RPC service'
    'DFSR'           = 'Expected for DFSR-based SYSVOL replication'
    'NtFrs'          = 'Legacy FRS-based SYSVOL replication; should be reviewed'
    'DNS'            = 'Expected when the domain controller also hosts AD-integrated DNS'
    'Spooler'        = 'Should normally be disabled on domain controllers unless explicitly required'
    'RemoteRegistry' = 'Should normally be disabled unless a documented management tool requires it'
    'W3SVC'          = 'IIS on a domain controller should be reviewed'
    'WsusService'    = 'WSUS on a domain controller should be avoided in most architectures'
    'SNMP'           = 'SNMP on a domain controller should be reviewed'
    'TlntSvr'        = 'Telnet should not be enabled on a domain controller'
    'Fax'            = 'Fax service is not expected on a domain controller'
    'Browser'        = 'Computer Browser is legacy and should not normally be used'
    'TermService'    = 'RDP may be operationally required but should be tightly controlled'
}

$runStarted = Get-Date
$timestamp = $runStarted.ToString('yyyyMMdd_HHmmss')
$runFolder = Join-Path $OutputFolder ("ADArchitectureAssessment_{0}" -f $timestamp)

New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

Write-Step ("Script version {0}" -f $script:ScriptVersion)
if ($PSCommandPath) {
    Write-Step ("Running file {0}" -f $PSCommandPath)
}

Write-Step "Importing ActiveDirectory module"
Import-Module ActiveDirectory -ErrorAction Stop

$groupPolicyAvailable = $false
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $groupPolicyAvailable = $true
}
catch {
    Add-CollectionWarning -Area 'GPO' -Message "GroupPolicy module was not available. GPO summary and WSUS GPO scan were skipped. $($_.Exception.Message)"
}

$dnsServerModuleAvailable = $false
try {
    Import-Module DnsServer -ErrorAction Stop
    $dnsServerModuleAvailable = $true
}
catch {
    Add-CollectionWarning -Area 'DNS' -Message "DnsServer module was not available. DNS zone and forwarder inventory were skipped. $($_.Exception.Message)"
}

Write-Step "Resolving domain and query domain controller"
if ($DomainName) {
    if ($DomainController) {
        $domain = Get-ADDomain -Identity $DomainName -Server $DomainController
    }
    else {
        $domain = Get-ADDomain -Identity $DomainName
    }
}
else {
    if ($DomainController) {
        $domain = Get-ADDomain -Server $DomainController
    }
    else {
        $domain = Get-ADDomain
    }
}

if ($DomainController) {
    $script:QueryServer = $DomainController
}
else {
    $script:QueryServer = ConvertTo-SafeString $domain.PDCEmulator
}

$domain = Get-ADDomain -Identity $domain.DNSRoot -Server $script:QueryServer
$forest = Get-ADForest -Identity $domain.Forest -Server $script:QueryServer
$rootDse = Get-ADRootDSE -Server $script:QueryServer

Write-Step "Collecting domain and forest summary"
$domainSummary = [pscustomobject]@{
    RunStarted              = $runStarted
    DomainDnsName           = ConvertTo-SafeString $domain.DNSRoot
    DomainNetBIOSName       = ConvertTo-SafeString $domain.NetBIOSName
    ForestName              = ConvertTo-SafeString $forest.Name
    DomainMode              = ConvertTo-SafeString $domain.DomainMode
    ForestMode              = ConvertTo-SafeString $forest.ForestMode
    QueryServer             = $script:QueryServer
    PDCEmulator             = ConvertTo-SafeString $domain.PDCEmulator
    RIDMaster               = ConvertTo-SafeString $domain.RIDMaster
    InfrastructureMaster    = ConvertTo-SafeString $domain.InfrastructureMaster
    SchemaMaster            = ConvertTo-SafeString $forest.SchemaMaster
    DomainNamingMaster      = ConvertTo-SafeString $forest.DomainNamingMaster
    RootDomain              = ConvertTo-SafeString $forest.RootDomain
    ChildDomains            = Join-SafeValues $forest.Domains
    GlobalCatalogs          = Join-SafeValues $forest.GlobalCatalogs
    SitesListedByForest     = Join-SafeValues $forest.Sites
    RecycleBinEnabled       = 'Unknown'
    TombstoneLifetimeDays   = 'Unknown'
    DefaultMinPasswordAge   = ''
    DefaultMaxPasswordAge   = ''
    DefaultMinPasswordLength = ''
    DefaultLockoutThreshold = ''
}

$legacyDomainModes = @('Windows2000Domain', 'Windows2003InterimDomain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain')
$legacyForestModes = @('Windows2000Forest', 'Windows2003InterimForest', 'Windows2003Forest', 'Windows2008Forest', 'Windows2008R2Forest')

if ((ConvertTo-SafeString $domain.DomainMode) -in $legacyDomainModes) {
    Add-Finding -Severity 'Medium' -Area 'Domain Functional Level' -ObjectName $domain.DNSRoot -Finding 'Domain functional level is legacy.' -Evidence "DomainMode is $($domain.DomainMode)." -Recommendation 'Review application compatibility and plan a functional-level uplift after validating all domain controllers and dependent applications.'
}

if ((ConvertTo-SafeString $forest.ForestMode) -in $legacyForestModes) {
    Add-Finding -Severity 'Medium' -Area 'Forest Functional Level' -ObjectName $forest.Name -Finding 'Forest functional level is legacy.' -Evidence "ForestMode is $($forest.ForestMode)." -Recommendation 'Review forest-wide compatibility and plan a functional-level uplift after validating all domains and applications.'
}

try {
    $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes -Server $script:QueryServer
    $recycleBinEnabled = @($recycleBinFeature.EnabledScopes).Count -gt 0
    $domainSummary.RecycleBinEnabled = $recycleBinEnabled

    if (-not $recycleBinEnabled) {
        Add-Finding -Severity 'Medium' -Area 'Forest Recovery' -ObjectName $forest.Name -Finding 'Active Directory Recycle Bin is not enabled.' -Evidence 'EnabledScopes is empty for the Recycle Bin optional feature.' -Recommendation 'Enable AD Recycle Bin after confirming forest readiness and recovery procedures.'
    }
}
catch {
    Add-CollectionWarning -Area 'Forest Recovery' -Message "Could not determine AD Recycle Bin status. $($_.Exception.Message)"
}

try {
    $directoryServiceObject = Get-ADObject -Identity ("CN=Directory Service,CN=Windows NT,CN=Services,{0}" -f $rootDse.configurationNamingContext) -Properties tombstoneLifetime -Server $script:QueryServer
    $tombstoneLifetime = $directoryServiceObject.tombstoneLifetime
    if ($null -eq $tombstoneLifetime) {
        $tombstoneLifetime = 180
    }

    $domainSummary.TombstoneLifetimeDays = $tombstoneLifetime

    if ([int]$tombstoneLifetime -lt 180) {
        Add-Finding -Severity 'Low' -Area 'Forest Recovery' -ObjectName $forest.Name -Finding 'Tombstone lifetime is lower than the commonly used 180-day value.' -Evidence "tombstoneLifetime is $tombstoneLifetime days." -Recommendation 'Review backup retention, replication outage tolerance, and authoritative restore requirements before changing this value.'
    }
}
catch {
    Add-CollectionWarning -Area 'Forest Recovery' -Message "Could not determine tombstone lifetime. $($_.Exception.Message)"
}

try {
    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $script:QueryServer
    $domainSummary.DefaultMinPasswordAge = ConvertTo-SafeString $passwordPolicy.MinPasswordAge
    $domainSummary.DefaultMaxPasswordAge = ConvertTo-SafeString $passwordPolicy.MaxPasswordAge
    $domainSummary.DefaultMinPasswordLength = $passwordPolicy.MinPasswordLength
    $domainSummary.DefaultLockoutThreshold = $passwordPolicy.LockoutThreshold

    if ($passwordPolicy.MinPasswordLength -lt 12) {
        Add-Finding -Severity 'Medium' -Area 'Account Policy' -ObjectName $domain.DNSRoot -Finding 'Default minimum password length is below 12 characters.' -Evidence "MinPasswordLength is $($passwordPolicy.MinPasswordLength)." -Recommendation 'Review the password policy against current enterprise standards and compensating controls such as MFA and banned-password filtering.'
    }

    if ($passwordPolicy.LockoutThreshold -eq 0) {
        Add-Finding -Severity 'Medium' -Area 'Account Policy' -ObjectName $domain.DNSRoot -Finding 'Account lockout threshold is not configured.' -Evidence 'LockoutThreshold is 0.' -Recommendation 'Review whether a lockout policy is required for the domain and align it with helpdesk and security monitoring processes.'
    }
}
catch {
    Add-CollectionWarning -Area 'Account Policy' -Message "Could not collect default domain password policy. $($_.Exception.Message)"
}

Write-Step "Collecting domain controller inventory"
$dcInventory = New-Object System.Collections.ArrayList
$fsmoRoleMap = [ordered]@{
    PDCEmulator          = ConvertTo-SafeString $domain.PDCEmulator
    RIDMaster            = ConvertTo-SafeString $domain.RIDMaster
    InfrastructureMaster = ConvertTo-SafeString $domain.InfrastructureMaster
    SchemaMaster         = ConvertTo-SafeString $forest.SchemaMaster
    DomainNamingMaster   = ConvertTo-SafeString $forest.DomainNamingMaster
}

$domainControllers = @()
try {
    $dcComputerObjects = @(
        Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=8192)' `
            -Properties DNSHostName, OperatingSystem, OperatingSystemVersion, LastLogonDate, PasswordLastSet, Enabled, IPv4Address, serverReferenceBL, userAccountControl, primaryGroupID `
            -ResultPageSize 1000 `
            -Server $script:QueryServer `
            -ErrorAction Stop
    )

    $domainControllers = @(
        foreach ($dcComputerObject in $dcComputerObjects) {
            $dcComputerName = ConvertTo-SafeString $dcComputerObject.Name
            $dcHostName = ConvertTo-SafeString $dcComputerObject.DNSHostName
            $serverReference = ConvertTo-SafeString $dcComputerObject.serverReferenceBL
            $ntdsOptions = 0

            if ([string]::IsNullOrWhiteSpace($dcHostName)) {
                $dcHostName = "{0}.{1}" -f $dcComputerName, (ConvertTo-SafeString $domain.DNSRoot)
            }

            if (-not [string]::IsNullOrWhiteSpace($serverReference)) {
                try {
                    $ntdsSettings = Get-ADObject -SearchBase $serverReference -LDAPFilter '(objectClass=nTDSDSA)' -SearchScope OneLevel -Properties options -Server $script:QueryServer -ErrorAction Stop | Select-Object -First 1
                    $ntdsOptions = ConvertTo-SafeInt64 $ntdsSettings.options
                }
                catch {
                    Add-CollectionWarning -Area 'Domain Controllers' -Message "Could not collect NTDS Settings options for $dcHostName. $($_.Exception.Message)"
                }
            }

            $userAccountControl = ConvertTo-SafeInt64 $dcComputerObject.userAccountControl
            $primaryGroupId = ConvertTo-SafeInt64 $dcComputerObject.primaryGroupID
            $isReadOnlyDc = (($userAccountControl -band 67108864) -ne 0) -or ($primaryGroupId -eq 521)
            $isGlobalCatalog = (($ntdsOptions -band 1) -ne 0)
            $operationMasterRoles = New-Object 'System.Collections.Generic.List[string]'

            foreach ($roleName in $fsmoRoleMap.Keys) {
                $roleHolder = $fsmoRoleMap[$roleName]
                if (-not [string]::IsNullOrWhiteSpace($roleHolder)) {
                    $roleHolderShort = ($roleHolder -split '\.')[0]

                    if (($roleHolder -ieq $dcHostName) -or ($roleHolder -ieq $dcComputerName) -or ($roleHolderShort -ieq $dcComputerName)) {
                        $null = $operationMasterRoles.Add($roleName)
                    }
                }
            }

            [pscustomobject]@{
                Name                 = $dcComputerName
                HostName             = $dcHostName
                Site                 = Get-SiteNameFromServerReference $serverReference
                IPv4Address          = ConvertTo-SafeString $dcComputerObject.IPv4Address
                OperatingSystem      = ConvertTo-SafeString $dcComputerObject.OperatingSystem
                IsGlobalCatalog      = $isGlobalCatalog
                IsReadOnly           = $isReadOnlyDc
                OperationMasterRoles = Join-SafeValues $operationMasterRoles
                ComputerObjectDN     = ConvertTo-SafeString $dcComputerObject.DistinguishedName
                DiscoveryMethod      = 'ADComputer'
            }
        }
    )
}
catch {
    Add-CollectionWarning -Area 'Domain Controllers' -Message "Domain-controller computer-account discovery failed. $($_.Exception.Message)"
    $domainControllers = @()
}

foreach ($dc in $domainControllers) {
    try {
        $computer = $null
        $dcHostName = ConvertTo-SafeString $dc.HostName
        $dcName = ConvertTo-SafeString $dc.Name

        $computerObjectDn = ConvertTo-SafeString $dc.ComputerObjectDN

        if (-not [string]::IsNullOrWhiteSpace($computerObjectDn)) {
            $computer = Get-ADComputer -Identity $computerObjectDn -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, PasswordLastSet, Enabled, IPv4Address -Server $script:QueryServer
        }

        $null = $dcInventory.Add([pscustomobject]@{
            Name                 = $dcName
            HostName             = $dcHostName
            Site                 = ConvertTo-SafeString $dc.Site
            IPv4Address          = ConvertTo-SafeString $dc.IPv4Address
            OperatingSystem      = ConvertTo-SafeString $dc.OperatingSystem
            OperatingSystemVer   = if ($computer) { ConvertTo-SafeString $computer.OperatingSystemVersion } else { '' }
            IsGlobalCatalog      = ConvertTo-SafeBoolean $dc.IsGlobalCatalog
            IsReadOnly           = ConvertTo-SafeBoolean $dc.IsReadOnly
            OperationMasterRoles = Join-SafeValues $dc.OperationMasterRoles
            Enabled              = if ($computer) { ConvertTo-SafeString $computer.Enabled } else { 'Unknown' }
            LastLogonDate        = if ($computer) { ConvertTo-SafeDateTime $computer.LastLogonDate } else { $null }
            PasswordLastSet      = if ($computer) { ConvertTo-SafeDateTime $computer.PasswordLastSet } else { $null }
        })
    }
    catch {
        Add-CollectionWarning -Area 'Domain Controllers' -Message "Could not process one discovered domain controller object. $($_.Exception.Message)"
    }
}

Write-Step ("Domain controller rows collected: {0}" -f $dcInventory.Count)

$dcCount = $dcInventory.Count
$gcCount = @($dcInventory | Where-Object { $_.IsGlobalCatalog }).Count
$rodcCount = @($dcInventory | Where-Object { $_.IsReadOnly }).Count

if ($dcCount -eq 0) {
    Add-Finding -Severity 'Critical' -Area 'Domain Controllers' -ObjectName $domain.DNSRoot -Finding 'No domain controllers were discovered.' -Evidence 'Get-ADDomainController returned no records.' -Recommendation 'Validate AD module connectivity and DNS/service health immediately.'
}
elseif ($dcCount -eq 1) {
    Add-Finding -Severity 'Critical' -Area 'Domain Controllers' -ObjectName $domain.DNSRoot -Finding 'The domain has only one discovered domain controller.' -Evidence 'Domain controller count is 1.' -Recommendation 'Add at least one additional writable domain controller and verify DNS, GC, SYSVOL, and replication health.'
}

if ($gcCount -eq 0) {
    Add-Finding -Severity 'Critical' -Area 'Global Catalog' -ObjectName $domain.DNSRoot -Finding 'No Global Catalog server was discovered.' -Evidence 'Global Catalog count is 0.' -Recommendation 'Enable Global Catalog on at least one healthy domain controller per domain/site design.'
}

$fsmoHolders = @(
    (ConvertTo-SafeString $domain.PDCEmulator),
    (ConvertTo-SafeString $domain.RIDMaster),
    (ConvertTo-SafeString $domain.InfrastructureMaster),
    (ConvertTo-SafeString $forest.SchemaMaster),
    (ConvertTo-SafeString $forest.DomainNamingMaster)
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

$normalizedDcs = @(
    $dcInventory | ForEach-Object {
        foreach ($dcNameValue in @($_.HostName, $_.Name)) {
            if (-not [string]::IsNullOrWhiteSpace($dcNameValue)) {
                $dcNameValue.ToLowerInvariant()
            }
        }
    }
)
foreach ($holder in ($fsmoHolders | Select-Object -Unique)) {
    $holderKey = $holder.ToLowerInvariant()
    $shortHolder = ($holder -split '\.')[0].ToLowerInvariant()

    if (($normalizedDcs -notcontains $holderKey) -and ($normalizedDcs -notcontains $shortHolder)) {
        Add-Finding -Severity 'High' -Area 'FSMO' -ObjectName $holder -Finding 'FSMO role holder was not in the discovered DC inventory.' -Evidence "FSMO holder $holder was reported by domain/forest metadata but not found in Get-ADDomainController output." -Recommendation 'Validate FSMO role holder health, DNS registration, and AD discovery from the query domain controller.'
    }
}

if (($fsmoHolders | Select-Object -Unique).Count -eq 1 -and $dcCount -gt 1) {
    Add-Finding -Severity 'Low' -Area 'FSMO' -ObjectName ($fsmoHolders | Select-Object -First 1) -Finding 'All FSMO roles are held by one domain controller.' -Evidence 'All five FSMO role names resolve to the same host.' -Recommendation 'This can be acceptable in small domains, but confirm the holder is well protected, monitored, backed up, and not overloaded.'
}

Write-Step "Collecting users, computers, groups, and OUs"
$userCutoff = (Get-Date).AddDays(-1 * $StaleUserDays)
$computerCutoff = (Get-Date).AddDays(-1 * $StaleComputerDays)

$users = @(Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordNeverExpires, PasswordLastSet, AdminCount, WhenCreated, DistinguishedName -ResultPageSize 1000 -Server $script:QueryServer)
$enabledUsers = @($users | Where-Object { $_.Enabled -eq $true })
$disabledUsers = @($users | Where-Object { $_.Enabled -ne $true })
$staleActiveUsers = @($enabledUsers | Where-Object { ($null -eq $_.LastLogonDate) -or ($_.LastLogonDate -lt $userCutoff) })
$neverLoggedOnUsers = @($enabledUsers | Where-Object { $null -eq $_.LastLogonDate })
$passwordNeverExpiresUsers = @($enabledUsers | Where-Object { $_.PasswordNeverExpires -eq $true })
$privilegedStaleUsers = @($staleActiveUsers | Where-Object { $_.AdminCount -eq 1 })

$computers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, WhenCreated, DistinguishedName -ResultPageSize 1000 -Server $script:QueryServer)
$enabledComputers = @($computers | Where-Object { $_.Enabled -eq $true })
$disabledComputers = @($computers | Where-Object { $_.Enabled -ne $true })
$staleActiveComputers = @($enabledComputers | Where-Object { ($null -eq $_.LastLogonDate) -or ($_.LastLogonDate -lt $computerCutoff) })
$serverComputers = @($computers | Where-Object { $_.OperatingSystem -like '*Server*' })

$groups = @(Get-ADGroup -Filter * -Properties GroupCategory, GroupScope, ManagedBy, WhenCreated, DistinguishedName -ResultPageSize 1000 -Server $script:QueryServer)
$ous = @(Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion, gPLink, WhenCreated -ResultPageSize 1000 -Server $script:QueryServer)
$fineGrainedPasswordPolicies = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:QueryServer -ErrorAction SilentlyContinue)

$accountSummary = [pscustomobject]@{
    TotalUsers                    = $users.Count
    EnabledUsers                  = $enabledUsers.Count
    DisabledUsers                 = $disabledUsers.Count
    StaleEnabledUsers             = $staleActiveUsers.Count
    NeverLoggedOnEnabledUsers     = $neverLoggedOnUsers.Count
    PasswordNeverExpiresUsers     = $passwordNeverExpiresUsers.Count
    AdminCountStaleEnabledUsers   = $privilegedStaleUsers.Count
    TotalComputers                = $computers.Count
    EnabledComputers              = $enabledComputers.Count
    DisabledComputers             = $disabledComputers.Count
    StaleEnabledComputers         = $staleActiveComputers.Count
    ServerComputerObjects         = $serverComputers.Count
    TotalGroups                   = $groups.Count
    TotalOUs                      = $ous.Count
    FineGrainedPasswordPolicyCount = $fineGrainedPasswordPolicies.Count
}

if ($staleActiveUsers.Count -gt 0) {
    Add-Finding -Severity 'Medium' -Area 'User Accounts' -ObjectName $domain.DNSRoot -Finding 'Enabled stale user accounts were found.' -Evidence "$($staleActiveUsers.Count) enabled users have no LastLogonDate or have LastLogonDate older than $StaleUserDays days." -Recommendation 'Review stale enabled users with application owners and disable or remove accounts that are no longer required.'
}

if ($privilegedStaleUsers.Count -gt 0) {
    Add-Finding -Severity 'High' -Area 'Privileged Accounts' -ObjectName $domain.DNSRoot -Finding 'Stale enabled users with AdminCount=1 were found.' -Evidence "$($privilegedStaleUsers.Count) stale enabled users have AdminCount=1." -Recommendation 'Review privileged group history, remove unnecessary rights, and disable stale privileged accounts.'
}

if ($passwordNeverExpiresUsers.Count -gt 0) {
    Add-Finding -Severity 'Medium' -Area 'User Accounts' -ObjectName $domain.DNSRoot -Finding 'Enabled users with PasswordNeverExpires were found.' -Evidence "$($passwordNeverExpiresUsers.Count) enabled users have PasswordNeverExpires=True." -Recommendation 'Validate whether these are managed service accounts or documented exceptions; remove the setting where not required.'
}

if ($staleActiveComputers.Count -gt 0) {
    Add-Finding -Severity 'Medium' -Area 'Computer Accounts' -ObjectName $domain.DNSRoot -Finding 'Enabled stale computer accounts were found.' -Evidence "$($staleActiveComputers.Count) enabled computer accounts have no LastLogonDate or have LastLogonDate older than $StaleComputerDays days." -Recommendation 'Review stale computer accounts with endpoint/server owners and disable or remove decommissioned objects.'
}

$unprotectedOus = @($ous | Where-Object { $_.ProtectedFromAccidentalDeletion -ne $true })
if ($unprotectedOus.Count -gt 0) {
    Add-Finding -Severity 'Low' -Area 'OU Design' -ObjectName $domain.DNSRoot -Finding 'OUs without accidental deletion protection were found.' -Evidence "$($unprotectedOus.Count) OUs have ProtectedFromAccidentalDeletion not set to True." -Recommendation 'Enable accidental deletion protection on production OUs after confirming automation dependencies.'
}

$groupByOu = @(
    $groups |
        Group-Object -Property { Convert-DnToReadablePath (Get-ParentDn $_.DistinguishedName) } |
        Sort-Object Count -Descending |
        ForEach-Object {
            [pscustomobject]@{
                GroupLocation = if ([string]::IsNullOrWhiteSpace($_.Name)) { 'Unknown' } else { $_.Name }
                GroupCount    = $_.Count
            }
        }
)

$groupsInDefaultUsersContainer = @($groups | Where-Object { (Get-ParentDn $_.DistinguishedName) -match '^CN=Users,' })
if ($groupsInDefaultUsersContainer.Count -gt 10) {
    Add-Finding -Severity 'Low' -Area 'Group Design' -ObjectName 'CN=Users' -Finding 'Many groups are located in the default Users container.' -Evidence "$($groupsInDefaultUsersContainer.Count) groups are in CN=Users." -Recommendation 'Review whether business/security groups should be moved to managed OUs with clear delegation and GPO design.'
}

$privilegedGroupNames = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'Group Policy Creator Owners'
)

$privilegedGroupSummary = New-Object System.Collections.ArrayList
foreach ($groupName in $privilegedGroupNames) {
    try {
        $privilegedGroup = Get-ADGroup -Identity $groupName -Properties DistinguishedName -Server $script:QueryServer
        $members = @(Get-ADGroupMember -Identity $privilegedGroup.DistinguishedName -Server $script:QueryServer -ErrorAction Stop)
        $memberNames = @($members | ForEach-Object { $_.Name })

        $null = $privilegedGroupSummary.Add([pscustomobject]@{
            GroupName    = $groupName
            DirectMemberCount = $members.Count
            DirectMembers = ($memberNames -join ', ')
        })

        if ($groupName -eq 'Domain Admins' -and $members.Count -gt 5) {
            Add-Finding -Severity 'Medium' -Area 'Privileged Groups' -ObjectName $groupName -Finding 'Domain Admins has more than five direct members.' -Evidence "Direct member count is $($members.Count)." -Recommendation 'Review privileged-access model and reduce standing Domain Admin membership.'
        }

        if ($groupName -eq 'Enterprise Admins' -and $members.Count -gt 2) {
            Add-Finding -Severity 'High' -Area 'Privileged Groups' -ObjectName $groupName -Finding 'Enterprise Admins has more than two direct members.' -Evidence "Direct member count is $($members.Count)." -Recommendation 'Review forest-wide administrative access and reduce standing Enterprise Admin membership.'
        }

        if ($groupName -in @('Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators') -and $members.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Area 'Privileged Groups' -ObjectName $groupName -Finding 'Legacy operator group has direct members.' -Evidence "Direct member count is $($members.Count)." -Recommendation 'Validate whether this legacy delegation is still required; prefer least-privilege delegated administration.'
        }
    }
    catch {
        Add-CollectionWarning -Area 'Privileged Groups' -Message "Could not collect group '$groupName'. $($_.Exception.Message)"
    }
}

Write-Step "Collecting AD sites, subnets, site links, and replication signals"
$sites = @()
$subnets = @()
$siteLinks = @()
$siteSummary = @()
$siteLinkSummary = @()
$replicationFailures = @()
$replicationPartnerSummary = @()

try {
    $sites = @(Get-ADReplicationSite -Filter * -Properties Description, Location, ProtectedFromAccidentalDeletion -Server $script:QueryServer)
    $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Site, Location, Description -Server $script:QueryServer)
    $siteLinks = @(Get-ADReplicationSiteLink -Filter * -Properties Cost, ReplicationFrequencyInMinutes, SitesIncluded, InterSiteTransportProtocol, Options -Server $script:QueryServer)

    $siteSummary = @(
        foreach ($site in $sites) {
            $siteSubnets = @($subnets | Where-Object { (Get-RdnNameFromDn $_.Site) -eq $site.Name })
            $siteDcs = @($dcInventory | Where-Object { $_.Site -eq $site.Name })

            [pscustomobject]@{
                SiteName      = $site.Name
                DomainControllers = $siteDcs.Count
                Subnets       = $siteSubnets.Count
                Location      = [string]$site.Location
                Description   = [string]$site.Description
                ProtectedFromAccidentalDeletion = [string]$site.ProtectedFromAccidentalDeletion
            }
        }
    )

    $siteLinkSummary = @(
        foreach ($siteLink in $siteLinks) {
            $includedSiteNames = @($siteLink.SitesIncluded | ForEach-Object { Get-RdnNameFromDn $_ })

            [pscustomobject]@{
                SiteLinkName = $siteLink.Name
                SitesIncluded = ($includedSiteNames -join ', ')
                SiteCount = $includedSiteNames.Count
                Cost = $siteLink.Cost
                ReplicationFrequencyMinutes = $siteLink.ReplicationFrequencyInMinutes
                Transport = [string]$siteLink.InterSiteTransportProtocol
                Options = [string]$siteLink.Options
            }
        }
    )

    if ($sites.Count -gt 1 -and $siteLinks.Count -eq 0) {
        Add-Finding -Severity 'High' -Area 'AD Sites' -ObjectName $domain.DNSRoot -Finding 'Multiple AD sites exist but no site links were discovered.' -Evidence "$($sites.Count) sites, 0 site links." -Recommendation 'Create site links that reflect WAN topology, cost, and replication frequency.'
    }

    foreach ($siteRow in $siteSummary) {
        if ($siteRow.Subnets -eq 0) {
            Add-Finding -Severity 'Medium' -Area 'AD Sites' -ObjectName $siteRow.SiteName -Finding 'AD site has no subnet mappings.' -Evidence "Site $($siteRow.SiteName) has 0 subnets." -Recommendation 'Map AD subnets to the correct site so clients and DCs locate local services correctly.'
        }

        if ($siteRow.DomainControllers -eq 0) {
            Add-Finding -Severity 'Low' -Area 'AD Sites' -ObjectName $siteRow.SiteName -Finding 'AD site has no domain controller.' -Evidence "Site $($siteRow.SiteName) has 0 discovered DCs." -Recommendation 'This can be valid for small branch sites, but confirm authentication and logon traffic over WAN is intentional.'
        }
    }

    if (@($sites | Where-Object { $_.Name -eq 'Default-First-Site-Name' }).Count -gt 0) {
        Add-Finding -Severity 'Low' -Area 'AD Sites' -ObjectName 'Default-First-Site-Name' -Finding 'Default AD site name is still present.' -Evidence 'A site named Default-First-Site-Name exists.' -Recommendation 'Rename the default site to a location-aware name if this is a production forest.'
    }

    foreach ($siteLinkRow in $siteLinkSummary) {
        if ($siteLinkRow.SiteCount -lt 2) {
            Add-Finding -Severity 'High' -Area 'AD Site Links' -ObjectName $siteLinkRow.SiteLinkName -Finding 'Site link includes fewer than two sites.' -Evidence "SiteCount is $($siteLinkRow.SiteCount)." -Recommendation 'Update or remove the site link. A functional site link should connect at least two sites.'
        }

        if ([int]$siteLinkRow.ReplicationFrequencyMinutes -gt 180) {
            Add-Finding -Severity 'Low' -Area 'AD Site Links' -ObjectName $siteLinkRow.SiteLinkName -Finding 'Site-link replication frequency is higher than 180 minutes.' -Evidence "ReplicationFrequencyInMinutes is $($siteLinkRow.ReplicationFrequencyMinutes)." -Recommendation 'Confirm the interval matches business recovery and convergence requirements.'
        }
    }

    if ($siteLinks.Count -gt 1) {
        $siteLinkCosts = @($siteLinks | Select-Object -ExpandProperty Cost -Unique)
        if ($siteLinkCosts.Count -eq 1 -and [int]$siteLinkCosts[0] -eq 100) {
            Add-Finding -Severity 'Low' -Area 'AD Site Links' -ObjectName $domain.DNSRoot -Finding 'All site links use default cost 100.' -Evidence "$($siteLinks.Count) site links all have cost 100." -Recommendation 'Review whether site-link costs reflect WAN preference, bandwidth, latency, and failover paths.'
        }
    }
}
catch {
    Add-CollectionWarning -Area 'AD Sites' -Message "Could not collect AD site topology. $($_.Exception.Message)"
}

try {
    $replicationFailures = @(
        Get-ADReplicationFailure -Target $domain.DNSRoot -Scope Domain -EnumeratingServer $script:QueryServer |
            Select-Object Server, Partner, FirstFailureTime, FailureCount, LastError, LastErrorMessage
    )

    if ($replicationFailures.Count -gt 0) {
        Add-Finding -Severity 'High' -Area 'Replication' -ObjectName $domain.DNSRoot -Finding 'AD replication failures were reported.' -Evidence "$($replicationFailures.Count) replication failure records were returned." -Recommendation 'Review the ReplicationFailures CSV and resolve DNS, network, secure-channel, or lingering-object causes.'
    }
}
catch {
    Add-CollectionWarning -Area 'Replication' -Message "Could not collect replication failures. $($_.Exception.Message)"
}

try {
    $replicationPartnerSummary = @(
        Get-ADReplicationPartnerMetadata -Target $domain.DNSRoot -Scope Domain -EnumerationServer $script:QueryServer |
            Select-Object Server, Partner, Partition, LastReplicationSuccess, LastReplicationAttempt, LastReplicationResult, ConsecutiveReplicationFailures
    )

    $staleReplicationPartners = @($replicationPartnerSummary | Where-Object {
        ($_.ConsecutiveReplicationFailures -gt 0) -or
        ($_.LastReplicationSuccess -and $_.LastReplicationSuccess -lt (Get-Date).AddHours(-24))
    })

    if ($staleReplicationPartners.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Area 'Replication' -ObjectName $domain.DNSRoot -Finding 'Replication partners show failures or old successful replication timestamps.' -Evidence "$($staleReplicationPartners.Count) partner metadata rows have failures or LastReplicationSuccess older than 24 hours." -Recommendation 'Review replication partner metadata and validate convergence across all naming contexts.'
    }
}
catch {
    Add-CollectionWarning -Area 'Replication' -Message "Could not collect replication partner metadata. $($_.Exception.Message)"
}

Write-Step "Collecting GPO summary"
$gpoSummary = [pscustomobject]@{
    GroupPolicyModuleAvailable = $groupPolicyAvailable
    TotalGpos                  = 0
    UnlinkedGpos               = 0
    AllSettingsDisabled        = 0
    ComputerSettingsDisabled   = 0
    UserSettingsDisabled       = 0
    WsUsPolicyGpos             = 0
}
$gpoRows = @()
$unlinkedGpoRows = @()
$wsusGpoRows = @()

if ($groupPolicyAvailable) {
    try {
        $gpos = @(Get-GPO -All -Domain $domain.DNSRoot -Server $script:QueryServer)
        $gpoRows = @(
            $gpos | Select-Object DisplayName, Id, Owner, GpoStatus, CreationTime, ModificationTime, UserVersion, ComputerVersion
        )

        $linkedGpoGuids = New-Object 'System.Collections.Generic.HashSet[string]'

        $domainObject = Get-ADObject -Identity $domain.DistinguishedName -Properties gPLink -Server $script:QueryServer
        foreach ($guid in (Get-GuidFromGpLink $domainObject.gPLink)) {
            $null = $linkedGpoGuids.Add($guid)
        }

        foreach ($ou in $ous) {
            foreach ($guid in (Get-GuidFromGpLink $ou.gPLink)) {
                $null = $linkedGpoGuids.Add($guid)
            }
        }

        try {
            $siteObjects = @(Get-ADObject -SearchBase ("CN=Sites,{0}" -f $rootDse.configurationNamingContext) -LDAPFilter '(objectClass=site)' -Properties gPLink -Server $script:QueryServer)
            foreach ($siteObject in $siteObjects) {
                foreach ($guid in (Get-GuidFromGpLink $siteObject.gPLink)) {
                    $null = $linkedGpoGuids.Add($guid)
                }
            }
        }
        catch {
            Add-CollectionWarning -Area 'GPO' -Message "Could not collect site-linked GPO references. $($_.Exception.Message)"
        }

        $unlinkedGpoRows = @(
            $gpos |
                Where-Object { -not $linkedGpoGuids.Contains((Convert-GuidToKey $_.Id)) } |
                Select-Object DisplayName, Id, Owner, GpoStatus, CreationTime, ModificationTime
        )

        $gpoSummary.TotalGpos = $gpos.Count
        $gpoSummary.UnlinkedGpos = $unlinkedGpoRows.Count
        $gpoSummary.AllSettingsDisabled = @($gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }).Count
        $gpoSummary.ComputerSettingsDisabled = @($gpos | Where-Object { $_.GpoStatus -eq 'ComputerSettingsDisabled' }).Count
        $gpoSummary.UserSettingsDisabled = @($gpos | Where-Object { $_.GpoStatus -eq 'UserSettingsDisabled' }).Count

        if ($unlinkedGpoRows.Count -gt 0) {
            Add-Finding -Severity 'Low' -Area 'GPO Hygiene' -ObjectName $domain.DNSRoot -Finding 'Unlinked GPOs were found.' -Evidence "$($unlinkedGpoRows.Count) GPOs were not linked at domain, OU, or site scope." -Recommendation 'Review unlinked GPOs and delete retired policies after confirming they are not used for backup, staging, or migration.'
        }

        if ($IncludeGpoScan) {
            Write-Step "Scanning GPO XML for WSUS or Windows Update policy references"
            foreach ($gpo in $gpos) {
                try {
                    $gpoXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $domain.DNSRoot -Server $script:QueryServer
                    if ($gpoXml -match 'WUServer|WUStatusServer|Windows Update|Specify intranet Microsoft update service location') {
                        $wsusGpoRows += [pscustomobject]@{
                            DisplayName      = $gpo.DisplayName
                            Id               = $gpo.Id
                            GpoStatus        = $gpo.GpoStatus
                            ModificationTime = $gpo.ModificationTime
                        }
                    }
                }
                catch {
                    Add-CollectionWarning -Area 'GPO WSUS Scan' -Message "Could not scan GPO '$($gpo.DisplayName)'. $($_.Exception.Message)"
                }
            }

            $gpoSummary.WsUsPolicyGpos = $wsusGpoRows.Count
        }
    }
    catch {
        Add-CollectionWarning -Area 'GPO' -Message "Could not collect GPO summary. $($_.Exception.Message)"
    }
}

Write-Step "Testing TCP ports on domain controllers"
$portCheckRows = New-Object System.Collections.ArrayList
if (-not $SkipPortChecks) {
    foreach ($dc in $dcInventory) {
        foreach ($port in ($TcpPortsToTest | Sort-Object -Unique)) {
            $portResult = Test-TcpPort -ComputerName $dc.HostName -Port $port -TimeoutMs $PortTimeoutMs
            $purpose = if ($portPurpose.ContainsKey([string]$port)) { $portPurpose[[string]$port] } else { 'Custom' }

            $null = $portCheckRows.Add([pscustomobject]@{
                DomainController = $dc.HostName
                Site             = $dc.Site
                Port             = $port
                Purpose          = $purpose
                Status           = $portResult.Status
                Open             = $portResult.Open
                ResponseMs       = $portResult.ResponseMs
                Error            = $portResult.Error
            })
        }
    }

    foreach ($dc in $dcInventory) {
        $dcPorts = @($portCheckRows | Where-Object { $_.DomainController -eq $dc.HostName })
        $requiredPorts = @(88, 135, 389, 445, 464, 9389)

        foreach ($requiredPort in $requiredPorts) {
            $row = $dcPorts | Where-Object { $_.Port -eq $requiredPort } | Select-Object -First 1
            if ($row -and -not $row.Open) {
                Add-Finding -Severity 'High' -Area 'DC Port Reachability' -ObjectName $dc.HostName -Finding "Expected AD TCP port $requiredPort is not reachable." -Evidence "$($row.Purpose) on TCP/$requiredPort returned $($row.Status). $($row.Error)" -Recommendation 'Validate Windows Firewall, network ACLs, local service health, and whether the test host has a permitted network path to the DC.'
            }
        }

        if ($dc.IsGlobalCatalog) {
            $gcPort = $dcPorts | Where-Object { $_.Port -eq 3268 } | Select-Object -First 1
            if ($gcPort -and -not $gcPort.Open) {
                Add-Finding -Severity 'High' -Area 'DC Port Reachability' -ObjectName $dc.HostName -Finding 'Global Catalog LDAP port is not reachable.' -Evidence "TCP/3268 returned $($gcPort.Status). $($gcPort.Error)" -Recommendation 'Validate Global Catalog service health, firewall policy, and network ACLs.'
            }
        }

        foreach ($wsusPort in @(8530, 8531)) {
            $wsusPortRow = $dcPorts | Where-Object { $_.Port -eq $wsusPort -and $_.Open } | Select-Object -First 1
            if ($wsusPortRow) {
                Add-Finding -Severity 'High' -Area 'WSUS Role Separation' -ObjectName $dc.HostName -Finding "WSUS port TCP/$wsusPort is reachable on a domain controller." -Evidence "$($wsusPortRow.Purpose) is open from the assessment host." -Recommendation 'Confirm WSUS is not installed on a domain controller. Separate WSUS/IIS from domain controller roles unless a documented exception exists.'
            }
        }

        $netbiosRow = $dcPorts | Where-Object { $_.Port -eq 139 -and $_.Open } | Select-Object -First 1
        if ($netbiosRow) {
            Add-Finding -Severity 'Low' -Area 'Legacy Protocols' -ObjectName $dc.HostName -Finding 'NetBIOS Session Service is reachable.' -Evidence 'TCP/139 is open from the assessment host.' -Recommendation 'Review whether NetBIOS is still required in the environment and restrict or retire it where possible.'
        }
    }
}
else {
    Add-CollectionWarning -Area 'DC Port Reachability' -Message 'Port checks were skipped by parameter.'
}

Write-Step "Collecting service posture from domain controllers"
$serviceRows = New-Object System.Collections.ArrayList
if (-not $SkipServiceChecks) {
    $serviceNamesToCheck = @(
        'NTDS',
        'Netlogon',
        'Kdc',
        'W32Time',
        'ADWS',
        'RPCSS',
        'DFSR',
        'NtFrs',
        'DNS',
        'Spooler',
        'RemoteRegistry',
        'W3SVC',
        'WsusService',
        'SNMP',
        'TlntSvr',
        'Fax',
        'Browser',
        'TermService'
    )

    foreach ($dc in $dcInventory) {
        try {
            $remoteServices = @(Get-WmiObject -Class Win32_Service -ComputerName $dc.HostName -ErrorAction Stop)

            foreach ($serviceName in $serviceNamesToCheck) {
                $service = $remoteServices | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
                $guidance = if ($serviceGuidance.ContainsKey($serviceName)) { $serviceGuidance[$serviceName] } else { '' }

                $null = $serviceRows.Add([pscustomobject]@{
                    DomainController = $dc.HostName
                    ServiceName      = $serviceName
                    DisplayName      = if ($service) { [string]$service.DisplayName } else { '' }
                    State            = if ($service) { [string]$service.State } else { 'NotInstalled' }
                    StartMode        = if ($service) { [string]$service.StartMode } else { 'NotInstalled' }
                    Guidance         = $guidance
                })
            }

            foreach ($requiredService in @('NTDS', 'Netlogon', 'Kdc', 'W32Time', 'ADWS', 'RPCSS')) {
                $serviceRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq $requiredService } | Select-Object -First 1
                if ($serviceRow -and $serviceRow.State -ne 'Running') {
                    Add-Finding -Severity 'High' -Area 'DC Services' -ObjectName $dc.HostName -Finding "Required DC service $requiredService is not running." -Evidence "$requiredService state is $($serviceRow.State), start mode is $($serviceRow.StartMode)." -Recommendation 'Validate the domain controller role health and service failure cause before making any service changes.'
                }
            }

            $dfsrRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq 'DFSR' } | Select-Object -First 1
            $frsRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq 'NtFrs' } | Select-Object -First 1
            if (($dfsrRow.State -ne 'Running') -and ($frsRow.State -ne 'Running')) {
                Add-Finding -Severity 'High' -Area 'SYSVOL Replication' -ObjectName $dc.HostName -Finding 'Neither DFSR nor FRS service is running.' -Evidence "DFSR state is $($dfsrRow.State); NtFrs state is $($frsRow.State)." -Recommendation 'Validate SYSVOL replication health immediately. A DC should have the active SYSVOL replication service running.'
            }

            if ($frsRow.State -eq 'Running') {
                Add-Finding -Severity 'Medium' -Area 'SYSVOL Replication' -ObjectName $dc.HostName -Finding 'Legacy FRS service is running.' -Evidence 'NtFrs service state is Running.' -Recommendation 'Confirm whether SYSVOL still uses FRS. Plan DFSR migration if the domain is still on legacy FRS replication.'
            }

            $dnsRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq 'DNS' } | Select-Object -First 1
            if ($dnsRow.State -notin @('Running', 'NotInstalled')) {
                Add-Finding -Severity 'High' -Area 'DNS' -ObjectName $dc.HostName -Finding 'DNS service is installed but not running on a domain controller.' -Evidence "DNS state is $($dnsRow.State), start mode is $($dnsRow.StartMode)." -Recommendation 'If this DC is intended to host AD-integrated DNS, restore DNS service health. If not, validate DNS client settings and site design.'
            }

            $spoolerRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq 'Spooler' } | Select-Object -First 1
            if ($spoolerRow.State -eq 'Running') {
                Add-Finding -Severity 'High' -Area 'DC Services' -ObjectName $dc.HostName -Finding 'Print Spooler is running on a domain controller.' -Evidence "Spooler start mode is $($spoolerRow.StartMode)." -Recommendation 'Disable Print Spooler on domain controllers unless a documented exception exists.'
            }

            $remoteRegistryRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq 'RemoteRegistry' } | Select-Object -First 1
            if ($remoteRegistryRow.State -eq 'Running') {
                Add-Finding -Severity 'Medium' -Area 'DC Services' -ObjectName $dc.HostName -Finding 'Remote Registry is running on a domain controller.' -Evidence "RemoteRegistry start mode is $($remoteRegistryRow.StartMode)." -Recommendation 'Disable Remote Registry unless a documented management or monitoring dependency requires it.'
            }

            foreach ($reviewService in @('W3SVC', 'WsusService', 'SNMP', 'TlntSvr', 'Fax', 'Browser')) {
                $reviewRow = $serviceRows | Where-Object { $_.DomainController -eq $dc.HostName -and $_.ServiceName -eq $reviewService } | Select-Object -First 1
                if ($reviewRow.State -eq 'Running') {
                    $severity = if ($reviewService -eq 'WsusService') { 'High' } elseif ($reviewService -eq 'TlntSvr') { 'High' } else { 'Medium' }
                    Add-Finding -Severity $severity -Area 'DC Services' -ObjectName $dc.HostName -Finding "$reviewService is running on a domain controller." -Evidence "$reviewService start mode is $($reviewRow.StartMode)." -Recommendation 'Review role separation and disable the service if there is no documented requirement on domain controllers.'
                }
            }
        }
        catch {
            Add-Finding -Severity 'Medium' -Area 'DC Services' -ObjectName $dc.HostName -Finding 'Could not collect service posture from domain controller.' -Evidence $_.Exception.Message -Recommendation 'Validate WMI/DCOM firewall rules, administrator rights, RPC reachability, and remote service permissions.'
        }
    }
}
else {
    Add-CollectionWarning -Area 'DC Services' -Message 'Service checks were skipped by parameter.'
}

Write-Step "Collecting DNS architecture summary"
$dnsZoneRows = New-Object System.Collections.ArrayList
$dnsForwarderRows = New-Object System.Collections.ArrayList
$dnsArchitectureSummary = [pscustomobject]@{
    DnsServerModuleAvailable = $dnsServerModuleAvailable
    QueriedDnsServers        = 0
    TotalZones               = 0
    ADIntegratedZones        = 0
    PrimaryZones             = 0
    SecondaryZones           = 0
    ReverseLookupZones       = 0
    NonSecureDynamicZones    = 0
    DomainDnsZoneFound       = $false
    ForwarderCount           = 0
}

if ($dnsServerModuleAvailable) {
    $dnsDcCandidates = @()

    if ($serviceRows.Count -gt 0) {
        $dnsDcCandidates = @(
            $serviceRows |
                Where-Object { $_.ServiceName -eq 'DNS' -and $_.State -eq 'Running' } |
                Select-Object -ExpandProperty DomainController -Unique
        )
    }

    if ($dnsDcCandidates.Count -eq 0) {
        $dnsDcCandidates = @($dcInventory | Select-Object -ExpandProperty HostName)
    }

    foreach ($dnsServer in $dnsDcCandidates) {
        try {
            $zones = @(Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop)
            $dnsArchitectureSummary.QueriedDnsServers++

            foreach ($zone in $zones) {
                $zoneRow = [pscustomobject]@{
                    DnsServer              = $dnsServer
                    ZoneName               = [string]$zone.ZoneName
                    ZoneType               = [string]$zone.ZoneType
                    IsDsIntegrated         = [string]$zone.IsDsIntegrated
                    IsReverseLookupZone    = [string]$zone.IsReverseLookupZone
                    DynamicUpdate          = [string]$zone.DynamicUpdate
                    ReplicationScope       = [string]$zone.ReplicationScope
                    DirectoryPartitionName = [string]$zone.DirectoryPartitionName
                    IsAutoCreated          = [string]$zone.IsAutoCreated
                    IsPaused               = [string]$zone.IsPaused
                }

                $null = $dnsZoneRows.Add($zoneRow)

                if ($zone.ZoneName -eq $domain.DNSRoot -and $zone.IsDsIntegrated -eq $true) {
                    $dnsArchitectureSummary.DomainDnsZoneFound = $true
                }

                if ([string]$zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    Add-Finding -Severity 'High' -Area 'DNS' -ObjectName "$dnsServer\$($zone.ZoneName)" -Finding 'DNS zone allows nonsecure dynamic updates.' -Evidence "DynamicUpdate is $($zone.DynamicUpdate)." -Recommendation 'Use secure-only dynamic updates for AD-integrated domain zones unless a documented exception exists.'
                }

                if ($zone.ZoneType -eq 'Primary' -and $zone.IsDsIntegrated -ne $true -and $zone.ZoneName -notmatch '^\d+\.in-addr\.arpa$') {
                    Add-Finding -Severity 'Low' -Area 'DNS' -ObjectName "$dnsServer\$($zone.ZoneName)" -Finding 'Primary DNS zone is not AD-integrated.' -Evidence "ZoneType is Primary and IsDsIntegrated is $($zone.IsDsIntegrated)." -Recommendation 'Review whether this zone should be AD-integrated for replication and availability.'
                }
            }

            try {
                $forwarder = Get-DnsServerForwarder -ComputerName $dnsServer -ErrorAction Stop
                foreach ($ipAddress in @($forwarder.IPAddress)) {
                    $null = $dnsForwarderRows.Add([pscustomobject]@{
                        DnsServer = $dnsServer
                        Forwarder = [string]$ipAddress
                        UseRootHint = [string]$forwarder.UseRootHint
                        Timeout = [string]$forwarder.Timeout
                    })
                }
            }
            catch {
                Add-CollectionWarning -Area 'DNS' -Message "Could not collect DNS forwarders from $dnsServer. $($_.Exception.Message)"
            }
        }
        catch {
            Add-CollectionWarning -Area 'DNS' -Message "Could not collect DNS zones from $dnsServer. $($_.Exception.Message)"
        }
    }

    $dnsArchitectureSummary.TotalZones = $dnsZoneRows.Count
    $dnsArchitectureSummary.ADIntegratedZones = @($dnsZoneRows | Where-Object { $_.IsDsIntegrated -eq 'True' }).Count
    $dnsArchitectureSummary.PrimaryZones = @($dnsZoneRows | Where-Object { $_.ZoneType -eq 'Primary' }).Count
    $dnsArchitectureSummary.SecondaryZones = @($dnsZoneRows | Where-Object { $_.ZoneType -eq 'Secondary' }).Count
    $dnsArchitectureSummary.ReverseLookupZones = @($dnsZoneRows | Where-Object { $_.IsReverseLookupZone -eq 'True' }).Count
    $dnsArchitectureSummary.NonSecureDynamicZones = @($dnsZoneRows | Where-Object { $_.DynamicUpdate -eq 'NonsecureAndSecure' }).Count
    $dnsArchitectureSummary.ForwarderCount = $dnsForwarderRows.Count

    if (-not $dnsArchitectureSummary.DomainDnsZoneFound) {
        Add-Finding -Severity 'High' -Area 'DNS' -ObjectName $domain.DNSRoot -Finding 'The domain DNS zone was not found as an AD-integrated zone on queried DNS servers.' -Evidence "Queried DNS servers: $($dnsDcCandidates -join ', ')." -Recommendation 'Validate DNS role placement and confirm the AD domain zone is hosted, AD-integrated, and replicated to the expected DNS servers.'
    }
}

Write-Step "Building report files"
$findingsSorted = @(
    $script:Findings |
        Sort-Object @{ Expression = { Get-SeverityRank $_.Severity } }, Area, ObjectName, Finding
)

$findingSeveritySummary = @(
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        [pscustomobject]@{
            Severity = $severity
            Count    = @($findingsSorted | Where-Object { $_.Severity -eq $severity }).Count
        }
    }
)

$executiveCategoryOrder = @(
    'Critical architecture risks',
    'Security hardening items',
    'AD topology/replication issues',
    'Cleanup/hygiene tasks'
)

$executiveFindingRows = @(
    foreach ($finding in $findingsSorted) {
        [pscustomobject]@{
            ExecutiveCategory = Get-FindingExecutiveCategory -Area $finding.Area -Severity $finding.Severity
            Severity          = $finding.Severity
            Area              = $finding.Area
            ObjectName        = $finding.ObjectName
            Finding           = $finding.Finding
            Evidence          = $finding.Evidence
            Recommendation    = $finding.Recommendation
        }
    }
)

$executiveCategorySummary = @(
    foreach ($category in $executiveCategoryOrder) {
        $categoryFindings = @($executiveFindingRows | Where-Object { $_.ExecutiveCategory -eq $category })
        $highestSeverity = ''

        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            if (@($categoryFindings | Where-Object { $_.Severity -eq $severity }).Count -gt 0) {
                $highestSeverity = $severity
                break
            }
        }

        [pscustomobject]@{
            Category        = $category
            Critical        = @($categoryFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High            = @($categoryFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium          = @($categoryFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low             = @($categoryFindings | Where-Object { $_.Severity -eq 'Low' }).Count
            Info            = @($categoryFindings | Where-Object { $_.Severity -eq 'Info' }).Count
            Total           = $categoryFindings.Count
            HighestSeverity = $highestSeverity
        }
    }
)

$criticalArchitectureFindings = @($executiveFindingRows | Where-Object { $_.ExecutiveCategory -eq 'Critical architecture risks' })
$securityHardeningFindings = @($executiveFindingRows | Where-Object { $_.ExecutiveCategory -eq 'Security hardening items' })
$topologyReplicationFindings = @($executiveFindingRows | Where-Object { $_.ExecutiveCategory -eq 'AD topology/replication issues' })
$cleanupHygieneFindings = @($executiveFindingRows | Where-Object { $_.ExecutiveCategory -eq 'Cleanup/hygiene tasks' })

$architectureCounts = [pscustomobject]@{
    DomainControllers      = $dcCount
    GlobalCatalogs         = $gcCount
    ReadOnlyDomainControllers = $rodcCount
    Users                  = $users.Count
    EnabledUsers           = $enabledUsers.Count
    StaleEnabledUsers      = $staleActiveUsers.Count
    Computers              = $computers.Count
    StaleEnabledComputers  = $staleActiveComputers.Count
    Groups                 = $groups.Count
    OUs                    = $ous.Count
    Sites                  = @($sites).Count
    Subnets                = @($subnets).Count
    SiteLinks              = @($siteLinks).Count
    GPOs                   = $gpoSummary.TotalGpos
    DnsZones               = $dnsArchitectureSummary.TotalZones
    DnsForwarders          = $dnsArchitectureSummary.ForwarderCount
    Findings               = $findingsSorted.Count
}

$htmlPath = Join-Path $runFolder 'AD_Architecture_Assessment.html'
$jsonPath = Join-Path $runFolder 'AD_Architecture_Assessment.json'
$findingsCsvPath = Join-Path $runFolder 'Findings.csv'

Export-CsvIfData -Data $findingsSorted -Path $findingsCsvPath
Export-CsvIfData -Data $executiveCategorySummary -Path (Join-Path $runFolder 'ExecutiveFindingSummary.csv')
Export-CsvIfData -Data $executiveFindingRows -Path (Join-Path $runFolder 'ExecutiveFindings.csv')
Export-CsvIfData -Data $dcInventory -Path (Join-Path $runFolder 'DomainControllers.csv')
Export-CsvIfData -Data $siteSummary -Path (Join-Path $runFolder 'Sites.csv')
Export-CsvIfData -Data $siteLinkSummary -Path (Join-Path $runFolder 'SiteLinks.csv')
Export-CsvIfData -Data $subnets -Path (Join-Path $runFolder 'Subnets.csv')
Export-CsvIfData -Data $groupByOu -Path (Join-Path $runFolder 'GroupsByLocation.csv')
Export-CsvIfData -Data $privilegedGroupSummary -Path (Join-Path $runFolder 'PrivilegedGroups.csv')
Export-CsvIfData -Data $portCheckRows -Path (Join-Path $runFolder 'DomainControllerPorts.csv')
Export-CsvIfData -Data $serviceRows -Path (Join-Path $runFolder 'DomainControllerServices.csv')
Export-CsvIfData -Data $replicationFailures -Path (Join-Path $runFolder 'ReplicationFailures.csv')
Export-CsvIfData -Data $replicationPartnerSummary -Path (Join-Path $runFolder 'ReplicationPartnerMetadata.csv')
Export-CsvIfData -Data $gpoRows -Path (Join-Path $runFolder 'GPOs.csv')
Export-CsvIfData -Data $unlinkedGpoRows -Path (Join-Path $runFolder 'UnlinkedGPOs.csv')
Export-CsvIfData -Data $wsusGpoRows -Path (Join-Path $runFolder 'WSUSPolicyGPOs.csv')
Export-CsvIfData -Data $dnsZoneRows -Path (Join-Path $runFolder 'DnsZones.csv')
Export-CsvIfData -Data $dnsForwarderRows -Path (Join-Path $runFolder 'DnsForwarders.csv')
Export-CsvIfData -Data $script:CollectionWarnings -Path (Join-Path $runFolder 'CollectionWarnings.csv')

Export-CsvIfData -Data (
    $staleActiveUsers |
        Select-Object SamAccountName, Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount, DistinguishedName
) -Path (Join-Path $runFolder 'StaleEnabledUsers.csv')

Export-CsvIfData -Data (
    $staleActiveComputers |
        Select-Object Name, Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, DistinguishedName
) -Path (Join-Path $runFolder 'StaleEnabledComputers.csv')

$reportData = [pscustomobject]@{
    GeneratedAt                = Get-Date
    RunFolder                  = $runFolder
    DomainSummary              = $domainSummary
    ArchitectureCounts         = $architectureCounts
    AccountSummary             = $accountSummary
    GpoSummary                 = $gpoSummary
    DnsArchitectureSummary     = $dnsArchitectureSummary
    FindingSeveritySummary     = $findingSeveritySummary
    ExecutiveCategorySummary   = $executiveCategorySummary
    ExecutiveFindings          = $executiveFindingRows
    Findings                   = $findingsSorted
    DomainControllers          = @($dcInventory)
    Sites                      = @($siteSummary)
    SiteLinks                  = @($siteLinkSummary)
    GroupsByLocation           = @($groupByOu)
    PrivilegedGroups           = @($privilegedGroupSummary)
    DnsZones                   = @($dnsZoneRows)
    DnsForwarders              = @($dnsForwarderRows)
    ReplicationFailures        = @($replicationFailures)
    ReplicationPartnerMetadata = @($replicationPartnerSummary)
    CollectionWarnings         = @($script:CollectionWarnings)
}

$reportData | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

$css = @'
body {
    background: #f4f6f8;
    color: #17202a;
    font-family: "Segoe UI", Tahoma, sans-serif;
    margin: 0;
    padding: 0;
}

header {
    background: #102a43;
    color: #ffffff;
    padding: 28px 36px;
}

header h1 {
    margin: 0 0 8px 0;
    font-size: 26px;
}

header p {
    margin: 0;
    color: #d9e2ec;
}

main {
    padding: 24px 36px 36px 36px;
}

section {
    background: #ffffff;
    border: 1px solid #d9e2ec;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(16, 42, 67, 0.06);
    margin-bottom: 22px;
    padding: 20px;
}

h2 {
    color: #102a43;
    font-size: 20px;
    margin: 0 0 14px 0;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px;
}

.card {
    background: #f8fafc;
    border-left: 4px solid #486581;
    border-radius: 8px;
    padding: 12px;
}

.card .label {
    color: #52606d;
    font-size: 12px;
    text-transform: uppercase;
}

.card .value {
    color: #102a43;
    font-size: 24px;
    font-weight: 700;
    margin-top: 4px;
}

table {
    border-collapse: collapse;
    font-size: 13px;
    width: 100%;
}

th {
    background: #243b53;
    color: #ffffff;
    position: sticky;
    top: 0;
}

th, td {
    border: 1px solid #d9e2ec;
    padding: 8px 10px;
    text-align: left;
    vertical-align: top;
}

tr:nth-child(even) {
    background: #f8fafc;
}

.sev-critical td {
    background: #ffebe6;
}

.sev-high td {
    background: #fff1e6;
}

.sev-medium td {
    background: #fffbea;
}

.sev-low td {
    background: #edf8ff;
}

.sev-info td {
    background: #f7f7f7;
}

.muted {
    color: #627d98;
}

.note {
    background: #edf8ff;
    border-left: 4px solid #2680c2;
    color: #243b53;
    padding: 10px 12px;
}
'@

$summaryCards = @"
<div class='cards'>
    <div class='card'><div class='label'>Domain Controllers</div><div class='value'>$($architectureCounts.DomainControllers)</div></div>
    <div class='card'><div class='label'>Global Catalogs</div><div class='value'>$($architectureCounts.GlobalCatalogs)</div></div>
    <div class='card'><div class='label'>Enabled Users</div><div class='value'>$($architectureCounts.EnabledUsers)</div></div>
    <div class='card'><div class='label'>Stale Users</div><div class='value'>$($architectureCounts.StaleEnabledUsers)</div></div>
    <div class='card'><div class='label'>Groups</div><div class='value'>$($architectureCounts.Groups)</div></div>
    <div class='card'><div class='label'>Sites</div><div class='value'>$($architectureCounts.Sites)</div></div>
    <div class='card'><div class='label'>Site Links</div><div class='value'>$($architectureCounts.SiteLinks)</div></div>
    <div class='card'><div class='label'>DNS Zones</div><div class='value'>$($architectureCounts.DnsZones)</div></div>
    <div class='card'><div class='label'>Findings</div><div class='value'>$($architectureCounts.Findings)</div></div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AD Architecture Assessment - $(ConvertTo-HtmlText $domain.DNSRoot)</title>
<style>
$css
</style>
</head>
<body>
<header>
    <h1>Active Directory Architecture Assessment</h1>
    <p>Domain: $(ConvertTo-HtmlText $domain.DNSRoot) | Query DC: $(ConvertTo-HtmlText $script:QueryServer) | Generated: $(ConvertTo-HtmlText (Get-Date))</p>
</header>
<main>
<section>
    <h2>Executive Summary</h2>
    $summaryCards
    <p class="note">This report is read-only. Port checks are TCP reachability checks from the assessment host, not a full port scan. Service recommendations are review items and do not make changes.</p>
</section>

<section>
    <h2>Executive Finding Groups</h2>
    <p class="muted">Findings are grouped into architecture risk, security hardening, topology/replication, and cleanup/hygiene categories so the remediation plan can be assigned to the right owners.</p>
    $(ConvertTo-HtmlTable -Data $executiveCategorySummary)
</section>

<section>
    <h2>Critical Architecture Risks</h2>
    $(ConvertTo-HtmlTable -Data $criticalArchitectureFindings -Properties @('Severity', 'Area', 'ObjectName', 'Finding', 'Evidence', 'Recommendation') -EmptyMessage 'No critical architecture risk findings were generated.')
</section>

<section>
    <h2>Security Hardening Items</h2>
    $(ConvertTo-HtmlTable -Data $securityHardeningFindings -Properties @('Severity', 'Area', 'ObjectName', 'Finding', 'Evidence', 'Recommendation') -EmptyMessage 'No security hardening findings were generated.')
</section>

<section>
    <h2>AD Topology And Replication Issues</h2>
    $(ConvertTo-HtmlTable -Data $topologyReplicationFindings -Properties @('Severity', 'Area', 'ObjectName', 'Finding', 'Evidence', 'Recommendation') -EmptyMessage 'No topology or replication findings were generated.')
</section>

<section>
    <h2>Cleanup And Hygiene Tasks</h2>
    $(ConvertTo-HtmlTable -Data $cleanupHygieneFindings -Properties @('Severity', 'Area', 'ObjectName', 'Finding', 'Evidence', 'Recommendation') -EmptyMessage 'No cleanup or hygiene findings were generated.')
</section>

<section>
    <h2>Finding Severity Summary</h2>
    $(ConvertTo-HtmlTable -Data $findingSeveritySummary)
</section>

<section>
    <h2>Findings</h2>
    $(ConvertTo-HtmlTable -Data $findingsSorted -EmptyMessage 'No findings were generated.')
</section>

<section>
    <h2>Domain And Forest</h2>
    $(ConvertTo-HtmlTable -Data @($domainSummary))
</section>

<section>
    <h2>Architecture Counts</h2>
    $(ConvertTo-HtmlTable -Data @($architectureCounts))
</section>

<section>
    <h2>Account And Object Summary</h2>
    $(ConvertTo-HtmlTable -Data @($accountSummary))
</section>

<section>
    <h2>Domain Controllers</h2>
    $(ConvertTo-HtmlTable -Data @($dcInventory))
</section>

<section>
    <h2>AD Sites</h2>
    $(ConvertTo-HtmlTable -Data @($siteSummary))
</section>

<section>
    <h2>AD Site Links</h2>
    $(ConvertTo-HtmlTable -Data @($siteLinkSummary))
</section>

<section>
    <h2>Groups By Location</h2>
    $(ConvertTo-HtmlTable -Data @($groupByOu))
</section>

<section>
    <h2>Privileged Groups</h2>
    $(ConvertTo-HtmlTable -Data @($privilegedGroupSummary))
</section>

<section>
    <h2>GPO Summary</h2>
    $(ConvertTo-HtmlTable -Data @($gpoSummary))
</section>

<section>
    <h2>DNS Architecture Summary</h2>
    $(ConvertTo-HtmlTable -Data @($dnsArchitectureSummary))
</section>

<section>
    <h2>DNS Zones</h2>
    $(ConvertTo-HtmlTable -Data @($dnsZoneRows))
</section>

<section>
    <h2>DNS Forwarders</h2>
    $(ConvertTo-HtmlTable -Data @($dnsForwarderRows))
</section>

<section>
    <h2>Domain Controller TCP Ports</h2>
    $(ConvertTo-HtmlTable -Data @($portCheckRows))
</section>

<section>
    <h2>Domain Controller Services</h2>
    $(ConvertTo-HtmlTable -Data @($serviceRows))
</section>

<section>
    <h2>Replication Failures</h2>
    $(ConvertTo-HtmlTable -Data @($replicationFailures) -EmptyMessage 'No replication failures were returned by Get-ADReplicationFailure.')
</section>

<section>
    <h2>Replication Partner Metadata</h2>
    $(ConvertTo-HtmlTable -Data @($replicationPartnerSummary))
</section>

<section>
    <h2>Collection Warnings</h2>
    $(ConvertTo-HtmlTable -Data @($script:CollectionWarnings) -EmptyMessage 'No collection warnings were generated.')
</section>
</main>
</body>
</html>
"@

$html | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host ''
Write-Host 'AD architecture assessment completed.'
Write-Host ("Output folder : {0}" -f $runFolder)
Write-Host ("HTML report   : {0}" -f $htmlPath)
Write-Host ("JSON report   : {0}" -f $jsonPath)
Write-Host ("Findings CSV  : {0}" -f $findingsCsvPath)
Write-Host ''
Write-Host 'Finding summary:'
$findingSeveritySummary | Format-Table -AutoSize
