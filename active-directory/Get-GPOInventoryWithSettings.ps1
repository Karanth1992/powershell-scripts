<#
.SYNOPSIS
    Generates a full GPO inventory for an Active Directory domain
    and exports it as a styled HTML report, including configured GPO settings.

.DESCRIPTION
    Collects the following for every GPO in the domain:
    - Creation and modification timestamps
    - OU links, including domain root links
    - Computer and user settings status
    - Applied permissions and trustees
    - WMI filter name and query
    - Configured settings inside the GPO from Get-GPOReport XML

    The ConfiguredSettings column shows settings configured in the GPO.
    It does not calculate Resultant Set of Policy (RSOP), link precedence,
    inheritance, security filtering outcome, or WMI filter pass/fail outcome
    for a specific computer or user.

.PARAMETER DomainName
    The fully qualified domain name to inventory.
    Example: "corp.contoso.com"

.PARAMETER OutputPath
    Path to write the HTML report.
    Defaults to C:\temp\GPOInventoryWithSettings.html

.EXAMPLE
    .\Get-GPOInventoryWithSettings.ps1 -DomainName "corp.contoso.com"

.EXAMPLE
    .\Get-GPOInventoryWithSettings.ps1 -DomainName "corp.contoso.com" -OutputPath "D:\Reports\GPOInventoryWithSettings.html"

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  2.0
    Requires: ActiveDirectory module, GroupPolicy module,
              read access to AD and GPO objects,
              run as Domain Admin or equivalent
#>

#requires -Modules ActiveDirectory, GroupPolicy

param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [string]$OutputPath = "C:\temp\GPOInventoryWithSettings.html"
)

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

function Get-GuidFromGpLink {
    param(
        [string]$GpLink
    )

    if ([string]::IsNullOrWhiteSpace($GpLink)) {
        return @()
    }

    [regex]::Matches($GpLink, '\{[0-9A-Fa-f-]{36}\}') |
        ForEach-Object { $_.Value.Trim('{}').ToLowerInvariant() }
}

function Convert-GpoIdToKey {
    param(
        [Parameter(Mandatory = $true)]
        [object]$GpoId
    )

    try {
        return ([guid]$GpoId).ToString().ToLowerInvariant()
    }
    catch {
        return $GpoId.ToString().Trim('{}').ToLowerInvariant()
    }
}

function ConvertTo-CompactText {
    param(
        [AllowNull()]
        [string]$Text,

        [int]$MaxLength = 240
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $value = ($Text -replace '\s+', ' ').Trim()

    if ($value.Length -gt $MaxLength) {
        return $value.Substring(0, $MaxLength) + "..."
    }

    return $value
}

function Get-XmlElementChildren {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node
    )

    return @(
        $Node.ChildNodes |
            Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }
    )
}

function Get-DirectChildText {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $child = Get-XmlElementChildren -Node $Node |
            Where-Object { $_.LocalName -ieq $name } |
            Select-Object -First 1

        if ($child) {
            $value = ConvertTo-CompactText -Text $child.InnerText

            if ($value) {
                return $value
            }
        }
    }

    return $null
}

function Get-FirstAttributeText {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    if (-not $Node.Attributes) {
        return $null
    }

    foreach ($name in $Names) {
        foreach ($attribute in $Node.Attributes) {
            if ($attribute.LocalName -ieq $name) {
                $value = ConvertTo-CompactText -Text $attribute.Value

                if ($value) {
                    return $value
                }
            }
        }
    }

    return $null
}

function Get-XmlAttributePairs {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [string[]]$SkipNames = @()
    )

    $pairs = [System.Collections.Generic.List[string]]::new()

    if (-not $Node.Attributes) {
        return @()
    }

    foreach ($attribute in $Node.Attributes) {
        if ($attribute.Name -like 'xmlns*') {
            continue
        }

        if ($attribute.Prefix -in @('xmlns', 'xsi', 'xsd')) {
            continue
        }

        if ($SkipNames -icontains $attribute.LocalName) {
            continue
        }

        $value = ConvertTo-CompactText -Text $attribute.Value

        if ($value) {
            $pairs.Add(("{0}={1}" -f $attribute.LocalName, $value))
        }
    }

    return @($pairs)
}

function Get-XmlLeafPairs {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [string[]]$SkipNames = @()
    )

    $pairs = [System.Collections.Generic.List[string]]::new()

    foreach ($child in Get-XmlElementChildren -Node $Node) {
        if ($SkipNames -icontains $child.LocalName) {
            continue
        }

        $grandChildren = Get-XmlElementChildren -Node $child

        if ($grandChildren.Count -gt 0) {
            continue
        }

        $value = ConvertTo-CompactText -Text $child.InnerText

        if ($value) {
            $pairs.Add(("{0}={1}" -f $child.LocalName, $value))
        }
    }

    return @($pairs)
}

function Get-XmlNestedSummaryPairs {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [int]$MaxItems = 12
    )

    $pairs = [System.Collections.Generic.List[string]]::new()
    $skipContainers = @(
        'Category',
        'Explain',
        'Properties',
        'Supported',
        'SupportedOn'
    )
    $skipLeafNames = @(
        'Category',
        'Explain',
        'Supported',
        'SupportedOn'
    )

    foreach ($child in Get-XmlElementChildren -Node $Node) {
        if ($skipContainers -icontains $child.LocalName) {
            continue
        }

        $grandChildren = Get-XmlElementChildren -Node $child

        if ($grandChildren.Count -eq 0) {
            continue
        }

        $childPairs = @(
            (Get-XmlAttributePairs -Node $child) +
            (Get-XmlLeafPairs -Node $child -SkipNames $skipLeafNames)
        )

        if ($childPairs.Count -gt 0) {
            $pairs.Add(("{0}({1})" -f $child.LocalName, ($childPairs -join ', ')))
        }

        if ($pairs.Count -ge $MaxItems) {
            break
        }
    }

    return @($pairs)
}

function Test-IsPolicySettingNode {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node
    )

    if ($Node.NodeType -ne [System.Xml.XmlNodeType]::Element) {
        return $false
    }

    $localName = $Node.LocalName
    $excludedNames = @(
        'Category',
        'DisplayName',
        'Enabled',
        'Explain',
        'Extension',
        'ExtensionData',
        'Filter',
        'FilterDataAvailable',
        'Filters',
        'Name',
        'Properties',
        'State',
        'Supported',
        'SupportedOn',
        'VersionDirectory',
        'VersionSysvol'
    )

    if ($excludedNames -icontains $localName) {
        return $false
    }

    $children = Get-XmlElementChildren -Node $Node

    if ($children.Count -eq 0) {
        return $false
    }

    if ($Node.SelectSingleNode("./*[local-name()='Properties']")) {
        return $true
    }

    $knownSettingContainers = @(
        'Account',
        'Application',
        'AuditSetting',
        'BitLocker',
        'DataSource',
        'DeployedPrinterConnection',
        'Drive',
        'Efs',
        'EnvironmentVariable',
        'EventLog',
        'File',
        'FileSystem',
        'FirewallRule',
        'FirewallSettings',
        'Folder',
        'FolderRedirection',
        'ImmediateTask',
        'Ini',
        'Ipsec',
        'LocalGroup',
        'LocalUser',
        'Package',
        'Policy',
        'Printer',
        'PublicKey',
        'QoSPolicy',
        'Registry',
        'RegistryKey',
        'RestrictedGroups',
        'ScheduledTask',
        'Script',
        'SecurityOptions',
        'Service',
        'SharedPrinter',
        'Shortcut',
        'SoftwareInstallation',
        'SystemServices',
        'TcpIpPrinter',
        'UserRightsAssignment',
        'WiredNetworkPolicy',
        'WirelessNetworkPolicy'
    )

    if ($knownSettingContainers -icontains $localName) {
        return $true
    }

    if ($Node.Attributes) {
        foreach ($attribute in $Node.Attributes) {
            if (@('action', 'displayName', 'hive', 'key', 'name', 'path', 'sourcePath', 'status', 'targetPath', 'value', 'valueName') -icontains $attribute.LocalName) {
                return $true
            }
        }
    }

    $settingName = Get-DirectChildText -Node $Node -Names @('DisplayName', 'Name', 'PolicyName', 'Title')

    if ($settingName) {
        $settingState = Get-DirectChildText -Node $Node -Names @('Action', 'Enabled', 'State')

        if ($settingState) {
            return $true
        }

        foreach ($child in $children) {
            if ($child.LocalName -like 'Setting*') {
                return $true
            }
        }

        if ($children.Count -le 10) {
            return $true
        }
    }

    return $false
}

function Get-PolicySettingCandidateNodes {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Root
    )

    $results = [System.Collections.Generic.List[System.Xml.XmlNode]]::new()

    function Add-PolicySettingNode {
        param(
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlNode]$Node,

            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[System.Xml.XmlNode]]$ResultList
        )

        foreach ($child in Get-XmlElementChildren -Node $Node) {
            if (Test-IsPolicySettingNode -Node $child) {
                $ResultList.Add($child)
                continue
            }

            Add-PolicySettingNode -Node $child -ResultList $ResultList
        }
    }

    Add-PolicySettingNode -Node $Root -ResultList $results

    return @($results)
}

function Format-PolicySetting {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory = $true)]
        [string]$ScopeName,

        [Parameter(Mandatory = $true)]
        [string]$ExtensionName
    )

    $settingType = $Node.LocalName
    $propertiesNode = $Node.SelectSingleNode("./*[local-name()='Properties']")
    $settingName = Get-DirectChildText -Node $Node -Names @('DisplayName', 'Name', 'PolicyName', 'Title')

    if (-not $settingName -and $propertiesNode) {
        $settingName = Get-FirstAttributeText -Node $propertiesNode -Names @(
            'displayName',
            'name',
            'targetPath',
            'path',
            'key',
            'valueName',
            'sourcePath',
            'location'
        )
    }

    if (-not $settingName) {
        $settingName = Get-FirstAttributeText -Node $Node -Names @(
            'displayName',
            'name',
            'targetPath',
            'path',
            'key',
            'valueName',
            'sourcePath',
            'location'
        )
    }

    if (-not $settingName) {
        $settingName = $settingType
    }

    $detailList = [System.Collections.Generic.List[string]]::new()
    $state = Get-DirectChildText -Node $Node -Names @('Action', 'Enabled', 'State')

    if ($state) {
        $detailList.Add(("State={0}" -f $state))
    }

    foreach ($pair in Get-XmlAttributePairs -Node $Node -SkipNames @('clsid', 'uid')) {
        $detailList.Add($pair)
    }

    if ($propertiesNode) {
        foreach ($pair in Get-XmlAttributePairs -Node $propertiesNode -SkipNames @('clsid', 'uid')) {
            $detailList.Add($pair)
        }

        foreach ($pair in Get-XmlLeafPairs -Node $propertiesNode -SkipNames @('DisplayName', 'Explain', 'Name', 'PolicyName', 'Supported', 'SupportedOn', 'Title')) {
            $detailList.Add($pair)
        }
    }

    foreach ($pair in Get-XmlLeafPairs -Node $Node -SkipNames @('Action', 'DisplayName', 'Enabled', 'Explain', 'Name', 'PolicyName', 'State', 'Supported', 'SupportedOn', 'Title')) {
        $detailList.Add($pair)
    }

    foreach ($pair in Get-XmlNestedSummaryPairs -Node $Node) {
        $detailList.Add($pair)
    }

    $details = @($detailList | Where-Object { $_ } | Sort-Object -Unique)

    if ($details.Count -gt 0) {
        return ("{0} | {1} | {2}: {3} | {4}" -f $ScopeName, $ExtensionName, $settingType, $settingName, ($details -join '; '))
    }

    return ("{0} | {1} | {2}: {3}" -f $ScopeName, $ExtensionName, $settingType, $settingName)
}

function Get-GPOConfiguredSettings {
    param(
        [Parameter(Mandatory = $true)]
        [guid]$GpoGuid,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    try {
        $reportXmlText = Get-GPOReport `
            -Guid $GpoGuid `
            -Domain $DomainName `
            -Server $Server `
            -ReportType Xml `
            -ErrorAction Stop

        [xml]$reportXml = $reportXmlText
    }
    catch {
        return [PSCustomObject]@{
            Count    = 0
            Settings = "Could not read settings from GPO report XML: $($_.Exception.Message)"
        }
    }

    $settings = [System.Collections.Generic.List[string]]::new()

    foreach ($scopeName in @('Computer', 'User')) {
        $scopeNode = $reportXml.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='$scopeName']")

        if (-not $scopeNode) {
            continue
        }

        $scopeLabel = $scopeName
        $enabledNode = $scopeNode.SelectSingleNode("./*[local-name()='Enabled']")

        if ($enabledNode -and $enabledNode.InnerText -ieq 'false') {
            $scopeLabel = "$scopeName (scope disabled)"
        }

        $extensionDataNodes = @($scopeNode.SelectNodes("./*[local-name()='ExtensionData']"))

        foreach ($extensionData in $extensionDataNodes) {
            $extensionName = Get-DirectChildText -Node $extensionData -Names @('Name')

            if (-not $extensionName) {
                $extensionName = "Unknown extension"
            }

            $extensionNodes = @($extensionData.SelectNodes("./*[local-name()='Extension']"))

            foreach ($extensionNode in $extensionNodes) {
                $candidateNodes = Get-PolicySettingCandidateNodes -Root $extensionNode

                foreach ($candidateNode in $candidateNodes) {
                    $settingLine = Format-PolicySetting `
                        -Node $candidateNode `
                        -ScopeName $scopeLabel `
                        -ExtensionName $extensionName

                    if ($settingLine) {
                        $settings.Add($settingLine)
                    }
                }
            }
        }
    }

    $uniqueSettings = @($settings | Where-Object { $_ } | Sort-Object -Unique)

    if ($uniqueSettings.Count -eq 0) {
        return [PSCustomObject]@{
            Count    = 0
            Settings = "No configured settings found in GPO report XML"
        }
    }

    return [PSCustomObject]@{
        Count    = $uniqueSettings.Count
        Settings = ($uniqueSettings -join "`n")
    }
}

function Get-WmiFilterQuery {
    param(
        [AllowNull()]
        [object]$WmiFilterObject
    )

    if (-not $WmiFilterObject) {
        return $null
    }

    $rawQuery = [string]$WmiFilterObject.'msWMI-Parm2'

    if ([string]::IsNullOrWhiteSpace($rawQuery)) {
        return $null
    }

    if ($rawQuery -match 'root\\[^;]+;(?<Query>.+)$') {
        return $Matches.Query.Trim(';')
    }

    return $rawQuery
}

function Get-GPOInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $adDomain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
    $pdc = [string]$adDomain.PDCEmulator

    Write-Host "Using domain controller: $pdc" -ForegroundColor Yellow

    $allGPOs = @(
        Get-GPO `
            -All `
            -Domain $DomainName `
            -Server $pdc `
            -ErrorAction Stop
    )

    Write-Host "Found $($allGPOs.Count) GPO(s)." -ForegroundColor Yellow

    $linkMap = @{}

    foreach ($gpo in $allGPOs) {
        $linkMap[(Convert-GpoIdToKey -GpoId $gpo.Id)] = [System.Collections.Generic.List[string]]::new()
    }

    Write-Host "Reading domain root GPO links..." -ForegroundColor Yellow

    $domainObject = Get-ADObject `
        -Identity $adDomain.DistinguishedName `
        -Server $pdc `
        -Properties gPLink `
        -ErrorAction Stop

    foreach ($guid in Get-GuidFromGpLink -GpLink $domainObject.gPLink) {
        if ($linkMap.ContainsKey($guid)) {
            $linkMap[$guid].Add($adDomain.DistinguishedName)
        }
    }

    Write-Host "Reading OU GPO links..." -ForegroundColor Yellow

    $linkedOUs = @(
        Get-ADOrganizationalUnit `
            -LDAPFilter "(gPLink=*)" `
            -Server $pdc `
            -Properties gPLink `
            -ErrorAction Stop
    )

    foreach ($ou in $linkedOUs) {
        foreach ($guid in Get-GuidFromGpLink -GpLink $ou.gPLink) {
            if ($linkMap.ContainsKey($guid)) {
                $linkMap[$guid].Add($ou.DistinguishedName)
            }
        }
    }

    Write-Host "Reading WMI filters..." -ForegroundColor Yellow

    $wmiFilters = @(
        Get-ADObject `
            -LDAPFilter "(objectClass=msWMI-Som)" `
            -Server $pdc `
            -Properties msWMI-Name, msWMI-Parm2 `
            -ErrorAction SilentlyContinue
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $index = 0

    foreach ($gpo in $allGPOs) {
        $index++
        Write-Host ("Processing {0}/{1}: {2}" -f $index, $allGPOs.Count, $gpo.DisplayName) -ForegroundColor Gray

        $permissionRecords = @(
            Get-GPPermission `
                -Guid $gpo.Id `
                -All `
                -DomainName $DomainName `
                -Server $pdc `
                -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [PSCustomObject]@{
                        Permission = "$($_.Trustee.Name), $($_.Trustee.SIDType), $($_.Permission), Denied: $($_.Denied)"
                        GPOApply   = if ($_.Permission -eq 'GpoApply') { $_.Trustee.Name } else { $null }
                    }
                }
        )

        $gpoGuid = Convert-GpoIdToKey -GpoId $gpo.Id

        if ($linkMap.ContainsKey($gpoGuid)) {
            $links = @($linkMap[$gpoGuid] | Sort-Object -Unique)
        }
        else {
            $links = @()
        }

        $wmiFilterName = $null
        $wmiQuery = $null

        if ($gpo.WmiFilter) {
            $wmiFilterName = $gpo.WmiFilter.Name

            try {
                $wmiFilterId = ($gpo.WmiFilter.Path -split '"')[1]

                $matchedWmiFilter = $wmiFilters |
                    Where-Object {
                        $_.Name -eq $wmiFilterId -or
                        $_.'msWMI-Name' -eq $wmiFilterName
                    } |
                    Select-Object -First 1

                $wmiQuery = Get-WmiFilterQuery -WmiFilterObject $matchedWmiFilter
            }
            catch {
                $wmiQuery = "Could not read WMI query"
            }
        }

        $configuredSettings = Get-GPOConfiguredSettings `
            -GpoGuid $gpo.Id `
            -DomainName $DomainName `
            -Server $pdc

        $results.Add([PSCustomObject]@{
            Domain                  = $DomainName
            GPOName                 = $gpo.DisplayName
            GPOId                   = $gpo.Id
            CreationTime            = $gpo.CreationTime
            ModificationTime        = $gpo.ModificationTime
            Links                   = if ($links.Count -gt 0) { $links -join "`n" } else { "Not linked" }
            ComputerSettings        = $gpo.Computer.Enabled
            UserSettings            = $gpo.User.Enabled
            GPOApply                = ($permissionRecords.GPOApply | Where-Object { $_ }) -join "`n"
            Permissions             = if ($permissionRecords.Count -gt 0) { $permissionRecords.Permission -join "`n" } else { "No permissions read" }
            WmiFilter               = $wmiFilterName
            WmiQuery                = $wmiQuery
            ConfiguredSettingsCount = $configuredSettings.Count
            ConfiguredSettings      = $configuredSettings.Settings
        })
    }

    return $results
}

$htmlHead = @'
<title>GPO Inventory With Settings Report</title>
<style>
body  { font-family:"Segoe UI",Arial,sans-serif; font-size:13px; background:#f3f4f6; color:#22223b; margin:20px; }
h1    { color:#2a394f; border-bottom:2px solid #c9d6e3; padding-bottom:8px; }
h3    { color:#555; font-weight:normal; }
p     { max-width:1200px; color:#555; line-height:1.45; }
table { border-collapse:collapse; width:100%; background:#fff; margin-top:16px; table-layout:auto; }
th    { background:#2a394f; color:#fff; padding:10px; text-align:left; font-size:12px; position:sticky; top:0; }
td    { border:1px solid #e1e5ee; padding:8px; vertical-align:top; font-size:12px; white-space:pre-line; }
tr:nth-child(even) td { background:#f8f8fc; }
tr:hover td { background:#eaf0fa; }
</style>
'@

$htmlBody = @"
<h1>GPO Inventory With Settings Report</h1>
<h3>Domain: $DomainName &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h3>
<p>The ConfiguredSettings column lists settings configured inside each GPO from Get-GPOReport XML. It does not calculate RSOP, GPO precedence, inheritance, security filtering outcome, or WMI filter pass/fail outcome for a specific endpoint or user.</p>
"@

Write-Host "Collecting GPO inventory for $DomainName..." -ForegroundColor Cyan

$inventory = Get-GPOInventory -DomainName $DomainName

$outputFolder = Split-Path -Path $OutputPath -Parent

if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

$inventory |
    Sort-Object GPOName |
    ConvertTo-Html `
        -Property Domain, GPOName, GPOId, CreationTime, ModificationTime,
                  Links, ComputerSettings, UserSettings,
                  GPOApply, Permissions, WmiFilter, WmiQuery,
                  ConfiguredSettingsCount, ConfiguredSettings `
        -Head $htmlHead `
        -Body $htmlBody |
    Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Report written to $OutputPath" -ForegroundColor Green
Write-Host "$($inventory.Count) GPO(s) inventoried." -ForegroundColor Cyan
