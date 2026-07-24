<#
.SYNOPSIS
    Exports Active Directory OU, trust, site/replication, GPO-link, and key
    group membership data to a single JSON snapshot for offline analysis.

.DESCRIPTION
    Stage 1 ("Export") of the ad-doc-generator pipeline. Collects structured,
    read-only data describing the shape of an AD forest so it can be handed
    off to the normalize/analyze/render stages without any further live
    connection to the domain.

    Collects:
    - OU hierarchy               (Get-ADOrganizationalUnit)
    - Trust relationships        (Get-ADTrust)
    - Domain controllers / sites (Get-ADDomainController)
    - Replication sites          (Get-ADReplicationSite)
    - Replication site links     (Get-ADReplicationSiteLink)
    - GPO links per OU           (Get-GPInheritance)
    - Nested membership of key groups (Get-ADGroupMember), for a caller-
      supplied list of group names (typically privileged groups such as
      Domain Admins, Enterprise Admins, Schema Admins).

    This script makes no changes to AD. It does not use WinRM, Invoke-Command,
    or PowerShell remoting - all data comes from the ActiveDirectory and
    GroupPolicy PowerShell modules over standard LDAP/ADWS, which is what
    those modules use internally.

.PARAMETER DomainName
    Optional AD DNS domain name. If omitted, the current logon domain is used.

.PARAMETER Server
    Optional AD server (domain controller) to query. If omitted, the
    ActiveDirectory module selects a server automatically.

.PARAMETER KeyGroupNames
    Names of groups whose nested membership should be captured, typically
    high-privilege groups. Defaults to the well-known forest/domain admin
    groups. Groups that do not exist in the target domain are skipped and
    recorded as a collection warning rather than failing the run.

.PARAMETER OutputFolder
    Folder where the JSON snapshot is written.
    Defaults to C:\Temp\Reports\ADDocGenerator per workspace convention.

.PARAMETER OutputFileName
    Base file name (without extension) for the JSON snapshot. A timestamp is
    appended automatically. Defaults to "ADTopologyExport".

.EXAMPLE
    .\Get-ADTopologyExport.ps1

    Exports topology data for the current logon domain to the default
    output folder.

.EXAMPLE
    .\Get-ADTopologyExport.ps1 -DomainName "corp.contoso.com" -Server "DC01.corp.contoso.com"

.EXAMPLE
    .\Get-ADTopologyExport.ps1 -KeyGroupNames "Domain Admins","Enterprise Admins","Schema Admins","Server Admins"

.NOTES
    Author:   K Shankar R Karanth
    Version:  1.1
    Read-only: Yes. This script makes no changes to Active Directory.
    WinRM:     Not required. No Invoke-Command or PowerShell remoting is used.
    Data sources: ActiveDirectory module (LDAP/ADWS), GroupPolicy module.
    Output: single timestamped JSON file under the output folder, written as
            UTF-8 without a byte-order mark so it parses cleanly with
            downstream tools (e.g. Python's json module, which rejects a BOM
            by default).
    Scope: GPO link discovery is limited to organizational units. Policies
           linked directly at the domain root (e.g. Default Domain Policy)
           are not captured.
    Requires:
    - Windows PowerShell 5.1
    - ActiveDirectory PowerShell module
    - GroupPolicy PowerShell module
    - Read access to the target domain(s)/forest
#>

#requires -Version 5.1
#requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
param(
    [string]$DomainName,

    [string]$Server,

    [ValidateNotNullOrEmpty()]
    [string[]]$KeyGroupNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins'),

    [ValidateNotNullOrEmpty()]
    [string]$OutputFolder = 'C:\Temp\Reports\ADDocGenerator',

    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName = 'ADTopologyExport'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CollectionResult {
    <#
        Builds a single stable result object for one collection step so
        partial failures in one area do not stop the rest of the export.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'New-CollectionResult only constructs an in-memory pscustomobject; it changes no system state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Area,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Healthy', 'Warning', 'Failed', 'Skipped')]
        [string]$Status,

        [AllowNull()]
        [object]$Data,

        [string]$Detail = ''
    )

    [pscustomobject]@{
        Area      = $Area
        Status    = $Status
        Detail    = $Detail
        Timestamp = (Get-Date).ToString('o')
        Data      = $Data
    }
}

function Get-OrganizationalUnitSnapshot {
    [CmdletBinding()]
    param(
        [hashtable]$AdParameters
    )

    try {
        $ouList = @(Get-ADOrganizationalUnit -Filter * @AdParameters -Properties Description, gPLink |
            ForEach-Object {
                [pscustomobject]@{
                    DistinguishedName = $_.DistinguishedName
                    Name              = $_.Name
                    ParentDN          = ($_.DistinguishedName -replace '^OU=[^,]+,', '')
                    Description       = $_.Description
                    HasGpoLink        = -not [string]::IsNullOrEmpty($_.gPLink)
                    Depth             = (($_.DistinguishedName -split ',OU=').Count - 1)
                }
            })

        New-CollectionResult -Area 'OrganizationalUnits' -Status 'Healthy' -Data $ouList `
            -Detail "Collected $($ouList.Count) organizational unit(s)."
    }
    catch {
        Write-Warning "Failed to collect organizational units: $($_.Exception.Message)"
        New-CollectionResult -Area 'OrganizationalUnits' -Status 'Failed' -Data @() -Detail $_.Exception.Message
    }
}

function Get-TrustSnapshot {
    [CmdletBinding()]
    param(
        [hashtable]$AdParameters
    )

    try {
        $trusts = @(Get-ADTrust -Filter * @AdParameters |
            ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    Target            = $_.Target
                    Source            = $_.Source
                    Direction         = $_.Direction.ToString()
                    TrustType         = $_.TrustType.ToString()
                    ForestTransitive  = $_.ForestTransitive
                    SIDFilteringQuarantined = $_.SIDFilteringQuarantined
                    DisallowTransivity      = $_.DisallowTransivity
                }
            })

        New-CollectionResult -Area 'Trusts' -Status 'Healthy' -Data $trusts `
            -Detail "Collected $($trusts.Count) trust relationship(s)."
    }
    catch {
        Write-Warning "Failed to collect AD trusts: $($_.Exception.Message)"
        New-CollectionResult -Area 'Trusts' -Status 'Failed' -Data @() -Detail $_.Exception.Message
    }
}

function Get-DomainControllerSnapshot {
    [CmdletBinding()]
    param(
        [hashtable]$AdParameters
    )

    try {
        $dcs = @(Get-ADDomainController -Filter * @AdParameters |
            ForEach-Object {
                [pscustomobject]@{
                    HostName            = $_.HostName
                    Site                = $_.Site
                    Domain              = $_.Domain
                    IsGlobalCatalog     = $_.IsGlobalCatalog
                    IsReadOnly          = $_.IsReadOnly
                    OperatingSystem     = $_.OperatingSystem
                    OperationMasterRoles = @($_.OperationMasterRoles | ForEach-Object { $_.ToString() })
                    IPv4Address         = $_.IPv4Address
                }
            })

        New-CollectionResult -Area 'DomainControllers' -Status 'Healthy' -Data $dcs `
            -Detail "Collected $($dcs.Count) domain controller(s)."
    }
    catch {
        Write-Warning "Failed to collect domain controllers: $($_.Exception.Message)"
        New-CollectionResult -Area 'DomainControllers' -Status 'Failed' -Data @() -Detail $_.Exception.Message
    }
}

function Get-ReplicationTopologySnapshot {
    [CmdletBinding()]
    param(
        [hashtable]$AdParameters
    )

    $result = [ordered]@{
        Sites     = @()
        SiteLinks = @()
    }
    $status = 'Healthy'
    $detailParts = New-Object System.Collections.ArrayList

    try {
        $sites = @(Get-ADReplicationSite -Filter * @AdParameters |
            ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    DistinguishedName = $_.DistinguishedName
                    Description       = $_.Description
                }
            })
        $result.Sites = $sites
        [void]$detailParts.Add("$($sites.Count) site(s)")
    }
    catch {
        Write-Warning "Failed to collect replication sites: $($_.Exception.Message)"
        $status = 'Warning'
        [void]$detailParts.Add("sites failed: $($_.Exception.Message)")
    }

    try {
        $siteLinks = @(Get-ADReplicationSiteLink -Filter * @AdParameters |
            ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    Cost              = $_.Cost
                    ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
                    SitesIncluded     = @($_.SitesIncluded)
                }
            })
        $result.SiteLinks = $siteLinks
        [void]$detailParts.Add("$($siteLinks.Count) site link(s)")
    }
    catch {
        Write-Warning "Failed to collect replication site links: $($_.Exception.Message)"
        $status = 'Warning'
        [void]$detailParts.Add("site links failed: $($_.Exception.Message)")
    }

    New-CollectionResult -Area 'ReplicationTopology' -Status $status -Data $result `
        -Detail ($detailParts -join '; ')
}

function Get-GpoLinkSnapshot {
    [CmdletBinding()]
    param(
        [string]$DomainNameForGpo
    )

    try {
        $ouDns = @(Get-ADOrganizationalUnit -Filter * -Server $DomainNameForGpo -ErrorAction Stop |
            Select-Object -ExpandProperty DistinguishedName)

        $links = New-Object System.Collections.ArrayList
        foreach ($ouDn in $ouDns) {
            try {
                $inheritance = Get-GPInheritance -Target $ouDn -Domain $DomainNameForGpo -ErrorAction Stop
                foreach ($gpoLink in $inheritance.GpoLinks) {
                    [void]$links.Add([pscustomobject]@{
                        OrganizationalUnit = $ouDn
                        GpoName            = $gpoLink.DisplayName
                        Enabled            = $gpoLink.Enabled
                        Enforced           = $gpoLink.Enforced
                        Order              = $gpoLink.Order
                    })
                }
            }
            catch {
                Write-Warning "Failed to read GPO inheritance for '$ouDn': $($_.Exception.Message)"
            }
        }

        New-CollectionResult -Area 'GpoLinks' -Status 'Healthy' -Data $links `
            -Detail "Collected $($links.Count) GPO link(s) across $($ouDns.Count) OU(s)."
    }
    catch {
        Write-Warning "Failed to enumerate OUs for GPO link collection: $($_.Exception.Message)"
        New-CollectionResult -Area 'GpoLinks' -Status 'Failed' -Data @() -Detail $_.Exception.Message
    }
}

function Get-KeyGroupMembershipSnapshot {
    [CmdletBinding()]
    param(
        [string[]]$GroupNames,
        [hashtable]$AdParameters
    )

    $groupResults = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList

    foreach ($groupName in $GroupNames) {
        try {
            $group = Get-ADGroup -Identity $groupName @AdParameters -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $group -Recursive @AdParameters -ErrorAction Stop |
                ForEach-Object {
                    [pscustomobject]@{
                        Name             = $_.Name
                        SamAccountName   = $_.SamAccountName
                        ObjectClass      = $_.objectClass
                        DistinguishedName = $_.distinguishedName
                    }
                }

            [void]$groupResults.Add([pscustomobject]@{
                GroupName = $groupName
                MemberCount = @($members).Count
                Members     = @($members)
            })
        }
        catch {
            Write-Warning "Skipping group '$groupName': $($_.Exception.Message)"
            [void]$skipped.Add([pscustomobject]@{ GroupName = $groupName; Reason = $_.Exception.Message })
        }
    }

    $status = if ($skipped.Count -gt 0 -and $groupResults.Count -eq 0) { 'Failed' }
              elseif ($skipped.Count -gt 0) { 'Warning' }
              else { 'Healthy' }

    New-CollectionResult -Area 'KeyGroupMembership' -Status $status -Data ([ordered]@{
        Groups  = $groupResults
        Skipped = $skipped
    }) -Detail "Collected $($groupResults.Count) group(s), skipped $($skipped.Count)."
}

try {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
catch {
    throw "Unable to create output folder '$OutputFolder': $($_.Exception.Message)"
}

$adParameters = @{}
if ($PSBoundParameters.ContainsKey('Server')) {
    $adParameters['Server'] = $Server
}
elseif ($PSBoundParameters.ContainsKey('DomainName')) {
    $adParameters['Server'] = $DomainName
}

$gpoDomain = if ($PSBoundParameters.ContainsKey('DomainName')) { $DomainName } else { (Get-ADDomain @adParameters).DNSRoot }

Write-Verbose "Starting AD topology export for domain '$gpoDomain'."

$collectionResults = [ordered]@{
    OrganizationalUnits  = Get-OrganizationalUnitSnapshot -AdParameters $adParameters
    Trusts               = Get-TrustSnapshot -AdParameters $adParameters
    DomainControllers    = Get-DomainControllerSnapshot -AdParameters $adParameters
    ReplicationTopology  = Get-ReplicationTopologySnapshot -AdParameters $adParameters
    GpoLinks             = Get-GpoLinkSnapshot -DomainNameForGpo $gpoDomain
    KeyGroupMembership   = Get-KeyGroupMembershipSnapshot -GroupNames $KeyGroupNames -AdParameters $adParameters
}

$snapshot = [pscustomobject]@{
    SchemaVersion = '1.0'
    ExportedAt    = (Get-Date).ToString('o')
    ExportedBy    = "$env:USERDOMAIN\$env:USERNAME"
    SourceDomain  = $gpoDomain
    Sections      = $collectionResults
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = Join-Path -Path $OutputFolder -ChildPath "$OutputFileName`_$timestamp.json"

try {
    $jsonText = $snapshot | ConvertTo-Json -Depth 10
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outputPath, $jsonText, $utf8NoBom)
    Write-Verbose "AD topology export written to '$outputPath'."
}
catch {
    throw "Failed to write export JSON to '$outputPath': $($_.Exception.Message)"
}

foreach ($key in $collectionResults.Keys) {
    $section = $collectionResults[$key]
    if ($section.Status -ne 'Healthy') {
        Write-Warning "Section '$key' completed with status '$($section.Status)': $($section.Detail)"
    }
}

[pscustomobject]@{
    OutputPath = $outputPath
    Sections   = $collectionResults.Keys
    Status     = if (($collectionResults.Values | Where-Object { $_.Status -eq 'Failed' })) { 'Warning' } else { 'Healthy' }
}
