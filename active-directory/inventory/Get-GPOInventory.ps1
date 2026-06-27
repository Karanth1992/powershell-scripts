<#
.SYNOPSIS
    Generates a full GPO inventory for an Active Directory domain
    and exports it as a styled HTML report.

.DESCRIPTION
    Collects the following for every GPO in the domain:
    - Creation and modification timestamps
    - OU links (including domain root links)
    - Computer and user settings status
    - Applied permissions and trustees
    - WMI filter name and query

    Outputs a colour-coded HTML report to a local path.

.PARAMETER DomainName
    The fully qualified domain name to inventory.
    Example: "corp.contoso.com"

.PARAMETER OutputPath
    Path to write the HTML report.
    Defaults to C:\temp\GPOInventory.html

.EXAMPLE
    .\Get-GPOInventory.ps1 -DomainName "corp.contoso.com"
    Generates inventory for the specified domain.

.EXAMPLE
    .\Get-GPOInventory.ps1 -DomainName "corp.contoso.com" -OutputPath "D:\Reports\GPOInventory.html"
    Generates inventory and writes to a custom path.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.1
    Requires: ActiveDirectory module, GroupPolicy module,
              read access to AD and GPO objects,
              run as Domain Admin or equivalent
#>
<#
.SYNOPSIS
    Generates a full GPO inventory for an Active Directory domain
    and exports it as a styled HTML report.

.EXAMPLE
    .\Get-GPOInventory.ps1 -DomainName "karanth.lab"

.EXAMPLE
    .\Get-GPOInventory.ps1 -DomainName "karanth.lab" -OutputPath "D:\Reports\GPOInventory.html"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [string]$OutputPath = "C:\temp\GPOInventory.html"
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
        ForEach-Object { $_.Value.Trim('{}').ToLower() }
}

function Get-GPOInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $adDomain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
    $pdc      = [string]$adDomain.PDCEmulator

    Write-Host "Using domain controller: $pdc" -ForegroundColor Yellow

    $allGPOs = Get-GPO -All -Domain $DomainName -Server $pdc -ErrorAction Stop

    Write-Host "Found $($allGPOs.Count) GPO(s)." -ForegroundColor Yellow

    $linkMap = @{}

    foreach ($gpo in $allGPOs) {
        $linkMap[$gpo.Id.Guid.ToString().ToLower()] = New-Object System.Collections.Generic.List[string]
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

    $linkedOUs = Get-ADOrganizationalUnit `
        -LDAPFilter "(gPLink=*)" `
        -Server $pdc `
        -Properties gPLink `
        -ErrorAction Stop

    foreach ($ou in $linkedOUs) {
        foreach ($guid in Get-GuidFromGpLink -GpLink $ou.gPLink) {
            if ($linkMap.ContainsKey($guid)) {
                $linkMap[$guid].Add($ou.DistinguishedName)
            }
        }
    }

    Write-Host "Reading WMI filters..." -ForegroundColor Yellow

    $wmiFilters = Get-ADObject `
        -LDAPFilter "(objectClass=msWMI-Som)" `
        -Server $pdc `
        -Properties msWMI-Name, msWMI-Parm2 `
        -ErrorAction SilentlyContinue

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($gpo in $allGPOs) {
        Write-Host "Processing: $($gpo.DisplayName)" -ForegroundColor Gray

        $permissions = Get-GPPermission `
            -Guid $gpo.Id `
            -All `
            -DomainName $DomainName `
            -Server $pdc `
            -ErrorAction SilentlyContinue |
            Select-Object `
                @{ Name = 'Permission'; Expression = {
                    "$($_.Trustee.Name), $($_.Trustee.SIDType), $($_.Permission), Denied: $($_.Denied)"
                }},
                @{ Name = 'GPOApply'; Expression = {
                    if ($_.Permission -eq 'GpoApply') { $_.Trustee.Name }
                }}

        $gpoGuid = $gpo.Id.Guid.ToString().ToLower()

        if ($linkMap.ContainsKey($gpoGuid)) {
            $links = $linkMap[$gpoGuid] | Sort-Object -Unique
        }
        else {
            $links = @()
        }

        $wmiFilterName = $null
        $wmiQuery      = $null

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

                if ($matchedWmiFilter.'msWMI-Parm2') {
                    $wmiQuery = ($matchedWmiFilter.'msWMI-Parm2' -split 'root\\CIMv2;')[-1]
                }
            }
            catch {
                $wmiQuery = "Could not read WMI query"
            }
        }

        $results.Add([PSCustomObject]@{
            Domain           = $DomainName
            GPOName          = $gpo.DisplayName
            GPOId            = $gpo.Id
            CreationTime     = $gpo.CreationTime
            ModificationTime = $gpo.ModificationTime
            Links            = if ($links.Count -gt 0) { $links -join "`n" } else { "Not linked" }
            ComputerSettings = $gpo.Computer.Enabled
            UserSettings     = $gpo.User.Enabled
            GPOApply         = ($permissions.GPOApply | Where-Object { $_ }) -join "`n"
            Permissions      = $permissions.Permission -join "`n"
            WmiFilter        = $wmiFilterName
            WmiQuery         = $wmiQuery
        })
    }

    return $results
}

$htmlHead = @'
<title>GPO Inventory Report</title>
<style>
body  { font-family:"Segoe UI",Arial,sans-serif; font-size:13px; background:#f3f4f6; color:#22223b; margin:20px; }
h1    { color:#2a394f; border-bottom:2px solid #c9d6e3; padding-bottom:8px; }
h3    { color:#555; font-weight:normal; }
table { border-collapse:collapse; width:100%; background:#fff; margin-top:16px; }
th    { background:#2a394f; color:#fff; padding:10px; text-align:left; font-size:12px; }
td    { border:1px solid #e1e5ee; padding:8px; vertical-align:top; font-size:12px; white-space:pre-line; }
tr:nth-child(even) td { background:#f8f8fc; }
tr:hover td { background:#eaf0fa; }
</style>
'@

$htmlBody = @"
<h1>GPO Inventory Report</h1>
<h3>Domain: $DomainName &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h3>
"@

Write-Host "Collecting GPO inventory for $DomainName..." -ForegroundColor Cyan

$inventory = Get-GPOInventory -DomainName $DomainName

$outputFolder = Split-Path $OutputPath

if (-not (Test-Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

$inventory |
    Sort-Object GPOName |
    ConvertTo-Html `
        -Property Domain, GPOName, GPOId, CreationTime, ModificationTime,
                  Links, ComputerSettings, UserSettings,
                  GPOApply, Permissions, WmiFilter, WmiQuery `
        -Head $htmlHead `
        -Body $htmlBody |
    Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Report written to $OutputPath" -ForegroundColor Green
Write-Host "$($inventory.Count) GPO(s) inventoried." -ForegroundColor Cyan
