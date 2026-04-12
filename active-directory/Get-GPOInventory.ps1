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
    Version:  1.0
    Requires: ActiveDirectory module, GroupPolicy module,
              read access to AD and GPO objects,
              run as Domain Admin or equivalent
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$DomainName,

    [string]$OutputPath = "C:\temp\GPOInventory.html"
)

Import-Module ActiveDirectory
Import-Module GroupPolicy

# ============ FUNCTIONS ============

function Get-GPOInventory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )

    $pdc       = (Get-ADDomainController -Discover -Service PrimaryDC -DomainName $DomainName).HostName
    $adDomain  = Get-ADDomain -Identity $DomainName
    $rootGPOs  = $adDomain.LinkedGroupPolicyObjects |
                    ForEach-Object { [regex]::Match($_, '\{.*?\}').Value.Trim('{}') }

    $allGPOs   = Get-GPO -All -Domain $DomainName -Server $pdc

    # Pre-build link map — one AD query instead of one per GPO
    $linkedGPOs = foreach ($gpo in $allGPOs) {
        $links = Get-ADOrganizationalUnit `
                    -Filter "gpLink -like '*$($gpo.Id.ToString('B'))*'" `
                    -Server $pdc |
                    Select-Object -ExpandProperty DistinguishedName
        [PSCustomObject]@{
            DisplayName = $gpo.DisplayName
            Links       = $links
        }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($gpo in $allGPOs) {
        $permissions = Get-GPPermission -Name $gpo.DisplayName -All `
                            -DomainName $DomainName -Server $pdc |
                        Select-Object `
                            @{ l='Permission'; e={ "$($_.Trustee.Name), $($_.Trustee.SIDType), $($_.Permission), Denied: $($_.Denied)" } },
                            @{ l='GPOApply';   e={ if ($_.Permission -eq 'GpoApply') { $_.Trustee.Name } } }

        $links = ($linkedGPOs | Where-Object { $_.DisplayName -eq $gpo.DisplayName }).Links

        if ($gpo.ID.ToString() -in $rootGPOs) {
            $links += $adDomain.DistinguishedName
        }

        # Reset WMI values each iteration to avoid bleed-through
        $wmiFilterName = $null
        $wmiQuery      = $null

        if ($gpo.WmiFilter.Path) {
            try {
                $wmiFilterId   = ($gpo.WmiFilter.Path -split '"')[1]
                $wmiFilterName = $gpo.WmiFilter.Name
                $wmiQuery      = ((Get-ADObject `
                                    -Filter { objectClass -eq 'msWMI-Som' } `
                                    -Server $pdc `
                                    -Properties 'msWMI-Parm2' |
                                  Where-Object { $_.Name -eq $wmiFilterId }).'msWMI-Parm2' `
                                    -split 'root\\CIMv2;')[1]
            }
            catch {
                Write-Warning "Could not retrieve WMI filter for GPO '$($gpo.DisplayName)': $_"
            }
        }

        $results.Add([PSCustomObject]@{
            Domain           = $DomainName
            GPOName          = $gpo.DisplayName
            CreationTime     = $gpo.CreationTime
            ModificationTime = $gpo.ModificationTime
            Links            = $links -join "`n"
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

# ============ HTML STYLING ============

$htmlHead = @'
<title>GPO Inventory Report</title>
<style>
body  { font-family:"Segoe UI",Arial,sans-serif; font-size:13px; background:#f3f4f6; color:#22223b; margin:20px; }
h1    { color:#2a394f; border-bottom:2px solid #c9d6e3; padding-bottom:8px; }
h3    { color:#555; font-weight:normal; }
table { border-collapse:collapse; width:100%; background:#fff; margin-top:16px; }
th    { background:#2a394f; color:#fff; padding:10px; text-align:left; font-size:12px; }
td    { border:1px solid #e1e5ee; padding:8px; vertical-align:top; font-size:12px; }
tr:nth-child(even) td { background:#f8f8fc; }
tr:hover td { background:#eaf0fa; }
.true  { color:#2d7a2d; font-weight:500; }
.false { color:#c0392b; font-weight:500; }
</style>
'@

$htmlBody = @"
<h1>GPO Inventory Report</h1>
<h3>Domain: $DomainName &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h3>
"@

# ============ RUN AND EXPORT ============

Write-Host "Collecting GPO inventory for $DomainName..." -ForegroundColor Cyan

$inventory = Get-GPOInventory -DomainName $DomainName

if (-not (Test-Path (Split-Path $OutputPath))) {
    New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force | Out-Null
}

$inventory |
    Sort-Object GPOName |
    ConvertTo-Html `
        -Property Domain, GPOName, CreationTime, ModificationTime,
                  Links, ComputerSettings, UserSettings,
                  GPOApply, Permissions, WmiFilter, WmiQuery `
        -Head $htmlHead `
        -Body $htmlBody |
    Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Report written to $OutputPath" -ForegroundColor Green
Write-Host "$($inventory.Count) GPO(s) inventoried." -ForegroundColor Cyan