function New-ADSKSite {
<#
.SYNOPSIS
    Creates an Active Directory site, subnet, and site link.

.DESCRIPTION
    Creates a new AD site and associates a subnet with it.
    Optionally creates a site link between the new site and an existing site.

.PARAMETER SiteName
    Name of the new AD site.

.PARAMETER SubnetCIDR
    Subnet in CIDR notation. Example: 192.168.10.0/24

.PARAMETER LinkToSite
    Name of an existing site to create a site link to.

.PARAMETER SiteLinkName
    Name for the site link. Defaults to '<SiteName>-<LinkToSite>'.

.PARAMETER SiteLinkCost
    Cost for the site link. Defaults to 100.

.PARAMETER ReplicationInterval
    Replication interval in minutes. Defaults to 15.

.EXAMPLE
    New-ADSKSite -SiteName 'Chennai' -SubnetCIDR '10.10.1.0/24' -LinkToSite 'Default-First-Site-Name'

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: ActiveDirectory module, Domain Admin rights.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)][string]$SubnetCIDR,
        [string]$LinkToSite,
        [string]$SiteLinkName,
        [int]$SiteLinkCost          = 100,
        [int]$ReplicationInterval   = 15
    )

    if (-not $SiteLinkName -and $LinkToSite) { $SiteLinkName = "$SiteName-$LinkToSite" }

    Write-ADSKBanner "Create AD Site"
    Write-ADSKInfo "Site   : $SiteName"
    Write-ADSKInfo "Subnet : $SubnetCIDR"

    # Create site
    $existing = Get-ADReplicationSite -Filter { Name -eq $SiteName } -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADReplicationSite -Name $SiteName
        Write-ADSKOk "Site created: $SiteName"
    } else {
        Write-ADSKWarn "Site already exists: $SiteName"
    }

    # Create subnet
    $existingSub = Get-ADReplicationSubnet -Filter { Name -eq $SubnetCIDR } -ErrorAction SilentlyContinue
    if (-not $existingSub) {
        New-ADReplicationSubnet -Name $SubnetCIDR -Site $SiteName
        Write-ADSKOk "Subnet created: $SubnetCIDR -> $SiteName"
    } else {
        Write-ADSKWarn "Subnet already exists: $SubnetCIDR"
    }

    # Create site link
    if ($LinkToSite) {
        $existingLink = Get-ADReplicationSiteLink -Filter { Name -eq $SiteLinkName } -ErrorAction SilentlyContinue
        if (-not $existingLink) {
            New-ADReplicationSiteLink -Name $SiteLinkName `
                -SitesIncluded @($SiteName, $LinkToSite) `
                -Cost $SiteLinkCost `
                -ReplicationFrequencyInMinutes $ReplicationInterval
            Write-ADSKOk "Site link created: $SiteLinkName (cost: $SiteLinkCost, interval: ${ReplicationInterval}min)"
        } else {
            Write-ADSKWarn "Site link already exists: $SiteLinkName"
        }
    }
}
