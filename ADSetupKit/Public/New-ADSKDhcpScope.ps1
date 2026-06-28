function New-ADSKDhcpScope {
<#
.SYNOPSIS
    Creates and activates a DHCP scope on the local DHCP server.

.DESCRIPTION
    Creates a new IPv4 DHCP scope, sets the IP range, subnet mask, gateway option,
    DNS server option, and activates the scope. Authorises the DHCP server in AD
    if not already authorised.

.PARAMETER ScopeName
    Display name for the DHCP scope.

.PARAMETER StartRange
    First IP address in the lease range.

.PARAMETER EndRange
    Last IP address in the lease range.

.PARAMETER SubnetMask
    Subnet mask. Example: 255.255.255.0

.PARAMETER DefaultGateway
    Default gateway to hand out via DHCP option 3.

.PARAMETER DnsServers
    DNS servers to hand out via DHCP option 6.

.PARAMETER LeaseDurationDays
    Lease duration in days. Defaults to 8.

.EXAMPLE
    New-ADSKDhcpScope -ScopeName 'Office LAN' -StartRange '192.168.1.100' -EndRange '192.168.1.200' -SubnetMask '255.255.255.0' -DefaultGateway '192.168.1.1' -DnsServers @('192.168.1.10')

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: DHCP Server role installed, Run as Administrator.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ScopeName,
        [Parameter(Mandatory)][string]$StartRange,
        [Parameter(Mandatory)][string]$EndRange,
        [Parameter(Mandatory)][string]$SubnetMask,
        [Parameter(Mandatory)][string]$DefaultGateway,
        [Parameter(Mandatory)][string[]]$DnsServers,
        [int]$LeaseDurationDays = 8
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    Write-ADSKBanner "Create DHCP Scope"
    Write-ADSKInfo "Name    : $ScopeName"
    Write-ADSKInfo "Range   : $StartRange - $EndRange"
    Write-ADSKInfo "Mask    : $SubnetMask"
    Write-ADSKInfo "Gateway : $DefaultGateway"
    Write-ADSKInfo "DNS     : $($DnsServers -join ', ')"

    # Derive scope ID from start range
    $scopeId = ($StartRange -split '\.' | Select-Object -First 3) -join '.'
    $scopeId = "$scopeId.0"

    if (-not $PSCmdlet.ShouldProcess("DHCP server", "Create scope '$ScopeName' ($StartRange - $EndRange)")) { return }

    Add-DhcpServerv4Scope -Name $ScopeName `
        -StartRange $StartRange `
        -EndRange   $EndRange `
        -SubnetMask $SubnetMask `
        -LeaseDuration (New-TimeSpan -Days $LeaseDurationDays) `
        -State Active

    Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router $DefaultGateway
    Set-DhcpServerv4OptionValue -ScopeId $scopeId -DnsServer $DnsServers

    Write-ADSKOk "Scope created and activated."

    # Authorise in AD
    try {
        Add-DhcpServerInDC -ErrorAction Stop
        Write-ADSKOk "DHCP server authorised in Active Directory."
    } catch {
        Write-ADSKWarn "Could not authorise DHCP in AD (may already be authorised): $_"
    }
}
