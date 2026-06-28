function Set-ADSKNetworkConfig {
<#
.SYNOPSIS
    Configures a static IP address, subnet mask, default gateway, and DNS servers on a network adapter.

.DESCRIPTION
    Sets a static IPv4 configuration on the specified network adapter.
    Removes any existing DHCP-assigned addresses before applying the static config.
    Optionally renames the adapter for clarity.

.PARAMETER AdapterName
    Name of the network adapter to configure. Defaults to the first connected adapter.

.PARAMETER IPAddress
    Static IPv4 address to assign.

.PARAMETER PrefixLength
    Subnet prefix length (e.g. 24 for 255.255.255.0). Defaults to 24.

.PARAMETER DefaultGateway
    Default gateway IPv4 address.

.PARAMETER DnsServers
    Array of DNS server addresses. Example: @('192.168.1.1','8.8.8.8')

.PARAMETER NewAdapterName
    Optional. Renames the adapter after configuration.

.EXAMPLE
    Set-ADSKNetworkConfig -IPAddress '192.168.1.10' -DefaultGateway '192.168.1.1' -DnsServers @('192.168.1.1')

.EXAMPLE
    Set-ADSKNetworkConfig -AdapterName 'Ethernet' -IPAddress '10.0.0.5' -PrefixLength 24 -DefaultGateway '10.0.0.1' -DnsServers @('10.0.0.1','10.0.0.2') -NewAdapterName 'LAN'

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$AdapterName,
        [Parameter(Mandatory)][string]$IPAddress,
        [int]$PrefixLength = 24,
        [Parameter(Mandatory)][string]$DefaultGateway,
        [Parameter(Mandatory)][string[]]$DnsServers,
        [string]$NewAdapterName
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    $adapter = if ($AdapterName) {
        Get-NetAdapter -Name $AdapterName -ErrorAction Stop
    } else {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    }

    if (-not $adapter) { throw "No connected network adapter found." }

    Write-ADSKInfo "Configuring adapter: $($adapter.Name)"

    # Remove existing IP and gateway
    $adapter | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    $adapter | Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    # Set static IP
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IPAddress `
        -PrefixLength $PrefixLength -DefaultGateway $DefaultGateway | Out-Null

    # Set DNS
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServers

    Write-ADSKOk "IP Address  : $IPAddress/$PrefixLength"
    Write-ADSKOk "Gateway     : $DefaultGateway"
    Write-ADSKOk "DNS Servers : $($DnsServers -join ', ')"

    if ($NewAdapterName) {
        Rename-NetAdapter -Name $adapter.Name -NewName $NewAdapterName
        Write-ADSKOk "Adapter renamed to: $NewAdapterName"
    }
}
