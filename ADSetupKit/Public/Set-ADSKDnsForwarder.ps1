function Set-ADSKDnsForwarder {
<#
.SYNOPSIS
    Sets DNS forwarders on the local DNS server.

.DESCRIPTION
    Replaces the current DNS forwarder list on the local DNS server
    with the specified addresses. Optionally enables or disables the
    root hints fallback.

.PARAMETER Forwarders
    Array of forwarder IP addresses. Example: @('8.8.8.8','8.8.4.4')

.PARAMETER UseRootHints
    If specified, root hints are used when forwarders fail. Default is false.

.EXAMPLE
    Set-ADSKDnsForwarder -Forwarders @('8.8.8.8','8.8.4.4')

.EXAMPLE
    Set-ADSKDnsForwarder -Forwarders @('10.0.0.1') -UseRootHints

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: DNS Server role installed, Run as Administrator.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string[]]$Forwarders,
        [switch]$UseRootHints
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    Write-ADSKBanner "Set DNS Forwarders"
    Write-ADSKInfo "Forwarders    : $($Forwarders -join ', ')"
    Write-ADSKInfo "Use Root Hints: $($UseRootHints.IsPresent)"

    Set-DnsServerForwarder -IPAddress $Forwarders -UseRootHint $UseRootHints.IsPresent
    Write-ADSKOk "DNS forwarders updated."
}
