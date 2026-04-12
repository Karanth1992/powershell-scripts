<#
.SYNOPSIS
    Tests critical port availability across all Active Directory
    domain controllers and outputs a colour-coded summary report.

.DESCRIPTION
    Checks all domain controllers in the current domain against
    a predefined list of ports required for AD health — including
    Kerberos, LDAP, DNS, RPC, SMB, and Global Catalog.

    Uses async TCP connections with a configurable timeout so
    unreachable hosts do not cause the script to hang.

    Outputs results to the console as a colour-coded table and
    optionally exports to CSV.

.PARAMETER TimeoutSeconds
    TCP connection timeout per port in seconds. Default is 3.

.PARAMETER ExportPath
    Optional path to export results as CSV.
    Example: "C:\temp\DCPortHealth.csv"

.EXAMPLE
    .\Test-DCPortHealth.ps1
    Checks all DCs with default 3 second timeout.

.EXAMPLE
    .\Test-DCPortHealth.ps1 -TimeoutSeconds 5 -ExportPath "C:\temp\DCPortHealth.csv"
    Checks all DCs with 5 second timeout and exports to CSV.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ActiveDirectory module, network access to DCs,
              run as Domain Admin or equivalent

    Port reference:
    88    — Kerberos
    53    — DNS
    135   — RPC Endpoint Mapper
    137   — NetBIOS Name Service
    138   — NetBIOS Datagram
    139   — NetBIOS Session
    389   — LDAP
    445   — SMB
    464   — Kerberos Password Change
    636   — LDAPS
    3268  — Global Catalog LDAP
    3269  — Global Catalog LDAPS
    3389  — RDP
#>

param (
    [int]$TimeoutSeconds = 3,
    [string]$ExportPath  = ""
)

Import-Module ActiveDirectory

# ============ PORT DEFINITIONS ============

$portsToCheck = [ordered]@{
    88   = 'Kerberos'
    53   = 'DNS'
    135  = 'RPC'
    137  = 'NetBIOS-NS'
    138  = 'NetBIOS-DGM'
    139  = 'NetBIOS-SSN'
    389  = 'LDAP'
    445  = 'SMB'
    464  = 'Kerberos-PW'
    636  = 'LDAPS'
    3268 = 'GC-LDAP'
    3269 = 'GC-LDAPS'
    3389 = 'RDP'
}

# ============ FUNCTIONS ============

function Test-PortWithTimeout {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutSeconds = 3
    )
    try {
        $tcp  = New-Object System.Net.Sockets.TcpClient
        $iar  = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)
        if (-not $wait) {
            $tcp.Close()
            return $false
        }
        $tcp.EndConnect($iar)
        $tcp.Close()
        return $true
    }
    catch { return $false }
}

# ============ MAIN ============

$domainControllers = Get-ADDomainController -Filter *
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($dc in $domainControllers) {
    Write-Host "`nChecking $($dc.HostName) [$($dc.Site)]..." -ForegroundColor Cyan

    foreach ($port in $portsToCheck.Keys) {
        $serviceName = $portsToCheck[$port]
        $isOpen      = Test-PortWithTimeout -ComputerName $dc.HostName -Port $port -TimeoutSeconds $TimeoutSeconds
        $status      = if ($isOpen) { 'Open' } else { 'Closed' }
        $color        = if ($isOpen) { 'Green' } else { 'Red' }

        Write-Host "  Port $($port.ToString().PadRight(5)) $($serviceName.PadRight(14)) $status" -ForegroundColor $color

        $results.Add([PSCustomObject]@{
            DomainController = $dc.HostName
            Site             = $dc.Site
            Port             = $port
            Service          = $serviceName
            Status           = $status
        })
    }
}

# ============ SUMMARY ============

$closed = $results | Where-Object { $_.Status -eq 'Closed' }

Write-Host "`n===== CLOSED PORTS SUMMARY =====" -ForegroundColor Yellow

if ($closed.Count -eq 0) {
    Write-Host "All ports open on all domain controllers." -ForegroundColor Green
}
else {
    $closed | Sort-Object DomainController, Port |
        Format-Table DomainController, Site, Port, Service, Status -AutoSize
}

# ============ EXPORT ============

if ($ExportPath -ne "") {
    $results | Sort-Object DomainController, Port |
        Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Full results exported to $ExportPath" -ForegroundColor Green
}