function Get-InsecureLDAPBinds {
<#
.SYNOPSIS
    Detects insecure LDAP binds across all domain controllers.

.DESCRIPTION
    Queries Event ID 2889 from the Directory Service log on every
    domain controller in the domain. Reports unsigned and simple LDAP
    binds which are a security risk and should be remediated before
    enforcing LDAP signing via Group Policy.

    Performs ping and RPC port 135 connectivity checks before querying
    each DC to avoid hanging on unreachable hosts.

    Output is saved as a dated CSV to the OutputFolder parameter path.

.PARAMETER Hours
    How many hours back to search for events. Defaults to 24.

.PARAMETER OutputPath
    Folder where the CSV output file is written.
    Defaults to C:\ADOpsKit\Reports\Get-InsecureLDAPBinds

.EXAMPLE
    Get-InsecureLDAPBinds
    Checks the last 24 hours across all DCs.

.EXAMPLE
    Get-InsecureLDAPBinds -Hours 72
    Checks the last 72 hours across all DCs.

.EXAMPLE
    Get-InsecureLDAPBinds -Hours 48 -OutputFolder "C:\Reports\LDAP"
    Checks the last 48 hours and writes the CSV to a custom folder.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Run as Domain Admin or equivalent with WMI access to all DCs.
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [Int]$Hours = 24,

        [string]$OutputPath = 'C:\ADOpsKit\Reports\Get-InsecureLDAPBinds'
    )

    Set-StrictMode -Version Latest
    $dateString = Get-Date -Format "yyyy-MM-dd"
    $since      = (Get-Date).AddHours(-$Hours)

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }

    $DomainControllers    = Get-ADDomainController -Filter *
    $AllInsecureLDAPBinds = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($DC in $DomainControllers) {
        $ComputerName = $DC.HostName
        Write-Host "Checking connectivity to $ComputerName..."

        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Write-Warning "$ComputerName is not responding to ping. Skipping."
            continue
        }

        if (-not (Test-ADOKTcpPort -ComputerName $ComputerName -Port 135 -TimeoutSeconds 15)) {
            Write-Warning "Cannot connect to RPC port 135 on $ComputerName. Skipping."
            continue
        }

        Write-Host "Connectivity OK for $ComputerName. Querying event logs via WMI..."

        try {
            $wmiQuery = "SELECT * FROM Win32_NTLogEvent WHERE Logfile='Directory Service' AND EventCode=2889"
            $Events   = Get-WmiObject -ComputerName $ComputerName -Query $wmiQuery -ErrorAction Stop

            $FilteredEvents = $Events | Where-Object {
                $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.TimeGenerated)
                $dt -ge $since
            }
        }
        catch {
            Write-Warning "WMI query failed for $ComputerName : $_"
            continue
        }

        foreach ($LdapEvent in $FilteredEvents) {
          try {
            if (-not $LdapEvent.InsertionStrings -or $LdapEvent.InsertionStrings.Count -lt 3) {
                Write-Warning "Event on $ComputerName has fewer than 3 InsertionStrings (unexpected format) - skipping."
                continue
            }

            $Client      = $LdapEvent.InsertionStrings[0]
            $User        = $LdapEvent.InsertionStrings[1]
            $BindTypeRaw = $LdapEvent.InsertionStrings[2]

            $IPAddress = $null
            $Port      = $null

            if ($Client) {
                # Client can be "ip:port" (IPv4) or "[ipv6]:port" (IPv6, bracketed).
                # Anchor on the trailing ':<port>' rather than a blind LastIndexOf,
                # which mis-splits IPv6 addresses that contain multiple colons.
                if ($Client -match '^\[(?<addr>[0-9A-Fa-f:]+)\]:(?<port>\d+)$') {
                    $IPAddress = $Matches.addr
                    $Port      = $Matches.port
                }
                elseif ($Client -match '^(?<addr>[^:]+):(?<port>\d+)$') {
                    $IPAddress = $Matches.addr
                    $Port      = $Matches.port
                }
                else {
                    # No recognizable trailing port (e.g. bare IPv6 with no port) - keep the raw value.
                    $IPAddress = $Client
                }
            }

            $BindType = switch ($BindTypeRaw) {
                "0"     { "Unsigned" }
                "1"     { "Simple"   }
                default { "Unknown"  }
            }

            $ClientName = $null
            if ($IPAddress) {
                try {
                    $ClientName = ([System.Net.Dns]::GetHostEntry($IPAddress)).HostName
                }
                catch {
                    $ClientName = $null
                }
            }

            $AllInsecureLDAPBinds.Add([PSCustomObject]@{
                DCName     = $ComputerName
                ClientName = $ClientName
                IPAddress  = $IPAddress
                Port       = $Port
                User       = $User
                BindType   = $BindType
            })
          }
          catch {
            Write-Warning "Failed to process an insecure LDAP bind event on $ComputerName : $($_.Exception.Message)"
          }
        }

        Write-Host "Events collected from $ComputerName."
    }

    $outputFile = Join-Path $OutputPath "${dateString}_InsecureLDAPBinds.csv"

    if ($AllInsecureLDAPBinds.Count -gt 0) {
        $AllInsecureLDAPBinds | Export-Csv -NoTypeInformation -LiteralPath $outputFile
        Write-Host "$($AllInsecureLDAPBinds.Count) record(s) saved to $outputFile"
    }
    else {
        Write-Host "No insecure LDAP binds found in the last $Hours hours."
    }
}
