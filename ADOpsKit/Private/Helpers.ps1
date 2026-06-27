# ADOpsKit Private Helpers
# These functions are dot-sourced by ADOpsKit.psm1 and are NOT exported.

# ---------------------------------------------------------------------------
# TCP port testing (consolidates Test-TcpPortWithTimeout / Test-PortWithTimeout
# from Get-InsecureLDAPBinds and Test-DCPortHealth)
# ---------------------------------------------------------------------------

function Test-ADOKTcpPort {
    <#
    .SYNOPSIS
        Tests whether a TCP port is reachable with an async connection and timeout.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateRange(1, 300)]
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

# ---------------------------------------------------------------------------
# TCP port test that returns a rich result object
# (used by Get-ADArchitectureAssessment)
# ---------------------------------------------------------------------------

function Test-ADOKTcpPortDetail {
    <#
    .SYNOPSIS
        Tests a TCP port and returns a PSCustomObject with Open/Status/ResponseMs.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateRange(100, 30000)]
        [int]$TimeoutMs = 1000
    )

    $started     = Get-Date
    $client      = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null

    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $connected   = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $connected) {
            return [pscustomobject]@{
                ComputerName = $ComputerName
                Port         = $Port
                Open         = $false
                Status       = 'ClosedOrFiltered'
                ResponseMs   = $null
                Error        = 'Connection timed out'
            }
        }

        $client.EndConnect($asyncResult)
        $elapsedMs = [int]((Get-Date) - $started).TotalMilliseconds

        return [pscustomobject]@{
            ComputerName = $ComputerName
            Port         = $Port
            Open         = $true
            Status       = 'Open'
            ResponseMs   = $elapsedMs
            Error        = ''
        }
    }
    catch {
        return [pscustomobject]@{
            ComputerName = $ComputerName
            Port         = $Port
            Open         = $false
            Status       = 'ClosedOrFiltered'
            ResponseMs   = $null
            Error        = $_.Exception.Message
        }
    }
    finally {
        if ($asyncResult -and $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }
        if ($client) { $client.Close() }
    }
}

# ---------------------------------------------------------------------------
# XML / HTML escaping
# (from Get-ADReplicationTopologyDiagram's Esc-Xml)
# ---------------------------------------------------------------------------

function ConvertTo-ADOKXmlEscaped {
    <#
    .SYNOPSIS
        Escapes a string for safe embedding in XML/HTML attribute or text content.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$s)
    $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

# ---------------------------------------------------------------------------
# Console step / status helpers
# (from Get-ADReplicationTopologyDiagram's Write-Step / Write-Ok / Write-Warn)
# ---------------------------------------------------------------------------

function Write-ADOKStep {
    <#
    .SYNOPSIS
        Writes a cyan [*] progress step to the host.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$M)
    Write-Host "  [*] $M" -ForegroundColor Cyan
}

function Write-ADOKOk {
    <#
    .SYNOPSIS
        Writes a green [+] success message to the host.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$M)
    Write-Host "  [+] $M" -ForegroundColor Green
}

function Write-ADOKWarn {
    <#
    .SYNOPSIS
        Writes a yellow [!] warning message to the host.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$M)
    Write-Host "  [!] $M" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# LDAP helpers
# (from Get-ADReplicationTopologyDiagram)
# ---------------------------------------------------------------------------

function New-ADOKLdapSearcher {
    <#
    .SYNOPSIS
        Creates a System.DirectoryServices.DirectorySearcher bound to an LDAP path.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param(
        [string]   $Server,
        [string]   $BaseDN,
        [string]   $Filter,
        [string[]] $Props,
        [string]   $Scope = 'Subtree'
    )
    $entry    = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$BaseDN")
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
    $searcher.Filter      = $Filter
    $searcher.SearchScope = $Scope
    $searcher.PageSize    = 500
    foreach ($p in $Props) { [void]$searcher.PropertiesToLoad.Add($p) }
    $searcher
}

function Get-ADOKLdapAttr {
    <#
    .SYNOPSIS
        Reads a single string attribute from an LDAP distinguished name.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$Server, [string]$DN, [string]$Attr)
    try {
        $e = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$DN")
        $e.RefreshCache([string[]]@($Attr))
        if ($e.Properties[$Attr].Count -gt 0) { [string]$e.Properties[$Attr][0] } else { '' }
    } catch { '' }
}

function ConvertFrom-ADOKDistinguishedName {
    <#
    .SYNOPSIS
        Converts a naming context like DC=Karanth,DC=Lab to Karanth.Lab.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$DN)
    ($DN -split ',' | Where-Object { $_ -match '^DC=' } |
        ForEach-Object { ($_ -split '=', 2)[1] }) -join '.'
}

function Get-ADOKDcNameFromNtdsDN {
    <#
    .SYNOPSIS
        Extracts the DC short-name from an NTDS Settings distinguished name.
    .NOTES
        Internal ADOpsKit helper. Not exported.
    #>
    param([string]$DN)
    $m = [regex]::Match($DN, 'CN=NTDS Settings,CN=([^,]+)')
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}
