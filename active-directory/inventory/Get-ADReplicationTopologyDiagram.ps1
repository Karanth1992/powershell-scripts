<#
.SYNOPSIS
    Discovers all domain controllers in the forest, collects their replication
    partnerships, and produces a self-contained HTML diagram of the topology.

.DESCRIPTION
    Uses only LDAP (port 389) and repadmin.exe - no ADWS, no WinRM required.

    For every domain controller found the script collects:
      - Hostname, FQDN, IPv4 address (via DNS)
      - AD site membership
      - FSMO roles held (via LDAP fSMORoleOwner attributes)
      - Operating system (via LDAP computer object)
      - GC / RODC flags (via NTDS Settings options attribute)
      - Inbound replication partners and failure counts (repadmin /showrepl)
      - Site links between sites (LDAP Inter-Site Transports container)

    Output is a fully self-contained HTML file with an inline SVG diagram.
    No internet connection or browser plugins required.

    The script is read-only - it does not modify any AD object.

.PARAMETER DomainController
    FQDN or IP of a domain controller to use for LDAP queries.
    Defaults to the PDC emulator discovered automatically.

.PARAMETER OutputFolder
    Directory where the HTML report is written.
    Defaults to the current working directory.

.PARAMETER IncludeAllDomains
    When specified the script queries every domain in the forest via its
    crossRef objects, not just the current domain.

.EXAMPLE
    .\Get-ADReplicationTopologyDiagram.ps1

.EXAMPLE
    .\Get-ADReplicationTopologyDiagram.ps1 -OutputFolder "C:\Reports" -IncludeAllDomains

.NOTES
    Requirements:
      - repadmin.exe  (available on any Windows Server or RSAT install)
      - LDAP port 389 reachable on the target DC
      - Domain User rights minimum; Replicating Directory Changes for full replication data
#>

[CmdletBinding()]
param(
    [string]$DomainController,
    [string]$OutputFolder = (Get-Location).Path,
    [switch]$IncludeAllDomains
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region -- helpers ------------------------------------------------------------

function Write-Step { param([string]$M) Write-Host "  [*] $M" -ForegroundColor Cyan  }
function Write-Ok   { param([string]$M) Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Warn { param([string]$M) Write-Host "  [!] $M" -ForegroundColor Yellow }

# Create a System.DirectoryServices.DirectorySearcher bound to an LDAP path
function New-LdapSearcher {
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

# Read a single string attribute from an LDAP path
function Get-LdapAttr {
    param([string]$Server, [string]$DN, [string]$Attr)
    try {
        $e = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$DN")
        $e.RefreshCache([string[]]@($Attr))
        if ($e.Properties[$Attr].Count -gt 0) { [string]$e.Properties[$Attr][0] } else { '' }
    } catch { '' }
}

# Convert a naming context like DC=Karanth,DC=Lab to Karanth.Lab
function ConvertFrom-DistinguishedName {
    param([string]$DN)
    ($DN -split ',' | Where-Object { $_ -match '^DC=' } |
        ForEach-Object { ($_ -split '=',2)[1] }) -join '.'
}

# Extract the DC short-name from an NTDS Settings distinguished name
function Get-DcNameFromNtdsDN {
    param([string]$DN)
    $m = [regex]::Match($DN, 'CN=NTDS Settings,CN=([^,]+)')
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}

#endregion

#region -- verify repadmin is available ---------------------------------------

if (-not (Get-Command repadmin.exe -ErrorAction SilentlyContinue)) {
    throw "repadmin.exe not found. Install RSAT (AD DS Tools) and re-run."
}

#endregion

#region -- resolve target DC via LDAP -----------------------------------------

Write-Step "Connecting to Active Directory via LDAP ..."

if (-not $DomainController) {
    # Use the .NET ActiveDirectory namespace (LDAP/Kerberos - no ADWS needed)
    try {
        $DomainController = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
    } catch {
        # Fallback: read from the environment and do a DNS lookup
        $DomainController = $env:LOGONSERVER -replace '\\', ''
        if (-not $DomainController) { throw "Cannot determine a domain controller. Pass -DomainController explicitly." }
    }
}

# Read the Root DSE to get naming context paths
$rootDSE   = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DomainController/RootDSE")
$defaultNC = [string]$rootDSE.Properties['defaultNamingContext'][0]
$configNC  = [string]$rootDSE.Properties['configurationNamingContext'][0]
$forestNC  = [string]$rootDSE.Properties['rootDomainNamingContext'][0]
$forestDNS = ConvertFrom-DistinguishedName $forestNC

Write-Ok "DC: $DomainController  Forest: $forestDNS"

#endregion

#region -- collect domains to scan -------------------------------------------

Write-Step "Enumerating domains ..."

# domainInfo: list of @{ DNSRoot; NC; PDC; }
$domainsToScan = [System.Collections.Generic.List[hashtable]]::new()

if ($IncludeAllDomains) {
    # crossRef objects in CN=Partitions,CN=Configuration enumerate all domains
    $crSearcher = New-LdapSearcher `
        -Server  $DomainController `
        -BaseDN  "CN=Partitions,$configNC" `
        -Filter  "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))" `
        -Props   @('dnsRoot','ncName','nETBIOSName')

    foreach ($cr in $crSearcher.FindAll()) {
        $nc      = [string]$cr.Properties['ncname'][0]
        $dns     = [string]$cr.Properties['dnsroot'][0]
        # Find a DC in this domain by querying its PDC FSMO
        $pdcDN   = Get-LdapAttr -Server $DomainController -DN $nc -Attr 'fSMORoleOwner'
        $pdcName = Get-DcNameFromNtdsDN $pdcDN
        if (-not $pdcName) { $pdcName = $DomainController }
        $domainsToScan.Add(@{ DNSRoot = $dns; NC = $nc; PDC = $pdcName })
    }
} else {
    $pdcDN   = Get-LdapAttr -Server $DomainController -DN $defaultNC -Attr 'fSMORoleOwner'
    $pdcName = Get-DcNameFromNtdsDN $pdcDN
    if (-not $pdcName) { $pdcName = $DomainController }
    $domainsToScan.Add(@{ DNSRoot = (ConvertFrom-DistinguishedName $defaultNC); NC = $defaultNC; PDC = $pdcName })
}

Write-Ok ("Domains: " + ($domainsToScan | ForEach-Object { $_.DNSRoot } | Sort-Object) -join ', ')

#endregion

#region -- collect DC inventory via LDAP Sites container ----------------------

Write-Step "Collecting domain controller inventory via LDAP ..."

$allDCs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($domain in $domainsToScan) {
    $queryDC = $domain.PDC

    # --- FSMO role holders (read fSMORoleOwner from 5 well-known objects) ---
    $fsmoMap = @{
        PDCEmulator          = Get-DcNameFromNtdsDN (Get-LdapAttr $queryDC $domain.NC                              'fSMORoleOwner')
        RIDMaster            = Get-DcNameFromNtdsDN (Get-LdapAttr $queryDC "CN=RID Manager`$,CN=System,$($domain.NC)" 'fSMORoleOwner')
        InfrastructureMaster = Get-DcNameFromNtdsDN (Get-LdapAttr $queryDC "CN=Infrastructure,$($domain.NC)"       'fSMORoleOwner')
        SchemaMaster         = Get-DcNameFromNtdsDN (Get-LdapAttr $queryDC "CN=Schema,$configNC"                    'fSMORoleOwner')
        DomainNamingMaster   = Get-DcNameFromNtdsDN (Get-LdapAttr $queryDC "CN=Partitions,$configNC"               'fSMORoleOwner')
    }

    # --- Find all server objects inside CN=Sites (one per DC per site) ---
    $srvSearcher = New-LdapSearcher `
        -Server $queryDC `
        -BaseDN "CN=Sites,$configNC" `
        -Filter "(objectClass=server)" `
        -Props  @('cn','dNSHostName','distinguishedName')

    foreach ($srvObj in $srvSearcher.FindAll()) {
        $name = [string]$srvObj.Properties['cn'][0]
        $fqdn = if ($srvObj.Properties['dnshostname'].Count -gt 0) { [string]$srvObj.Properties['dnshostname'][0] } else { '' }
        $dn   = [string]$srvObj.Properties['distinguishedname'][0]

        # Extract site name: CN=<name>,CN=Servers,CN=<site>,CN=Sites,...
        $siteName = if ($dn -match 'CN=Servers,CN=([^,]+),CN=Sites') { $Matches[1] } else { 'Unknown' }

        # Confirm it has an NTDS Settings child (proves it is an AD DC)
        $ntdsDN = "CN=NTDS Settings,$dn"
        try {
            $ntdsEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$queryDC/$ntdsDN")
            $ntdsEntry.RefreshCache([string[]]@('options','msDS-isRODC'))
        } catch {
            continue   # no NTDS Settings = not a DC
        }

        # GC: bit 0 of the options attribute on NTDS Settings
        $optVal = 0
        if ($ntdsEntry.Properties['options'].Count -gt 0) { $optVal = [int]$ntdsEntry.Properties['options'][0] }
        $isGC = ($optVal -band 1) -eq 1

        # RODC: msDS-isRODC on NTDS Settings
        $isRODC = $false
        if ($ntdsEntry.Properties['msDS-isRODC'].Count -gt 0) {
            $isRODC = [bool]$ntdsEntry.Properties['msDS-isRODC'][0]
        }

        # Resolve FQDN via DNS if missing
        if (-not $fqdn) {
            try { $fqdn = [System.Net.Dns]::GetHostEntry($name).HostName } catch { $fqdn = $name }
        }

        # IPv4 via DNS
        $ipv4 = '(unknown)'
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($fqdn) |
                     Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
            if ($addrs) { $ipv4 = $addrs[0].IPAddressToString }
        } catch { }

        # OS version from computer object in domain NC
        $os = 'Unknown'
        try {
            $compSearch = New-LdapSearcher `
                -Server $queryDC `
                -BaseDN $domain.NC `
                -Filter "(&(objectCategory=computer)(cn=$name))" `
                -Props  @('operatingSystem')
            $compResult = $compSearch.FindOne()
            if ($compResult -and $compResult.Properties['operatingsystem'].Count -gt 0) {
                $os = [string]$compResult.Properties['operatingsystem'][0]
            }
        } catch { }

        # FSMO roles this DC holds
        $fsmoRoles = @()
        foreach ($role in $fsmoMap.Keys) {
            if ($fsmoMap[$role] -eq $name) { $fsmoRoles += $role }
        }

        $allDCs.Add(@{
            HostName     = $fqdn
            Name         = $name
            IPv4         = $ipv4
            Site         = $siteName
            OS           = $os
            Domain       = $domain.DNSRoot
            IsGC         = $isGC
            IsRODC       = $isRODC
            FsmoRoles    = $fsmoRoles
            ReplFailures = 0
        })
    }
}

Write-Ok "Found $($allDCs.Count) domain controller(s)"

#endregion

#region -- build DC name index (short name and FQDN -> HostName) --------------

$dcNameIndex = @{}
foreach ($dc in $allDCs) {
    $dcNameIndex[$dc.Name.ToUpper()]     = $dc.HostName
    $dcNameIndex[$dc.HostName.ToUpper()] = $dc.HostName
}

#endregion

#region -- collect replication partnerships via repadmin ----------------------

Write-Step "Collecting replication topology via repadmin ..."

$replEdges = [System.Collections.Generic.List[hashtable]]::new()

try {
    # repadmin /showrepl * /csv queries every DC in the domain via DRSR/RPC
    # Output columns: Destination DSA Site, Destination DSA, Naming Context,
    #                 Source DSA Site, Source DSA, Transport Type,
    #                 Number of Failures, Last Failure Time, Last Success Time, Last Failure Status
    $rawCsv = & repadmin.exe /showrepl * /csv 2>$null
    $replCSV = $rawCsv | ConvertFrom-Csv

    foreach ($row in $replCSV) {
        $destName = ($row.'Destination DSA').Trim()
        $srcName  = ($row.'Source DSA').Trim()
        if (-not $destName -or -not $srcName) { continue }

        $destFQDN = if ($dcNameIndex.ContainsKey($destName.ToUpper())) { $dcNameIndex[$destName.ToUpper()] } else { $destName }
        $srcFQDN  = if ($dcNameIndex.ContainsKey($srcName.ToUpper()))  { $dcNameIndex[$srcName.ToUpper()]  } else { $srcName  }

        $failures = 0
        if ($row.'Number of Failures') { $failures = [int]($row.'Number of Failures') }

        $lastSuccess = $null
        if ($row.'Last Success Time' -and $row.'Last Success Time' -ne '') {
            try { $lastSuccess = [datetime]$row.'Last Success Time' } catch { }
        }
        $lastAttempt = $null
        if ($row.'Last Failure Time' -and $row.'Last Failure Time' -ne '') {
            try { $lastAttempt = [datetime]$row.'Last Failure Time' } catch { }
        }
        if (-not $lastAttempt -and $lastSuccess) { $lastAttempt = $lastSuccess }

        $replEdges.Add(@{
            Source         = $destFQDN
            Partner        = $srcName
            PartnerFQDN    = $srcFQDN
            Partition      = $row.'Naming Context'
            LastAttempt    = $lastAttempt
            LastSuccess    = $lastSuccess
            ConsecFailures = $failures
        })

        # Accumulate failure counts onto the destination DC
        if ($failures -gt 0) {
            $destDC = $allDCs | Where-Object { $_.HostName -eq $destFQDN -or $_.Name -eq $destName } | Select-Object -First 1
            if ($destDC) { $destDC.ReplFailures += $failures }
        }
    }

    Write-Ok "Found $($replEdges.Count) replication link(s)"
} catch {
    Write-Warn "repadmin /showrepl failed: $_"
}

#endregion

#region -- collect site links via LDAP ----------------------------------------

Write-Step "Collecting site links via LDAP ..."

$siteLinks = [System.Collections.Generic.List[hashtable]]::new()

try {
    $slSearcher = New-LdapSearcher `
        -Server $DomainController `
        -BaseDN "CN=Inter-Site Transports,CN=Sites,$configNC" `
        -Filter "(objectClass=siteLink)" `
        -Props  @('cn','cost','replInterval','siteList')

    foreach ($sl in $slSearcher.FindAll()) {
        $slName  = [string]$sl.Properties['cn'][0]
        $cost    = if ($sl.Properties['cost'].Count -gt 0)        { [int]$sl.Properties['cost'][0] }        else { 100 }
        $freq    = if ($sl.Properties['replinterval'].Count -gt 0) { [int]$sl.Properties['replinterval'][0] } else { 180 }

        # siteList contains DNs of sites; extract just the site name (CN=<site>)
        $siteNames = @()
        foreach ($siteDN in $sl.Properties['sitelist']) {
            if ($siteDN -match '^CN=([^,]+)') { $siteNames += $Matches[1] }
        }

        $siteLinks.Add(@{
            Name      = $slName
            Cost      = $cost
            Frequency = $freq
            Sites     = $siteNames
        })
    }

    Write-Ok "Found $($siteLinks.Count) site link(s)"
} catch {
    Write-Warn "Site link collection failed: $_"
}

#endregion

#region ── group DCs by site for diagram ──────────────────────────────────────

$siteGroups = @{}
foreach ($dc in $allDCs) {
    if (-not $siteGroups.ContainsKey($dc.Site)) { $siteGroups[$dc.Site] = @() }
    $siteGroups[$dc.Site] += $dc
}

#endregion

#region -- build SVG topology diagram -----------------------------------------

Write-Step "Building SVG replication topology diagram ..."

# --- Layout constants (pixels) ---
$dcW       = 210   # DC box width
$dcH       = 62    # DC box height
$dcPadX    = 18    # horizontal padding inside site frame
$dcPadTop  = 36    # space for site label inside frame
$dcGapY    = 14    # gap between DC boxes vertically
$sitePadB  = 16    # bottom padding inside site frame
$siteGapX  = 90    # horizontal gap between site columns
$siteGapY  = 90    # vertical gap between site rows
$maxCols   = 3     # site columns before wrapping
$margin    = 40    # canvas margin

# --- Per-site box dimensions ---
$sortedSites = @($siteGroups.Keys | Sort-Object)
$siteW = $dcW + 2 * $dcPadX

# --- Assign grid positions to sites ---
$siteInfo = [ordered]@{}
$col = 0 ; $row = 0
foreach ($site in $sortedSites) {
    $dcCount = $siteGroups[$site].Count
    $h = $dcPadTop + $dcCount * $dcH + [Math]::Max(0, $dcCount - 1) * $dcGapY + $sitePadB
    $siteInfo[$site] = @{ Col = $col; Row = $row; H = $h; W = $siteW; DCs = $siteGroups[$site] }
    $col++
    if ($col -ge $maxCols) { $col = 0; $row++ }
}

# --- Compute pixel X/Y of each site (align rows by max height in that row) ---
$rowMaxH = @{}
foreach ($s in $siteInfo.Keys) {
    $r = $siteInfo[$s].Row
    if (-not $rowMaxH.ContainsKey($r) -or $siteInfo[$s].H -gt $rowMaxH[$r]) { $rowMaxH[$r] = $siteInfo[$s].H }
}
$rowY = @{} ; $cumY = $margin
foreach ($r in ($rowMaxH.Keys | Sort-Object)) { $rowY[$r] = $cumY ; $cumY += $rowMaxH[$r] + $siteGapY }

foreach ($s in $siteInfo.Keys) {
    $siteInfo[$s].X = $margin + $siteInfo[$s].Col * ($siteW + $siteGapX)
    $siteInfo[$s].Y = $rowY[$siteInfo[$s].Row]
}

# --- Build DC centre-point lookup ---
$dcPos = @{}
foreach ($s in $siteInfo.Keys) {
    $si = $siteInfo[$s]
    for ($i = 0; $i -lt $si.DCs.Count; $i++) {
        $dc = $si.DCs[$i]
        $x1 = $si.X + $dcPadX
        $y1 = $si.Y + $dcPadTop + $i * ($dcH + $dcGapY)
        $dcPos[$dc.HostName] = @{
            X1 = $x1 ; Y1 = $y1
            CX = $x1 + $dcW / 2 ; CY = $y1 + $dcH / 2
            DC = $dc
        }
    }
}

# --- Canvas size ---
$canvasW = $margin
$canvasH = $margin
foreach ($s in $siteInfo.Keys) {
    $si = $siteInfo[$s]
    $rx = $si.X + $si.W + $margin
    $ry = $si.Y + $si.H + $margin
    if ($rx -gt $canvasW) { $canvasW = $rx }
    if ($ry -gt $canvasH) { $canvasH = $ry }
}
# Add room for legend at the bottom
$legendY  = $canvasH + 10
$canvasH  = $legendY + 80

# --- SVG helpers ---
function Esc-Xml { param([string]$s) $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

# --- Build SVG string ---
$svg = [System.Text.StringBuilder]::new()
$null = $svg.AppendLine("<svg xmlns='http://www.w3.org/2000/svg' width='$canvasW' height='$canvasH' font-family='Segoe UI,Arial,sans-serif'>")

# Defs: arrowhead markers
$null = $svg.AppendLine(@"
<defs>
  <marker id='arr' markerWidth='10' markerHeight='7' refX='9' refY='3.5' orient='auto'>
    <polygon points='0 0, 10 3.5, 0 7' fill='#38bdf8'/>
  </marker>
  <marker id='arrFail' markerWidth='10' markerHeight='7' refX='9' refY='3.5' orient='auto'>
    <polygon points='0 0, 10 3.5, 0 7' fill='#f87171'/>
  </marker>
  <filter id='shadow' x='-10%' y='-10%' width='120%' height='120%'>
    <feDropShadow dx='2' dy='2' stdDeviation='3' flood-color='#00000055'/>
  </filter>
</defs>
"@)

# Background
$null = $svg.AppendLine("<rect width='$canvasW' height='$canvasH' fill='#0f172a'/>")

# --- Draw site frames ---
foreach ($s in $siteInfo.Keys) {
    $si   = $siteInfo[$s]
    $x    = $si.X ; $y = $si.Y ; $w = $si.W ; $h = $si.H
    $sEsc = Esc-Xml $s
    $null = $svg.AppendLine("<rect x='$x' y='$y' width='$w' height='$h' rx='10' fill='#1e293b' stroke='#334155' stroke-width='2' filter='url(#shadow)'/>")
    $null = $svg.AppendLine("<text x='$($x + $w/2)' y='$($y + 22)' text-anchor='middle' font-size='13' font-weight='700' fill='#7dd3fc'>Site: $sEsc</text>")
}

# --- Draw DC boxes ---
foreach ($hn in $dcPos.Keys) {
    $p  = $dcPos[$hn]
    $dc = $p.DC
    $x1 = $p.X1 ; $y1 = $p.Y1
    $hasFail = $dc.ReplFailures -gt 0

    $fill   = if ($hasFail) { '#7f1d1d' } else { '#0f3460' }
    $stroke = if ($hasFail) { '#f87171' } else { '#38bdf8' }

    $null = $svg.AppendLine("<rect x='$x1' y='$y1' width='$dcW' height='$dcH' rx='6' fill='$fill' stroke='$stroke' stroke-width='1.5'/>")

    # Hostname (line 1)
    $name = Esc-Xml $dc.Name
    $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 18)' text-anchor='middle' font-size='12' font-weight='700' fill='#e2e8f0'>$name</text>")

    # IP (line 2)
    $ip = Esc-Xml $dc.IPv4
    $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 33)' text-anchor='middle' font-size='10' fill='#94a3b8'>$ip</text>")

    # Badges (line 3)
    $badges = @()
    if ($dc.IsGC)             { $badges += 'GC' }
    if ($dc.IsRODC)           { $badges += 'RODC' }
    if ($dc.FsmoRoles.Count)  { $badges += ($dc.FsmoRoles | ForEach-Object { ($_ -replace 'Master','').Trim() }) }
    if ($dc.ReplFailures -gt 0) { $badges += "FAIL:$($dc.ReplFailures)" }

    if ($badges) {
        $badgeText = Esc-Xml ($badges -join '  ')
        $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 52)' text-anchor='middle' font-size='9' fill='$stroke'>$badgeText</text>")
    }
}

# --- Deduplicate replication edges to one per directed DC pair,
#     keeping the worst (highest) failure count across all naming contexts ---
$uniqueEdgeMap = @{}
foreach ($edge in $replEdges) {
    $srcH = $edge.Source ; $dstH = $edge.PartnerFQDN
    if (-not $srcH -or -not $dstH) { continue }
    $key = "$srcH||$dstH"
    if (-not $uniqueEdgeMap.ContainsKey($key)) {
        $uniqueEdgeMap[$key] = @{} + $edge   # shallow copy of the hashtable
    } else {
        if ($edge.ConsecFailures -gt $uniqueEdgeMap[$key].ConsecFailures) {
            $uniqueEdgeMap[$key].ConsecFailures = $edge.ConsecFailures
            $uniqueEdgeMap[$key].LastAttempt    = $edge.LastAttempt
        }
    }
}

# --- Draw replication arrows (one per directed pair) ---
$drawnPairs = [System.Collections.Generic.HashSet[string]]::new()

foreach ($edge in $uniqueEdgeMap.Values) {
    $srcH = $edge.Source ; $dstH = $edge.PartnerFQDN
    if (-not $dcPos.ContainsKey($srcH) -or -not $dcPos.ContainsKey($dstH)) { continue }

    # Track which undirected pairs have already had one direction drawn
    $pairKey = (($srcH, $dstH | Sort-Object) -join '|')
    $isBidirectional = $drawnPairs.Contains($pairKey)
    $null = $drawnPairs.Add($pairKey)

    $src  = $dcPos[$srcH] ; $dst = $dcPos[$dstH]
    $hasFail   = $edge.ConsecFailures -gt 0
    $arrowId   = if ($hasFail) { 'arrFail' } else { 'arr' }
    $lineColor = if ($hasFail) { '#f87171' } else { '#38bdf8' }
    $dashStyle = if ($hasFail) { "stroke-dasharray='6,4'" } else { '' }

    $x1 = [int]$src.CX ; $y1 = [int]$src.CY
    $x2 = [int]$dst.CX ; $y2 = [int]$dst.CY

    # Bow the curve to one side; flip side for the return arrow so they don't overlap
    $mx  = ($x1 + $x2) / 2 ; $my = ($y1 + $y2) / 2
    $dx  = $x2 - $x1       ; $dy  = $y2 - $y1
    $len = [Math]::Sqrt($dx * $dx + $dy * $dy) ; if ($len -lt 1) { $len = 1 }
    $bow = [Math]::Max(50, $len * 0.4)
    $side = if ($isBidirectional) { -1 } else { 1 }
    $cpx = [int]($mx - $dy / $len * $bow * $side)
    $cpy = [int]($my + $dx / $len * $bow * $side)

    $null = $svg.AppendLine("<path d='M $x1 $y1 Q $cpx $cpy $x2 $y2' fill='none' stroke='$lineColor' stroke-width='1.8' $dashStyle marker-end='url(#$arrowId)' opacity='0.85'/>")
}

# --- Legend ---
$lx = $margin ; $ly = $legendY + 10
$null = $svg.AppendLine("<text x='$lx' y='$($ly - 4)' font-size='11' font-weight='700' fill='#64748b'>Legend</text>")
$null = $svg.AppendLine("<rect x='$lx' y='$ly' width='16' height='12' rx='2' fill='#0f3460' stroke='#38bdf8' stroke-width='1.5'/>")
$null = $svg.AppendLine("<text x='$($lx+22)' y='$($ly+10)' font-size='10' fill='#94a3b8'>Domain Controller</text>")
$null = $svg.AppendLine("<rect x='$($lx+160)' y='$ly' width='16' height='12' rx='2' fill='#7f1d1d' stroke='#f87171' stroke-width='1.5'/>")
$null = $svg.AppendLine("<text x='$($lx+182)' y='$($ly+10)' font-size='10' fill='#94a3b8'>Replication Failure</text>")
$null = $svg.AppendLine("<line x1='$($lx+350)' y1='$($ly+6)' x2='$($lx+380)' y2='$($ly+6)' stroke='#38bdf8' stroke-width='1.8' marker-end='url(#arr)'/>")
$null = $svg.AppendLine("<text x='$($lx+386)' y='$($ly+10)' font-size='10' fill='#94a3b8'>Replication link (OK)</text>")
$null = $svg.AppendLine("<line x1='$($lx+560)' y1='$($ly+6)' x2='$($lx+590)' y2='$($ly+6)' stroke='#f87171' stroke-width='1.8' stroke-dasharray='5,3' marker-end='url(#arrFail)'/>")
$null = $svg.AppendLine("<text x='$($lx+596)' y='$($ly+10)' font-size='10' fill='#94a3b8'>Replication link (FAIL)</text>")

$null = $svg.AppendLine("</svg>")

$svgDiagram = $svg.ToString()

#endregion

#region ── build site link table rows ─────────────────────────────────────────

$siteLinkRows = foreach ($sl in $siteLinks) {
    $sites = $sl.Sites -join ' &lt;-&gt; '
    "<tr><td>$($sl.Name)</td><td>$sites</td><td>$($sl.Cost)</td><td>$($sl.Frequency) min</td></tr>"
}

#endregion

#region ── build DC detail table rows ─────────────────────────────────────────

$dcRows = foreach ($dc in ($allDCs | Sort-Object { $_.Site }, { $_.HostName })) {
    $roles  = if ($dc.FsmoRoles) { $dc.FsmoRoles -join '<br>' } else { '-' }
    $flags  = @()
    if ($dc.IsGC)   { $flags += 'Global Catalog' }
    if ($dc.IsRODC) { $flags += 'RODC' }
    $flagStr = if ($flags) { $flags -join ', ' } else { '-' }
    $failClass = if ($dc.ReplFailures -gt 0) { ' class="fail"' } else { '' }

    "<tr$failClass><td>$($dc.HostName)</td><td>$($dc.IPv4)</td><td>$($dc.Site)</td><td>$($dc.Domain)</td><td>$($dc.OS)</td><td>$flagStr</td><td>$roles</td><td>$($dc.ReplFailures)</td></tr>"
}

#endregion

#region ── build replication edge table rows ──────────────────────────────────

$edgeRows = foreach ($edge in ($replEdges | Sort-Object Source)) {
    $lastOk   = if ($edge.LastSuccess)  { $edge.LastSuccess.ToString('yyyy-MM-dd HH:mm') } else { '-' }
    $lastTry  = if ($edge.LastAttempt)  { $edge.LastAttempt.ToString('yyyy-MM-dd HH:mm') } else { '-' }
    $failCls  = if ($edge.ConsecFailures -gt 0) { ' class="fail"' } else { '' }
    "<tr$failCls><td>$($edge.Source)</td><td>$($edge.PartnerFQDN)</td><td>$($edge.Partition)</td><td>$lastTry</td><td>$lastOk</td><td>$($edge.ConsecFailures)</td></tr>"
}

#endregion

#region ── assemble HTML ──────────────────────────────────────────────────────

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$forestName  = $forestDNS

$dcRowsHtml     = $dcRows     -join "`n      "
$edgeRowsHtml   = $edgeRows   -join "`n      "
$siteLinkRowsHtml = $siteLinkRows -join "`n      "

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Replication Topology - $forestName</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Segoe UI, Arial, sans-serif; background: #0f172a; color: #e2e8f0; }

  header { background: #1e293b; padding: 20px 32px; border-bottom: 1px solid #334155; }
  header h1 { font-size: 1.5rem; font-weight: 700; color: #38bdf8; }
  header p  { font-size: .85rem; color: #94a3b8; margin-top: 4px; }

  nav { display: flex; gap: 8px; padding: 14px 32px; background: #1e293b; border-bottom: 1px solid #334155; flex-wrap: wrap; }
  nav a { color: #38bdf8; font-size: .83rem; text-decoration: none; padding: 4px 12px; border: 1px solid #334155; border-radius: 4px; }
  nav a:hover { background: #334155; }

  section { padding: 28px 32px; }
  section h2 { font-size: 1.1rem; font-weight: 600; color: #7dd3fc; margin-bottom: 16px; border-left: 3px solid #38bdf8; padding-left: 10px; }

  .diagram-wrap { overflow-x: auto; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; }

  table { width: 100%; border-collapse: collapse; font-size: .82rem; }
  th { background: #1e3a5f; color: #93c5fd; padding: 8px 10px; text-align: left; white-space: nowrap; }
  td { padding: 7px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  tr:nth-child(even) td { background: #0f1f35; }
  tr.fail td { background: #3b1010 !important; color: #fca5a5; }

  footer { text-align: center; padding: 20px; font-size: .75rem; color: #475569; border-top: 1px solid #1e293b; }
</style>
</head>
<body>

<header>
  <h1>Active Directory Replication Topology</h1>
  <p>Forest: <strong>$forestName</strong> &nbsp;|&nbsp; Generated: $generatedAt &nbsp;|&nbsp; Source DC: $DomainController</p>
</header>

<nav>
  <a href="#diagram">Topology Diagram</a>
  <a href="#dcs">Domain Controllers</a>
  <a href="#replication">Replication Links</a>
  <a href="#sitelinks">Site Links</a>
</nav>

<section id="diagram">
  <h2>Replication Topology Diagram</h2>
  <p style="font-size:.8rem;color:#64748b;margin-bottom:14px;">
    Each box is a domain controller grouped by AD site.
    Arrows show replication flow (curved = bidirectional where both DCs replicate from each other).
    Red boxes = consecutive replication failures. Dashed red arrows = failing replication links.
  </p>
  <div class="diagram-wrap">
$svgDiagram
  </div>
</section>

<section id="dcs">
  <h2>Domain Controllers ($($allDCs.Count))</h2>
  <table>
    <thead>
      <tr>
        <th>Hostname</th><th>IPv4</th><th>Site</th><th>Domain</th>
        <th>OS</th><th>Flags</th><th>FSMO Roles</th><th>Repl Failures</th>
      </tr>
    </thead>
    <tbody>
      $dcRowsHtml
    </tbody>
  </table>
</section>

<section id="replication">
  <h2>Replication Partnerships ($($replEdges.Count))</h2>
  <table>
    <thead>
      <tr>
        <th>DC (Inbound)</th><th>Partner (Source)</th><th>Partition</th>
        <th>Last Attempt</th><th>Last Success</th><th>Consec. Failures</th>
      </tr>
    </thead>
    <tbody>
      $edgeRowsHtml
    </tbody>
  </table>
</section>

<section id="sitelinks">
  <h2>Site Links ($($siteLinks.Count))</h2>
  <table>
    <thead>
      <tr><th>Name</th><th>Sites</th><th>Cost</th><th>Frequency</th></tr>
    </thead>
    <tbody>
      $siteLinkRowsHtml
    </tbody>
  </table>
</section>

<footer>Generated by Get-ADReplicationTopologyDiagram.ps1 &nbsp;|&nbsp; $generatedAt</footer>
</body>
</html>
"@

#endregion

#region ── write output ───────────────────────────────────────────────────────

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputFile = Join-Path $OutputFolder "ADReplicationTopology_$timestamp.html"

$html | Out-File -FilePath $outputFile -Encoding utf8 -Force
Write-Ok "Report written to: $outputFile"

#endregion

#region ── console summary ────────────────────────────────────────────────────

Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host "  |   AD Replication Topology - Summary      |" -ForegroundColor Cyan
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host "  Forest           : $forestName"
Write-Host "  Domains scanned  : $($domainsToScan.Count)"
Write-Host "  Domain controllers: $($allDCs.Count)"
Write-Host "  Replication links : $($replEdges.Count)"
Write-Host "  Site links        : $($siteLinks.Count)"

$failingDCs = $allDCs | Where-Object { $_.ReplFailures -gt 0 }
if ($failingDCs) {
    Write-Host ""
    Write-Host "  DCs with replication failures:" -ForegroundColor Yellow
    foreach ($dc in $failingDCs) {
        Write-Host ("    - {0}  ({1} failure(s))" -f $dc.HostName, $dc.ReplFailures) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Output: $outputFile" -ForegroundColor Green

#endregion
