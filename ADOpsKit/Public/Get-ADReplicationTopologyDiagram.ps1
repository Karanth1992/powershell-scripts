function Get-ADReplicationTopologyDiagram {
<#
.SYNOPSIS
    Discovers all domain controllers in the forest, collects their replication
    partnerships, and produces a self-contained HTML diagram of the topology.

.DESCRIPTION
    Uses only LDAP (port 389) and repadmin.exe - no ADWS, no WinRM required.

    For every domain controller found the function collects:
      - Hostname, FQDN, IPv4 address (via DNS)
      - AD site membership
      - FSMO roles held (via LDAP fSMORoleOwner attributes)
      - Operating system (via LDAP computer object)
      - GC / RODC flags (via NTDS Settings options attribute)
      - Inbound replication partners and failure counts (repadmin /showrepl)
      - Site links between sites (LDAP Inter-Site Transports container)

    Output is a fully self-contained HTML file with an inline SVG diagram.
    No internet connection or browser plugins required.

    The function is read-only - it does not modify any AD object.

.PARAMETER DomainController
    FQDN or IP of a domain controller to use for LDAP queries.
    Defaults to the PDC emulator discovered automatically.

.PARAMETER OutputFolder
    Directory where the HTML report is written.
    Defaults to the current working directory.

.PARAMETER IncludeAllDomains
    When specified the function queries every domain in the forest via its
    crossRef objects, not just the current domain.

.EXAMPLE
    Get-ADReplicationTopologyDiagram

.EXAMPLE
    Get-ADReplicationTopologyDiagram -OutputFolder "C:\Reports" -IncludeAllDomains

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
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

    #region -- verify repadmin is available ---------------------------------------

    if (-not (Get-Command repadmin.exe -ErrorAction SilentlyContinue)) {
        throw "repadmin.exe not found. Install RSAT (AD DS Tools) and re-run."
    }

    #endregion

    #region -- resolve target DC via LDAP -----------------------------------------

    Write-ADOKStep "Connecting to Active Directory via LDAP ..."

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
    $forestDNS = ConvertFrom-ADOKDistinguishedName $forestNC

    Write-ADOKOk "DC: $DomainController  Forest: $forestDNS"

    #endregion

    #region -- collect domains to scan -------------------------------------------

    Write-ADOKStep "Enumerating domains ..."

    # domainInfo: list of @{ DNSRoot; NC; PDC; }
    $domainsToScan = [System.Collections.Generic.List[hashtable]]::new()

    if ($IncludeAllDomains) {
        # crossRef objects in CN=Partitions,CN=Configuration enumerate all domains
        $crSearcher = New-ADOKLdapSearcher `
            -Server  $DomainController `
            -BaseDN  "CN=Partitions,$configNC" `
            -Filter  "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))" `
            -Props   @('dnsRoot','ncName','nETBIOSName')

        foreach ($cr in $crSearcher.FindAll()) {
            $nc      = [string]$cr.Properties['ncname'][0]
            $dns     = [string]$cr.Properties['dnsroot'][0]
            # Find a DC in this domain by querying its PDC FSMO
            $pdcDN   = Get-ADOKLdapAttr -Server $DomainController -DN $nc -Attr 'fSMORoleOwner'
            $pdcName = Get-ADOKDcNameFromNtdsDN $pdcDN
            if (-not $pdcName) { $pdcName = $DomainController }
            $domainsToScan.Add(@{ DNSRoot = $dns; NC = $nc; PDC = $pdcName })
        }
    } else {
        $pdcDN   = Get-ADOKLdapAttr -Server $DomainController -DN $defaultNC -Attr 'fSMORoleOwner'
        $pdcName = Get-ADOKDcNameFromNtdsDN $pdcDN
        if (-not $pdcName) { $pdcName = $DomainController }
        $domainsToScan.Add(@{ DNSRoot = (ConvertFrom-ADOKDistinguishedName $defaultNC); NC = $defaultNC; PDC = $pdcName })
    }

    Write-ADOKOk ("Domains: " + ($domainsToScan | ForEach-Object { $_.DNSRoot } | Sort-Object) -join ', ')

    #endregion

    #region -- collect DC inventory via LDAP Sites container ----------------------

    Write-ADOKStep "Collecting domain controller inventory via LDAP ..."

    $allDCs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($domain in $domainsToScan) {
        $queryDC = $domain.PDC

        # --- FSMO role holders (read fSMORoleOwner from 5 well-known objects) ---
        $fsmoMap = @{
            PDCEmulator          = Get-ADOKDcNameFromNtdsDN (Get-ADOKLdapAttr $queryDC $domain.NC                              'fSMORoleOwner')
            RIDMaster            = Get-ADOKDcNameFromNtdsDN (Get-ADOKLdapAttr $queryDC "CN=RID Manager`$,CN=System,$($domain.NC)" 'fSMORoleOwner')
            InfrastructureMaster = Get-ADOKDcNameFromNtdsDN (Get-ADOKLdapAttr $queryDC "CN=Infrastructure,$($domain.NC)"       'fSMORoleOwner')
            SchemaMaster         = Get-ADOKDcNameFromNtdsDN (Get-ADOKLdapAttr $queryDC "CN=Schema,$configNC"                    'fSMORoleOwner')
            DomainNamingMaster   = Get-ADOKDcNameFromNtdsDN (Get-ADOKLdapAttr $queryDC "CN=Partitions,$configNC"               'fSMORoleOwner')
        }

        # --- Find all server objects inside CN=Sites (one per DC per site) ---
        $srvSearcher = New-ADOKLdapSearcher `
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
            } catch { <# DNS lookup failed — IP stays empty #> }

            # OS version from computer object in domain NC
            $os = 'Unknown'
            try {
                $compSearch = New-ADOKLdapSearcher `
                    -Server $queryDC `
                    -BaseDN $domain.NC `
                    -Filter "(&(objectCategory=computer)(cn=$name))" `
                    -Props  @('operatingSystem')
                $compResult = $compSearch.FindOne()
                if ($compResult -and $compResult.Properties['operatingsystem'].Count -gt 0) {
                    $os = [string]$compResult.Properties['operatingsystem'][0]
                }
            } catch { <# LDAP query failed — OS stays Unknown #> }

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

    Write-ADOKOk "Found $($allDCs.Count) domain controller(s)"

    #endregion

    #region -- build DC name index (short name and FQDN -> HostName) --------------

    $dcNameIndex = @{}
    foreach ($dc in $allDCs) {
        $dcNameIndex[$dc.Name.ToUpper()]     = $dc.HostName
        $dcNameIndex[$dc.HostName.ToUpper()] = $dc.HostName
    }

    #endregion

    #region -- collect replication partnerships via repadmin ----------------------

    Write-ADOKStep "Collecting replication topology via repadmin ..."

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
                try { $lastSuccess = [datetime]$row.'Last Success Time' } catch { <# unparseable date #> }
            }
            $lastAttempt = $null
            if ($row.'Last Failure Time' -and $row.'Last Failure Time' -ne '') {
                try { $lastAttempt = [datetime]$row.'Last Failure Time' } catch { <# unparseable date #> }
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

        Write-ADOKOk "Found $($replEdges.Count) replication link(s)"
    } catch {
        Write-ADOKWarn "repadmin /showrepl failed: $_"
    }

    #endregion

    #region -- collect site links via LDAP ----------------------------------------

    Write-ADOKStep "Collecting site links via LDAP ..."

    $siteLinks = [System.Collections.Generic.List[hashtable]]::new()

    try {
        $slSearcher = New-ADOKLdapSearcher `
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

        Write-ADOKOk "Found $($siteLinks.Count) site link(s)"
    } catch {
        Write-ADOKWarn "Site link collection failed: $_"
    }

    #endregion

    #region -- group DCs by site for diagram --------------------------------------

    $siteGroups = @{}
    foreach ($dc in $allDCs) {
        if (-not $siteGroups.ContainsKey($dc.Site)) { $siteGroups[$dc.Site] = @() }
        $siteGroups[$dc.Site] += $dc
    }

    #endregion

    #region -- build SVG topology diagram (circular / star layout) ----------------

    Write-ADOKStep "Building SVG replication topology diagram ..."

    # --- DC box dimensions ---
    $dcW    = 210
    $dcH    = 68    # slightly taller to fit site label inside the box
    $margin = 60

    # -----------------------------------------------------------------------
    # Identify the PDC emulator - it goes in the centre of the diagram.
    # Fall back to the first DC if no PDC role is found.
    # -----------------------------------------------------------------------
    $pdcDC    = $allDCs | Where-Object { $_.FsmoRoles -contains 'PDCEmulator' } | Select-Object -First 1
    if (-not $pdcDC) { $pdcDC = $allDCs | Select-Object -First 1 }
    $otherDCs = @($allDCs | Where-Object { $_.HostName -ne $pdcDC.HostName } | Sort-Object { $_.Site }, { $_.Name })

    # -----------------------------------------------------------------------
    # Calculate the orbit radius so the outer DC boxes never overlap each other
    # or the centre box.
    # Minimum spacing between adjacent outer boxes = dcW + 30 px gap.
    # Circumference needed = n * (dcW + 30).  radius = circ / (2*pi)
    # -----------------------------------------------------------------------
    $n = $otherDCs.Count
    if ($n -gt 0) {
        $minRadius = [int]([Math]::Max(260, ($n * ($dcW + 40)) / (2 * [Math]::PI)))
    } else {
        $minRadius = 0
    }

    # Canvas: the centre point sits at (cx, cy); we need room on all four sides
    # for the outer boxes plus a margin.
    $cx = $margin + $minRadius + [int]($dcW / 2)
    $cy = $margin + $minRadius + [int]($dcH / 2)
    $canvasW  = $cx * 2
    $legendY  = $cy * 2 + $margin
    $canvasH  = $legendY + 70

    # -----------------------------------------------------------------------
    # Compute pixel positions
    # -----------------------------------------------------------------------
    $dcPos = @{}

    # PDC at the centre
    $dcPos[$pdcDC.HostName] = @{
        X1 = $cx - [int]($dcW / 2)
        Y1 = $cy - [int]($dcH / 2)
        CX = $cx ; CY = $cy
        DC = $pdcDC
    }

    # Outer DCs equally spaced around the orbit, starting at the top (-90 deg)
    for ($i = 0; $i -lt $n; $i++) {
        $angleDeg = -90 + ($i * 360 / $n)
        $angleRad = $angleDeg * [Math]::PI / 180
        $ocx = [int]($cx + $minRadius * [Math]::Cos($angleRad))
        $ocy = [int]($cy + $minRadius * [Math]::Sin($angleRad))
        $dc  = $otherDCs[$i]
        $dcPos[$dc.HostName] = @{
            X1 = $ocx - [int]($dcW / 2)
            Y1 = $ocy - [int]($dcH / 2)
            CX = $ocx ; CY = $ocy
            DC = $dc
        }
    }

    # -----------------------------------------------------------------------
    # Collect site colour palette (cycle through a set of distinct hues)
    # -----------------------------------------------------------------------
    $sitePalette = @(
        @{ Fill='#0c2a4a'; Stroke='#1d6fa4' },   # blue
        @{ Fill='#1a2e1a'; Stroke='#3a8a3a' },   # green
        @{ Fill='#2e1a2e'; Stroke='#9a3a9a' },   # purple
        @{ Fill='#2e2200'; Stroke='#b87a00' },   # amber
        @{ Fill='#002e2e'; Stroke='#009a9a' },   # teal
        @{ Fill='#2e0a00'; Stroke='#c04000' }    # orange
    )
    $siteColorMap = @{}
    $paletteIdx   = 0
    foreach ($site in ($allDCs | ForEach-Object { $_.Site } | Select-Object -Unique | Sort-Object)) {
        $siteColorMap[$site] = $sitePalette[$paletteIdx % $sitePalette.Count]
        $paletteIdx++
    }

    # -----------------------------------------------------------------------
    # Build SVG
    # -----------------------------------------------------------------------
    $svg = [System.Text.StringBuilder]::new()
    $null = $svg.AppendLine("<svg xmlns='http://www.w3.org/2000/svg' width='$canvasW' height='$canvasH' font-family='Segoe UI,Arial,sans-serif'>")

    $null = $svg.AppendLine(@"
<defs>
  <marker id='arr' markerWidth='10' markerHeight='7' refX='9' refY='3.5' orient='auto'>
    <polygon points='0 0, 10 3.5, 0 7' fill='#38bdf8'/>
  </marker>
  <marker id='arrFail' markerWidth='10' markerHeight='7' refX='9' refY='3.5' orient='auto'>
    <polygon points='0 0, 10 3.5, 0 7' fill='#f87171'/>
  </marker>
  <filter id='glow'>
    <feGaussianBlur stdDeviation='3' result='blur'/>
    <feMerge><feMergeNode in='blur'/><feMergeNode in='SourceGraphic'/></feMerge>
  </filter>
  <filter id='shadow' x='-15%' y='-15%' width='130%' height='130%'>
    <feDropShadow dx='2' dy='3' stdDeviation='4' flood-color='#000000aa'/>
  </filter>
</defs>
"@)

    # Background
    $null = $svg.AppendLine("<rect width='$canvasW' height='$canvasH' fill='#0a0f1e'/>")

    # Subtle orbit ring (visual guide)
    if ($n -gt 0) {
        $null = $svg.AppendLine("<circle cx='$cx' cy='$cy' r='$minRadius' fill='none' stroke='#1e293b' stroke-width='1' stroke-dasharray='6,6'/>")
    }

    # -----------------------------------------------------------------------
    # Deduplicate replication edges (one per directed DC pair, worst failures)
    # -----------------------------------------------------------------------
    $uniqueEdgeMap = @{}
    foreach ($edge in $replEdges) {
        $srcH = $edge.Source ; $dstH = $edge.PartnerFQDN
        if (-not $srcH -or -not $dstH) { continue }
        $key = "$srcH||$dstH"
        if (-not $uniqueEdgeMap.ContainsKey($key)) {
            $uniqueEdgeMap[$key] = @{} + $edge
        } else {
            if ($edge.ConsecFailures -gt $uniqueEdgeMap[$key].ConsecFailures) {
                $uniqueEdgeMap[$key].ConsecFailures = $edge.ConsecFailures
                $uniqueEdgeMap[$key].LastAttempt    = $edge.LastAttempt
            }
        }
    }

    # -----------------------------------------------------------------------
    # Draw replication arrows FIRST (so they appear behind the DC boxes)
    # -----------------------------------------------------------------------
    $drawnPairs = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($edge in $uniqueEdgeMap.Values) {
        $srcH = $edge.Source ; $dstH = $edge.PartnerFQDN
        if (-not $dcPos.ContainsKey($srcH) -or -not $dcPos.ContainsKey($dstH)) { continue }

        $pairKey = (($srcH, $dstH | Sort-Object) -join '|')
        $isReturn = $drawnPairs.Contains($pairKey)   # true = second direction of a bidirectional pair
        $null = $drawnPairs.Add($pairKey)

        $src = $dcPos[$srcH] ; $dst = $dcPos[$dstH]
        $hasFail   = $edge.ConsecFailures -gt 0
        $arrowId   = if ($hasFail) { 'arrFail' } else { 'arr' }
        $lineColor = if ($hasFail) { '#f87171' } else { '#38bdf8' }
        $dashStyle = if ($hasFail) { "stroke-dasharray='6,4'" } else { '' }

        $ax1 = [int]$src.CX ; $ay1 = [int]$src.CY
        $ax2 = [int]$dst.CX ; $ay2 = [int]$dst.CY

        # Offset the two directions of a bidirectional pair to avoid overlap.
        # Bow size scales with distance; flip perpendicular side for the return arrow.
        $mdx = $ax2 - $ax1 ; $mdy = $ay2 - $ay1
        $mlen = [Math]::Sqrt($mdx*$mdx + $mdy*$mdy) ; if ($mlen -lt 1) { $mlen = 1 }
        $bow  = [Math]::Max(55, $mlen * 0.38)
        $side = if ($isReturn) { 1 } else { -1 }
        $mcpx = [int](($ax1+$ax2)/2 - $mdy/$mlen * $bow * $side)
        $mcpy = [int](($ay1+$ay2)/2 + $mdx/$mlen * $bow * $side)

        $null = $svg.AppendLine("<path d='M $ax1 $ay1 Q $mcpx $mcpy $ax2 $ay2' fill='none' stroke='$lineColor' stroke-width='2' $dashStyle marker-end='url(#$arrowId)' opacity='0.8'/>")
    }

    # -----------------------------------------------------------------------
    # Draw DC boxes ON TOP of the arrows
    # -----------------------------------------------------------------------
    foreach ($hn in $dcPos.Keys) {
        $p   = $dcPos[$hn]
        $dc  = $p.DC
        $x1  = $p.X1 ; $y1 = $p.Y1
        $isPdc    = ($dc.HostName -eq $pdcDC.HostName)
        $hasFail  = $dc.ReplFailures -gt 0
        $siteCol  = $siteColorMap[$dc.Site]

        # Outer site-coloured glow ring around each box
        $null = $svg.AppendLine("<rect x='$($x1-4)' y='$($y1-4)' width='$($dcW+8)' height='$($dcH+8)' rx='10' fill='$($siteCol.Fill)' stroke='$($siteCol.Stroke)' stroke-width='2' opacity='0.6'/>")

        # Main DC box
        if ($isPdc) {
            # PDC: gold border, slightly larger shadow
            $fill   = if ($hasFail) { '#4a1010' } else { '#1a1a3e' }
            $stroke = if ($hasFail) { '#f87171' } else { '#fbbf24' }
            $null = $svg.AppendLine("<rect x='$x1' y='$y1' width='$dcW' height='$dcH' rx='7' fill='$fill' stroke='$stroke' stroke-width='2.5' filter='url(#shadow)'/>")
        } else {
            $fill   = if ($hasFail) { '#7f1d1d' } else { '#0f2044' }
            $stroke = if ($hasFail) { '#f87171' } else { '#38bdf8' }
            $null = $svg.AppendLine("<rect x='$x1' y='$y1' width='$dcW' height='$dcH' rx='7' fill='$fill' stroke='$stroke' stroke-width='1.5' filter='url(#shadow)'/>")
        }

        # Site name banner at top of box
        $siteEsc = ConvertTo-ADOKXmlEscaped $dc.Site
        $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 13)' text-anchor='middle' font-size='9' fill='$($siteCol.Stroke)' letter-spacing='0.5'>$siteEsc</text>")

        # Thin separator line under site label
        $null = $svg.AppendLine("<line x1='$($x1+8)' y1='$($y1+17)' x2='$($x1+$dcW-8)' y2='$($y1+17)' stroke='$($siteCol.Stroke)' stroke-width='0.5' opacity='0.5'/>")

        # Hostname
        $nameCol  = if ($isPdc) { '#fde68a' } else { '#e2e8f0' }
        $nameEsc  = ConvertTo-ADOKXmlEscaped $dc.Name
        $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 31)' text-anchor='middle' font-size='12' font-weight='700' fill='$nameCol'>$nameEsc</text>")

        # IPv4
        $ipEsc = ConvertTo-ADOKXmlEscaped $dc.IPv4
        $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 45)' text-anchor='middle' font-size='10' fill='#94a3b8'>$ipEsc</text>")

        # Role / badge line
        $badges = @()
        if ($isPdc)               { $badges += 'PDC' }
        if ($dc.IsGC)             { $badges += 'GC' }
        if ($dc.IsRODC)           { $badges += 'RODC' }
        $extraRoles = $dc.FsmoRoles | Where-Object { $_ -ne 'PDCEmulator' } |
                      ForEach-Object { ($_ -replace 'Master','').Trim() }
        if ($extraRoles)          { $badges += $extraRoles }
        if ($dc.ReplFailures -gt 0) { $badges += "FAIL:$($dc.ReplFailures)" }

        if ($badges) {
            $badgeColor = if ($hasFail) { '#f87171' } elseif ($isPdc) { '#fbbf24' } else { '#38bdf8' }
            $badgeEsc   = ConvertTo-ADOKXmlEscaped ($badges -join '  ')
            $null = $svg.AppendLine("<text x='$($x1 + $dcW/2)' y='$($y1 + 60)' text-anchor='middle' font-size='9' fill='$badgeColor' font-weight='600'>$badgeEsc</text>")
        }
    }

    # -----------------------------------------------------------------------
    # Site legend pills (bottom strip)
    # -----------------------------------------------------------------------
    $null = $svg.AppendLine("<text x='$margin' y='$($legendY + 4)' font-size='11' font-weight='700' fill='#475569'>Sites</text>")
    $pillX = $margin + 40 ; $pillY = $legendY - 6
    foreach ($site in ($siteColorMap.Keys | Sort-Object)) {
        $col  = $siteColorMap[$site]
        $sEsc = ConvertTo-ADOKXmlEscaped $site
        $tw   = $sEsc.Length * 7 + 24   # approximate pill width
        $null = $svg.AppendLine("<rect x='$pillX' y='$pillY' width='$tw' height='18' rx='9' fill='$($col.Fill)' stroke='$($col.Stroke)' stroke-width='1.2'/>")
        $null = $svg.AppendLine("<text x='$($pillX + $tw/2)' y='$($pillY + 12)' text-anchor='middle' font-size='10' fill='$($col.Stroke)'>$sEsc</text>")
        $pillX += $tw + 10
    }

    # Replication link legend
    $rx = $margin ; $ry = $legendY + 20
    $null = $svg.AppendLine("<text x='$rx' y='$($ry + 4)' font-size='11' font-weight='700' fill='#475569'>Links</text>")
    $null = $svg.AppendLine("<line x1='$($rx+44)' y1='$($ry+2)' x2='$($rx+76)' y2='$($ry+2)' stroke='#38bdf8' stroke-width='2' marker-end='url(#arr)'/>")
    $null = $svg.AppendLine("<text x='$($rx+82)' y='$($ry+6)' font-size='10' fill='#94a3b8'>Replication OK</text>")
    $null = $svg.AppendLine("<line x1='$($rx+220)' y1='$($ry+2)' x2='$($rx+252)' y2='$($ry+2)' stroke='#f87171' stroke-width='2' stroke-dasharray='5,3' marker-end='url(#arrFail)'/>")
    $null = $svg.AppendLine("<text x='$($rx+258)' y='$($ry+6)' font-size='10' fill='#94a3b8'>Replication FAIL</text>")

    # PDC marker
    $null = $svg.AppendLine("<rect x='$($rx+400)' y='$($ry-6)' width='14' height='14' rx='3' fill='#1a1a3e' stroke='#fbbf24' stroke-width='2'/>")
    $null = $svg.AppendLine("<text x='$($rx+420)' y='$($ry+6)' font-size='10' fill='#94a3b8'>PDC Emulator (centre)</text>")

    $null = $svg.AppendLine("</svg>")
    $svgDiagram = $svg.ToString()

    #endregion

    #region -- build site link table rows -----------------------------------------

    $siteLinkRows = foreach ($sl in $siteLinks) {
        $sites = $sl.Sites -join ' &lt;-&gt; '
        "<tr><td>$($sl.Name)</td><td>$sites</td><td>$($sl.Cost)</td><td>$($sl.Frequency) min</td></tr>"
    }

    #endregion

    #region -- build DC detail table rows -----------------------------------------

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

    #region -- build replication edge table rows ----------------------------------

    $edgeRows = foreach ($edge in ($replEdges | Sort-Object Source)) {
        $lastOk   = if ($edge.LastSuccess)  { $edge.LastSuccess.ToString('yyyy-MM-dd HH:mm') } else { '-' }
        $lastTry  = if ($edge.LastAttempt)  { $edge.LastAttempt.ToString('yyyy-MM-dd HH:mm') } else { '-' }
        $failCls  = if ($edge.ConsecFailures -gt 0) { ' class="fail"' } else { '' }
        "<tr$failCls><td>$($edge.Source)</td><td>$($edge.PartnerFQDN)</td><td>$($edge.Partition)</td><td>$lastTry</td><td>$lastOk</td><td>$($edge.ConsecFailures)</td></tr>"
    }

    #endregion

    #region -- assemble HTML ------------------------------------------------------

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $forestName  = $forestDNS

    $dcRowsHtml       = $dcRows       -join "`n      "
    $edgeRowsHtml     = $edgeRows     -join "`n      "
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

<footer>Generated by Get-ADReplicationTopologyDiagram — ADOpsKit &nbsp;|&nbsp; $generatedAt</footer>
</body>
</html>
"@

    #endregion

    #region -- write output -------------------------------------------------------

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile = Join-Path $OutputFolder "ADReplicationTopology_$timestamp.html"

    $html | Out-File -FilePath $outputFile -Encoding utf8 -Force
    Write-ADOKOk "Report written to: $outputFile"

    #endregion

    #region -- console summary ----------------------------------------------------

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
}
