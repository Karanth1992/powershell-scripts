function Get-DCDecommissionReadiness {
    <#
    .SYNOPSIS
        Pre-decommission readiness scan for a Domain Controller.

    .DESCRIPTION
        Collects all relevant information needed before decommissioning a DC:
        - FSMO role holdings
        - Replication health and partners
        - Logon activity (recent authentications)
        - DNS role and zone hosting
        - SYSVOL/DFSR health
        - Site/subnet associations
        - Dependent clients (recent Kerberos/NTLM logons from this DC)
        - Service dependencies (LDAP binds, trust status)
        - Pending replication changes

        Output is written to a timestamped HTML report and a structured PS object.

    .PARAMETER DCName
        FQDN or hostname of the DC to assess.

    .PARAMETER DaysBack
        How many days of event log history to scan. Default: 7.

    .PARAMETER OutputPath
        Folder to write the HTML report. Default: C:\ADOpsKit\Reports\Get-DCDecommissionReadiness.

    .PARAMETER Credential
        Alternate credentials if running from a non-domain-joined machine.

    .EXAMPLE
        Get-DCDecommissionReadiness -DCName "DC01.corp.contoso.com"

    .EXAMPLE
        Get-DCDecommissionReadiness -DCName "DC01.corp.contoso.com" -DaysBack 14 -OutputPath "D:\Reports"

    .NOTES
        Author:   K Shankar R Karanth
        Website:  https://karanth.ovh
        Version:  1.0
        Run this from a machine with RSAT installed and Domain Admin (or delegated read) rights.
        The account running this script needs remote event log access on the target DC.
    #>

    #Requires -Modules ActiveDirectory

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DCName,

        [int]$DaysBack = 7,

        [string]$OutputPath = "C:\ADOpsKit\Reports\Get-DCDecommissionReadiness",

        [System.Management.Automation.PSCredential]$Credential
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Continue"

    #region ── Helpers ──────────────────────────────────────────────────────────────

    function Write-Section {
        param([string]$Title)
        $line = "=" * 70
        Write-Host "`n$line" -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host "$line" -ForegroundColor Cyan
    }

    function Write-Check {
        param([string]$Label, [string]$Status, [string]$Detail = "")
        $colour = switch ($Status) {
            "OK"      { "Green"  }
            "WARN"    { "Yellow" }
            "FAIL"    { "Red"    }
            "INFO"    { "White"  }
            default   { "Gray"   }
        }
        $pad = $Label.PadRight(45)
        Write-Host "  $pad [$Status] $Detail" -ForegroundColor $colour
    }

    function Get-EventsRemotely {
        param(
            [string]$ComputerName,
            [string]$LogName,
            [int[]]$EventIds,
            [datetime]$After,
            [int]$MaxResults = 200
        )
        $filter = @{
            LogName   = $LogName
            Id        = $EventIds
            StartTime = $After
        }
        try {
            $splatArgs = @{
                ComputerName    = $ComputerName
                FilterHashtable = $filter
                MaxEvents       = $MaxResults
                ErrorAction     = "Stop"
            }
            if ($Credential) { $splatArgs.Credential = $Credential }
            Get-WinEvent @splatArgs
        }
        catch [System.Exception] {
            if ($_.Exception.Message -match "No events were found") {
                return @()
            }
            Write-Warning "  [EventLog] $LogName on $ComputerName : $($_.Exception.Message)"
            return @()
        }
    }

    #endregion

    #region ── Init ─────────────────────────────────────────────────────────────────

    $StartTime  = Get-Date
    $Since      = $StartTime.AddDays(-$DaysBack)
    $Timestamp  = $StartTime.ToString("yyyyMMdd_HHmmss")
    $ReportFile = Join-Path $OutputPath "DCDecomm_${DCName}_${Timestamp}.html"
    $Results    = [ordered]@{}   # Accumulates all findings

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    Write-Host "`n  DC Pre-Decommission Readiness Scanner" -ForegroundColor Magenta
    Write-Host "  Target : $DCName" -ForegroundColor Magenta
    Write-Host "  Window : Last $DaysBack days (since $($Since.ToString('yyyy-MM-dd')))" -ForegroundColor Magenta
    Write-Host "  Report : $ReportFile`n" -ForegroundColor Magenta

    # Verify DC is reachable
    if (-not (Test-Connection -ComputerName $DCName -Count 1 -Quiet)) {
        throw "Cannot reach $DCName."
    }

    #endregion

    #region ── 1. BASIC DC INFO ─────────────────────────────────────────────────────

    Write-Section "1. Basic DC Information"

    try {
        $splatDC = @{ Identity = $DCName; ErrorAction = "Stop" }
        if ($Credential) { $splatDC.Credential = $Credential }
        $DC = Get-ADDomainController @splatDC

        $dcInfo = [ordered]@{
            Hostname        = $DC.HostName
            Site            = $DC.Site
            IPAddress       = $DC.IPv4Address
            OS              = $DC.OperatingSystem
            OSVersion       = $DC.OperatingSystemVersion
            IsGlobalCatalog = $DC.IsGlobalCatalog
            IsRODC          = $DC.IsReadOnly
            LdapPort        = $DC.LdapPort
            Domain          = $DC.Domain
            Forest          = $DC.Forest
        }
        $Results["BasicInfo"] = $dcInfo
        $dcInfo.GetEnumerator() | ForEach-Object {
            Write-Check $_.Key "INFO" $_.Value
        }
    }
    catch {
        Write-Check "Get-ADDomainController" "FAIL" $_.Exception.Message
        $Results["BasicInfo"] = @{ Error = $_.Exception.Message }
    }

    #endregion

    #region ── 2. FSMO ROLES ────────────────────────────────────────────────────────

    Write-Section "2. FSMO Role Holdings"

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop

        $fsmoRoles = [ordered]@{
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            SchemaMaster         = $forest.SchemaMaster
            DomainNamingMaster   = $forest.DomainNamingMaster
        }

        $heldRoles = @()
        foreach ($role in $fsmoRoles.GetEnumerator()) {
            $holder = $role.Value -replace "\..*", ""   # strip FQDN for comparison
            $target = $DCName     -replace "\..*", ""
            if ($holder -ieq $target) {
                Write-Check $role.Key "WARN" "*** HELD BY THIS DC — must transfer before demote ***"
                $heldRoles += $role.Key
            }
            else {
                Write-Check $role.Key "OK" $role.Value
            }
        }
        $Results["FSMO"] = @{ Roles = $fsmoRoles; HeldByTargetDC = $heldRoles }
    }
    catch {
        Write-Check "FSMO Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 3. REPLICATION HEALTH ────────────────────────────────────────────────

    Write-Section "3. Replication Health"

    try {
        $replPartners = Get-ADReplicationPartnerMetadata -Target $DCName -ErrorAction Stop
        $Results["ReplicationPartners"] = $replPartners | Select-Object Partner, LastReplicationSuccess,
            LastReplicationAttempt, LastReplicationResult, ConsecutiveReplicationFailures

        foreach ($p in $replPartners) {
            $failures = $p.ConsecutiveReplicationFailures
            $lastOK   = $p.LastReplicationSuccess
            $status   = if ($failures -gt 0) { "WARN" } else { "OK" }
            Write-Check "Partner: $($p.Partner -replace 'CN=NTDS Settings,CN=|,.*','')" `
                $status "LastOK=$($lastOK.ToString('yyyy-MM-dd HH:mm')) Failures=$failures"
        }

        # Replication queue / pending changes
        $replQueue = @(Get-ADReplicationQueueOperation -Server $DCName -ErrorAction Stop)
        $queueCount = ($replQueue | Measure-Object).Count
        $qStatus = if ($queueCount -gt 0) { "WARN" } else { "OK" }
        Write-Check "Replication Queue" $qStatus "$queueCount pending operations"
        $Results["ReplicationQueue"] = $replQueue

        # Replication failures
        $replFail = @(Get-ADReplicationFailure -Target $DCName -ErrorAction Stop)
        $failCount = ($replFail | Measure-Object).Count
        $fStatus = if ($failCount -gt 0) { "FAIL" } else { "OK" }
        Write-Check "Replication Failures" $fStatus "$failCount active failures"
        $Results["ReplicationFailures"] = $replFail
    }
    catch {
        Write-Check "Replication Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 4. LOGON ACTIVITY — SECURITY EVENT LOG ───────────────────────────────

    Write-Section "4. Logon Activity (Last $DaysBack Days)"

    # 4606/4624 = Logon; 4768 = Kerberos TGT; 4769 = Kerberos TGS; 4776 = NTLM
    $logonEventIds = @(4624, 4625, 4648, 4768, 4769, 4776)
    $logonEvents   = Get-EventsRemotely -ComputerName $DCName -LogName "Security" `
                        -EventIds $logonEventIds -After $Since -MaxResults 1000

    $logonSummary = $logonEvents | Group-Object Id | Sort-Object Count -Descending |
        Select-Object @{N="EventId";E={$_.Name}},
                      @{N="Description";E={
                          switch ($_.Name) {
                              "4624" { "Interactive/Network Logon Success" }
                              "4625" { "Logon Failure" }
                              "4648" { "Logon with Explicit Credentials" }
                              "4768" { "Kerberos TGT Request (AS-REQ)" }
                              "4769" { "Kerberos Service Ticket (TGS-REQ)" }
                              "4776" { "NTLM Authentication" }
                              default { "Unknown" }
                          }
                      }},
                      Count

    $logonSummary | ForEach-Object {
        $status = if ($_.Count -gt 100) { "WARN" } else { "INFO" }
        Write-Check "Event $($_.EventId) — $($_.Description)" $status "Count=$($_.Count)"
    }
    $Results["LogonActivity"] = $logonSummary

    # Top authenticating accounts (from 4768 TGT requests)
    $tgtEvents = $logonEvents | Where-Object { $_.Id -eq 4768 }
    if ($tgtEvents) {
        $topAccounts = $tgtEvents | ForEach-Object {
            try { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty "#text" }
            catch { $null }
        } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20

        Write-Host "`n  Top 20 Accounts Requesting Kerberos TGTs from this DC:" -ForegroundColor Yellow
        $topAccounts | ForEach-Object {
            Write-Check "  $($_.Name)" "INFO" "TGT Requests: $($_.Count)"
        }
        $Results["TopKerberosAccounts"] = $topAccounts
    }

    #endregion

    #region ── 5. DNS ROLE ──────────────────────────────────────────────────────────

    Write-Section "5. DNS Role & Zone Hosting"

    try {
        $dnsService = Get-Service -ComputerName $DCName -Name DNS -ErrorAction Stop
        $dnsStatus  = if ($dnsService.Status -eq "Running") { "WARN" } else { "OK" }
        Write-Check "DNS Server Service" $dnsStatus $dnsService.Status

        if ($dnsService.Status -eq "Running") {
            Write-Host "  *** This DC is running DNS. Verify zone replication and remove from client DNS settings before decommission. ***" -ForegroundColor Yellow

            # Get zones hosted on this DC
            $zones = Get-DnsServerZone -ComputerName $DCName -ErrorAction Stop |
                Select-Object ZoneName, ZoneType, IsDsIntegrated, IsAutoCreated, ReplicationScope
            $zones | ForEach-Object {
                Write-Check "Zone: $($_.ZoneName)" "INFO" "Type=$($_.ZoneType) DSIntegrated=$($_.IsDsIntegrated)"
            }
            $Results["DNSZones"] = $zones
        }
    }
    catch {
        Write-Check "DNS Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 6. SYSVOL / DFSR HEALTH ─────────────────────────────────────────────

    Write-Section "6. SYSVOL / DFSR Health"

    $dfsrEventIds = @(2213, 4012, 5008, 1202, 6016, 6018)
    $dfsrEvents   = @(Get-EventsRemotely -ComputerName $DCName -LogName "DFS Replication" `
                        -EventIds $dfsrEventIds -After $Since -MaxResults 100)

    if ($dfsrEvents.Count -gt 0) {
        Write-Check "DFSR Critical Events" "WARN" "$($dfsrEvents.Count) events found in last $DaysBack days"
        $dfsrEvents | Select-Object TimeCreated, Id, Message | ForEach-Object {
            Write-Host "    [$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))] Event $($_.Id): $($_.Message.Substring(0,[math]::Min(120,$_.Message.Length)))" -ForegroundColor Yellow
        }
    }
    else {
        Write-Check "DFSR Critical Events" "OK" "No critical DFSR events in last $DaysBack days"
    }
    $Results["DFSREvents"] = @($dfsrEvents | Select-Object TimeCreated, Id, Message)

    # SYSVOL share availability
    $sysvol = Test-Path -LiteralPath "\\$DCName\SYSVOL" -ErrorAction SilentlyContinue
    if ($sysvol) {
        Write-Check "SYSVOL Share" "OK" "Share is present and accessible"
    }
    else {
        Write-Check "SYSVOL Share" "WARN" "SYSVOL share not found or inaccessible remotely"
    }

    $netlogon = Test-Path -LiteralPath "\\$DCName\NETLOGON" -ErrorAction SilentlyContinue
    $nlStatus  = if ($netlogon) { "OK" } else { "WARN" }
    Write-Check "NETLOGON Share" $nlStatus $(if ($netlogon) { "Present" } else { "Not found" })

    #endregion

    #region ── 7. SITE & SUBNET ASSOCIATIONS ────────────────────────────────────────

    Write-Section "7. Site & Subnet Associations"

    try {
        $siteName = (Get-ADDomainController -Identity $DCName).Site
        Write-Check "DC Site" "INFO" $siteName

        $subnets = Get-ADReplicationSubnet -Filter * -Properties Site |
            Where-Object { $_.Site -match $siteName }
        $subnetCount = ($subnets | Measure-Object).Count
        $snStatus = if ($subnetCount -gt 0) { "WARN" } else { "OK" }
        Write-Check "Subnets mapped to this site" $snStatus "$subnetCount subnet(s) — reassign or remove before decommission"
        $subnets | ForEach-Object {
            Write-Host "    $($_.Name) → $($_.Site)" -ForegroundColor Gray
        }
        $Results["Subnets"] = @($subnets | Select-Object Name, Location, Site)

        # Site links referencing this site
        $siteLinks = Get-ADReplicationSiteLink -Filter * |
            Where-Object { $_.SitesIncluded -match $siteName }
        $slCount = ($siteLinks | Measure-Object).Count
        Write-Check "Site Links referencing this site" "INFO" "$slCount link(s)"
        $siteLinks | ForEach-Object {
            Write-Host "    $($_.Name) — Sites: $($_.SitesIncluded -join ', ')" -ForegroundColor Gray
        }
        $Results["SiteLinks"] = $siteLinks | Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded
    }
    catch {
        Write-Check "Site/Subnet Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 8. NETLOGON / SECURE CHANNEL ─────────────────────────────────────────

    Write-Section "8. Netlogon & Secure Channel Activity"

    $netlogonEventIds = @(5722, 5805, 5723, 3210, 5806)
    $netlogonEvents   = @(Get-EventsRemotely -ComputerName $DCName -LogName "System" `
                            -EventIds $netlogonEventIds -After $Since -MaxResults 200)

    if ($netlogonEvents.Count -gt 0) {
        Write-Check "Secure Channel Issues (5722/5805)" "WARN" "$($netlogonEvents.Count) events found"
        $netlogonEvents | Select-Object TimeCreated, Id, Message | ForEach-Object {
            Write-Host "    [$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))] Event $($_.Id): $($_.Message.Substring(0,[math]::Min(120,$_.Message.Length)))" -ForegroundColor Yellow
        }
    }
    else {
        Write-Check "Secure Channel Issues" "OK" "No Netlogon errors in last $DaysBack days"
    }

    # Check Netlogon.log for this DC for LOGON entries (via UNC)
    $netlogonLog = "\\$DCName\ADMIN$\debug\netlogon.log"
    try {
        if (Test-Path $netlogonLog) {
            $logLines   = Get-Content $netlogonLog -Tail 500
            $logonLines = @($logLines | Select-String "LOGON" | Select-Object -Last 50)
            Write-Check "Netlogon.log LOGON entries (last 500 lines)" "INFO" "$($logonLines.Count) LOGON entries"
            $Results["NetlogonLog"] = $logonLines | Select-Object -ExpandProperty Line
        }
        else {
            Write-Check "Netlogon.log" "WARN" "Not accessible at $netlogonLog"
        }
    }
    catch {
        Write-Check "Netlogon.log" "WARN" "Access denied or path unavailable"
    }

    #endregion

    #region ── 9. DIRECTORY SERVICE ERRORS ──────────────────────────────────────────

    Write-Section "9. Directory Service Event Log"

    $dsErrorIds = @(1311, 1566, 2088, 1084, 1925, 2042)
    $dsEvents   = @(Get-EventsRemotely -ComputerName $DCName -LogName "Directory Service" `
                      -EventIds $dsErrorIds -After $Since -MaxResults 200)

    if ($dsEvents.Count -gt 0) {
        Write-Check "Directory Service Errors/Warnings" "WARN" "$($dsEvents.Count) events found"
        $dsEvents | Select-Object TimeCreated, Id, Message | ForEach-Object {
            Write-Host "    [$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))] Event $($_.Id): $($_.Message.Substring(0,[math]::Min(150,$_.Message.Length)))" -ForegroundColor Yellow
        }
    }
    else {
        Write-Check "Directory Service Errors" "OK" "No critical DS events in last $DaysBack days"
    }
    $Results["DirectoryServiceEvents"] = @($dsEvents | Select-Object TimeCreated, Id, Message)

    #endregion

    #region ── 10. ACTIVE SESSIONS ON THIS DC ───────────────────────────────────────

    Write-Section "10. Active RDP / Interactive Sessions"

    try {
        $sessions = query session /server:$DCName 2>&1
        Write-Host "  Active Sessions on $DCName :" -ForegroundColor Yellow
        $sessions | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        $Results["ActiveSessions"] = $sessions
    }
    catch {
        Write-Check "Session Query" "WARN" $_.Exception.Message
    }

    #endregion

    #region ── 11. TRUST RELATIONSHIPS ──────────────────────────────────────────────

    Write-Section "11. Trust Relationships"

    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop |
            Select-Object Name, Direction, TrustType, IntraForest
        $trustCount = ($trusts | Measure-Object).Count
        Write-Check "Domain Trusts" "INFO" "$trustCount trust(s) — verify none depend solely on this DC"
        $trusts | ForEach-Object {
            Write-Host "    $($_.Name) [$($_.Direction)] Type=$($_.TrustType) IntraForest=$($_.IntraForest)" -ForegroundColor Gray
        }
        $Results["Trusts"] = $trusts
    }
    catch {
        Write-Check "Trust Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 12. GLOBAL CATALOG STATUS ────────────────────────────────────────────

    Write-Section "12. Global Catalog Status"

    try {
        $isGC   = (Get-ADDomainController -Identity $DCName).IsGlobalCatalog
        $allGCs = (Get-ADForest).GlobalCatalogs
        $gcCount = ($allGCs | Measure-Object).Count

        if ($isGC) {
            Write-Check "Is Global Catalog" "WARN" "*** This DC is a GC. Ensure another GC exists in the site before decommission. ***"
            Write-Check "Other GCs in forest" "INFO" "$gcCount total — $($allGCs -join ', ')"
        }
        else {
            Write-Check "Is Global Catalog" "OK" "Not a GC — no GC transfer needed"
        }
        $Results["GlobalCatalog"] = @{ IsGC = $isGC; AllGCs = $allGCs }
    }
    catch {
        Write-Check "GC Query" "FAIL" $_.Exception.Message
    }

    #endregion

    #region ── 13. PENDING DECOMMISSION CHECKLIST ───────────────────────────────────

    Write-Section "13. Pre-Decommission Checklist Summary"

    $checklist = [ordered]@{
        "Transfer FSMO roles off this DC"                   = if ($Results["FSMO"].HeldByTargetDC.Count -gt 0) { "ACTION REQUIRED" } else { "OK — No roles held" }
        "Resolve replication failures"                      = if ($Results["ReplicationFailures"].Count -gt 0) { "ACTION REQUIRED" } else { "OK" }
        "Drain replication queue"                           = if ($Results["ReplicationQueue"].Count -gt 0)    { "ACTION REQUIRED" } else { "OK" }
        "Reassign/remove subnets from site"                 = if ($Results["Subnets"].Count -gt 0)             { "ACTION REQUIRED" } else { "OK" }
        "Migrate DNS zones / remove from client DNS"        = if ($DC.IsGlobalCatalog)                          { "VERIFY" }         else { "VERIFY" }
        "Ensure another GC exists in this site"             = if ($Results["GlobalCatalog"].IsGC)               { "ACTION REQUIRED" } else { "OK" }
        "Verify no clients homed solely to this DC"         = "VERIFY — see LogonActivity section"
        "Check for active user sessions"                    = "VERIFY — see ActiveSessions section"
        "Resolve Directory Service errors"                  = if ($Results["DirectoryServiceEvents"].Count -gt 0) { "REVIEW" } else { "OK" }
        "Resolve DFSR/SYSVOL errors"                        = if ($Results["DFSREvents"].Count -gt 0)           { "REVIEW" }  else { "OK" }
        "Notify dependent applications / service accounts"  = "MANUAL — review TopKerberosAccounts list"
        "Run: dcpromo /forceremoval only as last resort"    = "NOTE — use Uninstall-ADDSDomainController"
    }

    foreach ($item in $checklist.GetEnumerator()) {
        $status = switch -Wildcard ($item.Value) {
            "OK*"              { "OK"   }
            "ACTION REQUIRED*" { "WARN" }
            "VERIFY*"          { "INFO" }
            "REVIEW*"          { "INFO" }
            "MANUAL*"          { "INFO" }
            "NOTE*"            { "INFO" }
            default            { "INFO" }
        }
        Write-Check $item.Key $status $item.Value
    }

    #endregion

    #region ── HTML REPORT ───────────────────────────────────────────────────────────

    function ConvertTo-HtmlTable {
        param([object[]]$Data, [string]$Title)
        if (-not $Data -or $Data.Count -eq 0) { return "<p><em>No data.</em></p>" }
        $html  = "<h3>$Title</h3><table><thead><tr>"
        $props = $Data[0].PSObject.Properties.Name
        $props | ForEach-Object { $html += "<th>$_</th>" }
        $html += "</tr></thead><tbody>"
        foreach ($row in $Data) {
            $html += "<tr>"
            $props | ForEach-Object { $html += "<td>$($row.$_)</td>" }
            $html += "</tr>"
        }
        $html += "</tbody></table>"
        return $html
    }

    $html = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>DC Decommission Readiness — $DCName</title>
    <style>
      body    { font-family: Consolas, monospace; background:#1e1e2e; color:#cdd6f4; margin:2rem; }
      h1      { color:#cba6f7; border-bottom:2px solid #cba6f7; padding-bottom:.4rem; }
      h2      { color:#89b4fa; margin-top:2rem; }
      h3      { color:#94e2d5; }
      table   { border-collapse:collapse; width:100%; margin-bottom:1.5rem; font-size:.85rem; }
      th      { background:#313244; color:#cba6f7; padding:.4rem .6rem; text-align:left; }
      td      { padding:.35rem .6rem; border-bottom:1px solid #313244; }
      tr:hover td { background:#313244; }
      .warn   { color:#f9e2af; }
      .fail   { color:#f38ba8; }
      .ok     { color:#a6e3a1; }
      .meta   { color:#6c7086; font-size:.8rem; margin-bottom:2rem; }
    </style>
    </head>
    <body>
    <h1>DC Pre-Decommission Readiness Report</h1>
    <p class="meta">
      Target DC : <strong>$DCName</strong><br>
      Generated : <strong>$($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</strong><br>
      Scan window : <strong>Last $DaysBack days</strong>
    </p>

    <h2>1. Basic DC Information</h2>
    $(ConvertTo-HtmlTable -Data ($Results["BasicInfo"].GetEnumerator() | Select-Object @{N="Property";E={$_.Key}},@{N="Value";E={$_.Value}}) -Title "")

    <h2>2. FSMO Roles</h2>
    $(ConvertTo-HtmlTable -Data ($Results["FSMO"].Roles.GetEnumerator() | Select-Object @{N="Role";E={$_.Key}},@{N="Holder";E={$_.Value}}) -Title "")
    <p class="warn">Roles held by this DC: <strong>$($Results["FSMO"].HeldByTargetDC -join ", ")</strong></p>

    <h2>3. Replication Partners</h2>
    $(ConvertTo-HtmlTable -Data $Results["ReplicationPartners"] -Title "")

    <h2>4. Logon Activity Summary</h2>
    $(ConvertTo-HtmlTable -Data $Results["LogonActivity"] -Title "")

    <h2>4b. Top Kerberos Accounts (TGT Requests)</h2>
    $(ConvertTo-HtmlTable -Data ($Results["TopKerberosAccounts"] | Select-Object @{N="Account";E={$_.Name}},@{N="TGT Requests";E={$_.Count}}) -Title "")

    <h2>5. DNS Zones</h2>
    $(ConvertTo-HtmlTable -Data $Results["DNSZones"] -Title "")

    <h2>6. DFSR Events</h2>
    $(ConvertTo-HtmlTable -Data $Results["DFSREvents"] -Title "")

    <h2>7. Site Subnets</h2>
    $(ConvertTo-HtmlTable -Data $Results["Subnets"] -Title "")

    <h2>8. Netlogon Log (last 50 LOGON entries)</h2>
    <pre>$(($Results["NetlogonLog"] -join "`n"))</pre>

    <h2>9. Directory Service Events</h2>
    $(ConvertTo-HtmlTable -Data $Results["DirectoryServiceEvents"] -Title "")

    <h2>10. Trust Relationships</h2>
    $(ConvertTo-HtmlTable -Data $Results["Trusts"] -Title "")

    <h2>11. Global Catalog</h2>
    $(ConvertTo-HtmlTable -Data @([pscustomobject]@{ IsGC = $Results["GlobalCatalog"].IsGC; AllGCsInForest = ($Results["GlobalCatalog"].AllGCs -join ", ") }) -Title "")

    <h2>12. Pre-Decommission Checklist</h2>
    $(ConvertTo-HtmlTable -Data ($checklist.GetEnumerator() | Select-Object @{N="Item";E={$_.Key}},@{N="Status";E={$_.Value}}) -Title "")

    <hr>
    <p class="meta">Generated by Get-DCDecommissionReadiness.ps1 — ADOpsKit</p>
    </body>
    </html>
"@

    $html | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Host "`n  [DONE] Report written to: $ReportFile" -ForegroundColor Green
    Write-Host "  Total runtime: $([math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1))s`n" -ForegroundColor Green

    # Return structured results object for pipeline use
    return [pscustomobject]$Results

    #endregion

}
