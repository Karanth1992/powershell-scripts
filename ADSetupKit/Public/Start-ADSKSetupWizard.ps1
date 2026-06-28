function Start-ADSKSetupWizard {
<#
.SYNOPSIS
    Interactive wizard that guides you through setting up a Windows Server from scratch.

.DESCRIPTION
    Walks through network configuration, computer rename, application installation,
    role installation, and DC promotion or domain join in a single guided session.
    Post-restart tasks (AD sites, DHCP, DNS forwarders) are automatically scheduled
    to run after the DC promotion reboot.

.EXAMPLE
    Start-ADSKSetupWizard

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator on a fresh Windows Server.
#>
    [CmdletBinding()]
    param()

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    # -------------------------------------------------------------------------
    # Welcome
    # -------------------------------------------------------------------------
    Write-ADSKBanner "ADSetupKit  -  Windows Server Setup Wizard"
    Write-Host @"

  This wizard will guide you through the following steps:

    Step 1  Network configuration (static IP, gateway, DNS)
    Step 2  Computer rename
    Step 3  Application installation (from a scripts folder)
    Step 4  Role installation (ADDS, DNS, DHCP, IIS, etc.)
    Step 5  Server purpose (DC promotion or domain join)
    Step 6  Post-restart tasks (sites, DHCP scope, DNS forwarders)
    Step 7  Review and confirm

  Press Ctrl+C at any time to abort.
"@ -ForegroundColor Gray

    # =========================================================================
    # Collect configuration  -  no changes are made until Step 9 (Execute)
    # =========================================================================

    # -------------------------------------------------------------------------
    # Step 1  -  Network
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 1  -  Network Configuration"
    $configNetwork = $false
    $netParams     = @{}

    $doNet = Read-Host "  Configure a static IP address? (Y/N)"
    if ($doNet -match '^[Yy]') {
        $configNetwork = $true

        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($adapters.Count -gt 1) {
            Write-Host "`n  Connected adapters:" -ForegroundColor White
            $adapters | ForEach-Object { Write-Host "    $($_.Name)" }
            $netParams['AdapterName'] = (Read-Host "  Adapter name (leave blank for first connected)").Trim()
            if (-not $netParams['AdapterName']) { $netParams.Remove('AdapterName') }
        } else {
            Write-ADSKInfo "Using adapter: $($adapters[0].Name)"
        }

        $netParams['IPAddress']       = Read-Host "  IP Address"
        $prefixRaw                    = Read-Host "  Prefix length (default 24)"
        $netParams['PrefixLength']    = if ($prefixRaw -match '^\d+$') { [int]$prefixRaw } else { 24 }
        $netParams['DefaultGateway']  = Read-Host "  Default Gateway"
        $dnsRaw                       = Read-Host "  DNS Servers (comma-separated)"
        $netParams['DnsServers']      = $dnsRaw -split ',' | ForEach-Object { $_.Trim() }

        $renameNic = Read-Host "  Rename the adapter? (Y/N)"
        if ($renameNic -match '^[Yy]') {
            $netParams['NewAdapterName'] = Read-Host "  New adapter name"
        }
    }

    # -------------------------------------------------------------------------
    # Step 2  -  Computer Name
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 2  -  Computer Name"
    $renameComputer = $false
    $newComputerName = ''

    Write-ADSKInfo "Current computer name: $env:COMPUTERNAME"
    $doRename = Read-Host "  Rename this computer? (Y/N)"
    if ($doRename -match '^[Yy]') {
        $renameComputer  = $true
        $newComputerName = Read-Host "  New computer name"
    }

    # -------------------------------------------------------------------------
    # Step 3  -  Applications
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 3  -  Application Installation"
    $installApps   = $false
    $appFolder     = ''

    $doApps = Read-Host "  Install applications from a scripts folder? (Y/N)"
    if ($doApps -match '^[Yy]') {
        $appFolder = Read-Host "  Path to installer scripts folder"
        if (Test-Path $appFolder) {
            $installApps = $true
        } else {
            Write-ADSKWarn "Folder not found: $appFolder  -  skipping application install."
        }
    }

    # -------------------------------------------------------------------------
    # Step 4  -  Roles
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 4  -  Role Installation"

    $roleMenuOptions = @(
        'AD Domain Services (ADDS)'
        'DNS Server'
        'DHCP Server'
        'File Server'
        'Print Server'
        'Web Server (IIS)'
        'Group Policy Management (GPMC)'
        'RSAT Tools'
        'None - skip role installation'
    )

    $roleMap = @{
        'AD Domain Services (ADDS)'      = 'AD-Domain-Services'
        'DNS Server'                     = 'DNS'
        'DHCP Server'                    = 'DHCP'
        'File Server'                    = 'File-Services'
        'Print Server'                   = 'Print-Services'
        'Web Server (IIS)'               = 'Web-Server'
        'Group Policy Management (GPMC)' = 'GPMC'
        'RSAT Tools'                     = 'RSAT-AD-Tools'
    }

    Write-Host "`n  Select roles to install:" -ForegroundColor White
    Write-Host "  [0] Recommended for DC (ADDS + DNS + GPMC)" -ForegroundColor Green
    for ($i = 0; $i -lt $roleMenuOptions.Count; $i++) {
        Write-Host "  [$($i+1)] $($roleMenuOptions[$i])"
    }
    Write-Host "  Enter numbers separated by commas, or 0 for recommended DC set."

    $selectedRoleNames = @()
    $installRoles      = $false

    do {
        $raw   = (Read-Host "  Choice").Trim()
        $parts = $raw -split ',' | ForEach-Object { $_.Trim() }
        $valid = $true

        if ($parts -contains '0') {
            $selectedRoleNames = @('AD-Domain-Services', 'DNS', 'GPMC')
            $installRoles      = $true
            break
        }

        $tempSelected = @()
        foreach ($p in $parts) {
            $n = 0
            if ([int]::TryParse($p, [ref]$n) -and $n -ge 1 -and $n -le $roleMenuOptions.Count) {
                $label = $roleMenuOptions[$n - 1]
                if ($label -eq 'None - skip role installation') {
                    $tempSelected = @()
                    $installRoles = $false
                    break
                }
                $tempSelected += $roleMap[$label]
                $installRoles  = $true
            } else {
                Write-Host "  Invalid entry: $p" -ForegroundColor Yellow
                $valid = $false
                break
            }
        }

        if ($valid) { $selectedRoleNames = $tempSelected }
    } while (-not $valid)

    $addsSelected = $selectedRoleNames -contains 'AD-Domain-Services'

    # -------------------------------------------------------------------------
    # Step 5  -  Server Purpose
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 5  -  Server Purpose"

    $serverPurpose   = ''      # 'NewForest','AdditionalDC','ChildDomain','DomainMember','Standalone'
    $promotionParams = @{}
    $domainJoinParams = @{}

    if ($addsSelected) {
        $purposeChoice = Read-ADSKMenuChoice -Prompt "What are we building?" -Options @(
            'New Forest (this is the first DC)'
            'Additional DC in existing domain'
            'New Child Domain'
        )

        switch ($purposeChoice) {
            'New Forest (this is the first DC)' {
                $serverPurpose = 'NewForest'
                $promotionParams['DomainName']        = Read-Host "  Forest root FQDN (e.g. corp.contoso.com)"
                $netBios = Read-Host "  NetBIOS name (leave blank to auto-derive)"
                if ($netBios) { $promotionParams['DomainNetBiosName'] = $netBios }
                $promotionParams['SafeModePassword']  = Read-Host "  DSRM Password" -AsSecureString
            }
            'Additional DC in existing domain' {
                $serverPurpose = 'AdditionalDC'
                $promotionParams['DomainName']        = Read-Host "  Domain FQDN (e.g. corp.contoso.com)"
                $promotionParams['Credential']        = Get-Credential -Message "  Domain Admin credentials"
                $promotionParams['SafeModePassword']  = Read-Host "  DSRM Password" -AsSecureString
                $siteRaw = Read-Host "  AD Site name (leave blank for Default-First-Site-Name)"
                if ($siteRaw) { $promotionParams['SiteName'] = $siteRaw }
            }
            'New Child Domain' {
                $serverPurpose = 'ChildDomain'
                $promotionParams['ChildDomainName']   = Read-Host "  Child domain label (e.g. uk)"
                $promotionParams['ParentDomainName']  = Read-Host "  Parent domain FQDN (e.g. corp.contoso.com)"
                $promotionParams['Credential']        = Get-Credential -Message "  Enterprise Admin credentials"
                $promotionParams['SafeModePassword']  = Read-Host "  DSRM Password" -AsSecureString
                $siteRaw = Read-Host "  AD Site name (leave blank for Default-First-Site-Name)"
                if ($siteRaw) { $promotionParams['SiteName'] = $siteRaw }
            }
        }
    } else {
        $purposeChoice = Read-ADSKMenuChoice -Prompt "What is this server for?" -Options @(
            'Join to existing domain (member server)'
            'Standalone server (no domain)'
        )

        if ($purposeChoice -eq 'Join to existing domain (member server)') {
            $serverPurpose = 'DomainMember'
            $domainJoinParams['DomainName']  = Read-Host "  Domain FQDN (e.g. corp.contoso.com)"
            $domainJoinParams['Credential']  = Get-Credential -Message "  Domain Admin credentials"
            $ouRaw = Read-Host "  OU path (leave blank for default Computers container)"
            if ($ouRaw) { $domainJoinParams['OUPath'] = $ouRaw }
        } else {
            $serverPurpose = 'Standalone'
        }
    }

    # -------------------------------------------------------------------------
    # Step 6  -  Post-Restart Tasks (DC promotions only)
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 6  -  Post-Restart Configuration"

    $postRestartTasks = [System.Collections.Generic.List[string]]::new()
    $siteParams       = @{}
    $dhcpParams       = @{}
    $dnsParams        = @{}

    $isDcPromotion = $serverPurpose -in @('NewForest','AdditionalDC','ChildDomain')

    if ($isDcPromotion) {
        Write-ADSKInfo "After DC promotion the server will restart. You can schedule tasks to run automatically on first boot."

        $doSite = Read-Host "  Create an AD site and subnet after restart? (Y/N)"
        if ($doSite -match '^[Yy]') {
            $siteParams['SiteName']   = Read-Host "  Site name"
            $siteParams['SubnetCIDR'] = Read-Host "  Subnet CIDR (e.g. 192.168.10.0/24)"
            $linkSite = Read-Host "  Link to existing site? (leave blank to skip)"
            if ($linkSite) { $siteParams['LinkToSite'] = $linkSite }
            $postRestartTasks.Add('Site')
        }

        $doDhcp = Read-Host "  Create a DHCP scope after restart? (Y/N)"
        if ($doDhcp -match '^[Yy]') {
            $dhcpParams['ScopeName']      = Read-Host "  Scope name"
            $dhcpParams['StartRange']     = Read-Host "  Start IP"
            $dhcpParams['EndRange']       = Read-Host "  End IP"
            $dhcpParams['SubnetMask']     = Read-Host "  Subnet mask (e.g. 255.255.255.0)"
            $dhcpParams['DefaultGateway'] = Read-Host "  Default gateway"
            $dnsRaw2                      = Read-Host "  DNS servers (comma-separated)"
            $dhcpParams['DnsServers']     = $dnsRaw2 -split ',' | ForEach-Object { $_.Trim() }
            $postRestartTasks.Add('DHCP')
        }

        $doDns = Read-Host "  Set DNS forwarders after restart? (Y/N)"
        if ($doDns -match '^[Yy]') {
            $fwdRaw                  = Read-Host "  Forwarder IPs (comma-separated)"
            $dnsParams['Forwarders'] = $fwdRaw -split ',' | ForEach-Object { $_.Trim() }
            $rootHints = Read-Host "  Enable root hints fallback? (Y/N)"
            if ($rootHints -match '^[Yy]') { $dnsParams['UseRootHints'] = $true }
            $postRestartTasks.Add('DNS')
        }
    } else {
        Write-ADSKInfo "Post-restart scheduled tasks are only applicable for DC promotion scenarios. Skipping."
    }

    # -------------------------------------------------------------------------
    # Step 7  -  Review & Confirm
    # -------------------------------------------------------------------------
    Write-ADSKBanner "Step 7  -  Review"

    Write-Host "`n  The wizard will perform the following actions:`n" -ForegroundColor White

    if ($configNetwork) {
        Write-Host "  [Network]   Set static IP $($netParams['IPAddress'])/$($netParams['PrefixLength']) on $(if ($netParams.ContainsKey('AdapterName')) { $netParams['AdapterName'] } else { 'first connected adapter' })" -ForegroundColor Cyan
        Write-Host "              Gateway: $($netParams['DefaultGateway'])  DNS: $($netParams['DnsServers'] -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "  [Network]   Skip" -ForegroundColor DarkGray
    }

    if ($renameComputer) {
        Write-Host "  [Rename]    $env:COMPUTERNAME -> $newComputerName" -ForegroundColor Cyan
    } else {
        Write-Host "  [Rename]    Skip" -ForegroundColor DarkGray
    }

    if ($installApps) {
        Write-Host "  [Apps]      Run scripts from $appFolder" -ForegroundColor Cyan
    } else {
        Write-Host "  [Apps]      Skip" -ForegroundColor DarkGray
    }

    if ($installRoles -and $selectedRoleNames.Count -gt 0) {
        Write-Host "  [Roles]     Install: $($selectedRoleNames -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "  [Roles]     Skip" -ForegroundColor DarkGray
    }

    switch ($serverPurpose) {
        'NewForest'    { Write-Host "  [Purpose]   Promote as new forest root DC for $($promotionParams['DomainName'])" -ForegroundColor Cyan }
        'AdditionalDC' { Write-Host "  [Purpose]   Promote as additional DC for $($promotionParams['DomainName'])" -ForegroundColor Cyan }
        'ChildDomain'  { Write-Host "  [Purpose]   Promote as first DC of child domain $($promotionParams['ChildDomainName']).$($promotionParams['ParentDomainName'])" -ForegroundColor Cyan }
        'DomainMember' { Write-Host "  [Purpose]   Join domain $($domainJoinParams['DomainName'])" -ForegroundColor Cyan }
        'Standalone'   { Write-Host "  [Purpose]   Standalone server (no domain join)" -ForegroundColor DarkGray }
        default        { Write-Host "  [Purpose]   None selected" -ForegroundColor DarkGray }
    }

    if ($postRestartTasks.Count -gt 0) {
        Write-Host "  [PostBoot]  Scheduled: $($postRestartTasks -join ', ')" -ForegroundColor Cyan
    }

    Write-Host ''
    $confirm = Read-Host "  Proceed with all steps above? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-ADSKWarn "Wizard cancelled by user."
        return
    }

    # =========================================================================
    # Execute
    # =========================================================================
    Write-ADSKBanner "Executing Setup"

    # --- Network ---
    if ($configNetwork) {
        Write-ADSKBanner "Configuring Network"
        Set-ADSKNetworkConfig @netParams
    }

    # --- Rename ---
    if ($renameComputer) {
        Write-ADSKBanner "Renaming Computer"
        Rename-ADSKComputer -NewName $newComputerName
    }

    # --- Applications ---
    if ($installApps) {
        Install-ADSKApplications -ScriptFolder $appFolder
    }

    # --- Roles ---
    if ($installRoles -and $selectedRoleNames.Count -gt 0) {
        Install-ADSKRoles -Roles $selectedRoleNames
    }

    # --- Post-restart task script ---
    if ($postRestartTasks.Count -gt 0) {
        $postScriptDir = 'C:\ADSKSetup'
        if (-not (Test-Path $postScriptDir)) { New-Item -ItemType Directory -Path $postScriptDir | Out-Null }
        $postScriptPath = Join-Path $postScriptDir 'PostRestart.ps1'

        $scriptLines = [System.Collections.Generic.List[string]]::new()
        $scriptLines.Add("# ADSetupKit  -  Post-Restart Configuration")
        $scriptLines.Add("# Generated by Start-ADSKSetupWizard on $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
        $scriptLines.Add("Import-Module ADSetupKit -ErrorAction Stop")
        $scriptLines.Add('')

        if ($postRestartTasks -contains 'Site') {
            $siteCmd = "New-ADSKSite -SiteName '$($siteParams['SiteName'])' -SubnetCIDR '$($siteParams['SubnetCIDR'])'"
            if ($siteParams.ContainsKey('LinkToSite')) { $siteCmd += " -LinkToSite '$($siteParams['LinkToSite'])'" }
            $scriptLines.Add($siteCmd)
        }

        if ($postRestartTasks -contains 'DHCP') {
            $dnsListStr = ($dhcpParams['DnsServers'] | ForEach-Object { "'$_'" }) -join ','
            $dhcpCmd  = "New-ADSKDhcpScope ``"
            $dhcpCmd += "`n    -ScopeName '$($dhcpParams['ScopeName'])' ``"
            $dhcpCmd += "`n    -StartRange '$($dhcpParams['StartRange'])' ``"
            $dhcpCmd += "`n    -EndRange '$($dhcpParams['EndRange'])' ``"
            $dhcpCmd += "`n    -SubnetMask '$($dhcpParams['SubnetMask'])' ``"
            $dhcpCmd += "`n    -DefaultGateway '$($dhcpParams['DefaultGateway'])' ``"
            $dhcpCmd += "`n    -DnsServers @($dnsListStr)"
            $scriptLines.Add($dhcpCmd)
        }

        if ($postRestartTasks -contains 'DNS') {
            $fwdListStr = ($dnsParams['Forwarders'] | ForEach-Object { "'$_'" }) -join ','
            $dnsCmd = "Set-ADSKDnsForwarder -Forwarders @($fwdListStr)"
            if ($dnsParams['UseRootHints']) { $dnsCmd += ' -UseRootHints' }
            $scriptLines.Add($dnsCmd)
        }

        # Self-delete and unregister task at the end
        $scriptLines.Add('')
        $scriptLines.Add("# Self-cleanup")
        $scriptLines.Add("Unregister-ScheduledTask -TaskName 'ADSKPostRestart' -Confirm:`$false -ErrorAction SilentlyContinue")
        $scriptLines.Add("Remove-Item -Path '$postScriptPath' -Force -ErrorAction SilentlyContinue")

        $scriptLines | Set-Content -Path $postScriptPath -Encoding UTF8
        Register-ADSKStartupTask -TaskName 'ADSKPostRestart' -ScriptPath $postScriptPath
        Write-ADSKOk "Post-restart script saved: $postScriptPath"
        Write-ADSKOk "Scheduled task 'ADSKPostRestart' registered to run at next startup."
    }

    # --- Server Purpose ---
    switch ($serverPurpose) {
        'NewForest' {
            Write-ADSKBanner "Forest Promotion"
            New-ADSKForest @promotionParams
        }
        'AdditionalDC' {
            Write-ADSKBanner "Additional DC Promotion"
            Add-ADSKDomainController @promotionParams
        }
        'ChildDomain' {
            Write-ADSKBanner "Child Domain Promotion"
            New-ADSKChildDomain @promotionParams
        }
        'DomainMember' {
            Write-ADSKBanner "Domain Join"
            Add-ADSKDomainMember @domainJoinParams
            Write-ADSKWarn "Restart the server to complete the domain join."
        }
        'Standalone' {
            Write-ADSKInfo "Server left as standalone  -  no domain join performed."
        }
    }

    if ($renameComputer -and $serverPurpose -eq 'Standalone') {
        Write-ADSKWarn "Remember to restart the server to apply the computer rename."
    }

    Write-ADSKBanner "Setup Wizard Complete"
    Write-ADSKOk "All selected steps have been executed."
}
