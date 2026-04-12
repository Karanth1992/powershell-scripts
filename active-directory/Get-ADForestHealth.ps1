<#
.SYNOPSIS
    Generates an HTML health report for all domain controllers
    across an Active Directory forest.

.DESCRIPTION
    Discovers all domains in the forest, queries each domain's
    PDC Emulator via Invoke-Command, and collects the following
    per domain controller:

    - DCDiag tests: Connectivity, DFSREvent, KccEvent, FSMO,
      NetLogons, Replication
    - OS drive free space (GB)
    - CPU usage (%)
    - Memory usage (%)
    - Uptime (days)

    Uses WMI for hardware metrics so it works even when
    WinRM is blocked. Outputs a colour-coded HTML report
    to a central network share and optionally sends it
    by email.

.EXAMPLE
    .\Get-ADForestHealth.ps1
    Runs the health check and writes the HTML report to the
    path defined in $OutputFolder.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  8.0
    Created:  26-02-2026
    Requires: ActiveDirectory module, WinRM access to PDC Emulators,
              WMI access to all domain controllers,
              run as Domain Admin or equivalent

    To enable email reporting, uncomment the Send-MailMessage
    block at the bottom and update $smtpsettings.
#>

# ============ CONFIGURATION ============

$now              = Get-Date
$date             = $now.ToShortDateString()
$reportTime       = $now
$allDomains       = (Get-ADForest).Domains
$reportEmailSubject = "Active Directory Health Check for $($allDomains -join ', ')"

# ============ EMAIL CONFIGURATION ============
# Update these values before enabling email reporting

$smtpSettings = @{
    To         = 'recipient@example.com'
    From       = 'sender@example.com'
    Subject    = "$reportEmailSubject - $date"
    SmtpServer = 'smtp.example.com'
    Port       = 25
}

# ============ OUTPUT CONFIGURATION ============

$outputFolder = "\\ServerName\C$\Scripts\HealthCheck\Reports\"
$forestName   = (Get-ADForest).Name
$safeForest   = $forestName -replace '[\\/:*?"<>| ]', '_'
$outFile      = Join-Path $outputFolder ("ADHealth_Latest_{0}.html" -f $safeForest)

# ========== DISCOVER PDC EMULATORS ==========

$domainPDCs = @{}
foreach ($domain in $allDomains) {
    $domainPDCs[$domain] = (Get-ADDomain -Server $domain).PDCEmulator
}

# ========== DATA COLLECTION SCRIPTBLOCK ==========
# Runs remotely on each PDC Emulator via Invoke-Command

$domainHealthScriptBlock = {
    param([string]$DomainName)

    Import-Module ActiveDirectory -ErrorAction Stop

    function Get-AllDomainControllers {
        param($ComputerName)
        Get-ADDomainController -Filter * -Server $ComputerName | Sort-Object HostName
    }

    function Get-DCUptimeDays {
        param($ComputerName)
        if (-not (Test-Connection $ComputerName -Count 1 -Quiet)) { return 'Fail' }
        try {
            $os       = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $lastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
            return (New-TimeSpan -Start $lastBoot -End (Get-Date)).Days
        }
        catch { return 'WMI Failure' }
    }

    function Get-DCDiagResults {
        param($ComputerName)

        $results = [PSCustomObject]@{
            ServerName         = $ComputerName
            Connectivity       = $null
            DFSREvent          = $null
            KccEvent           = $null
            KnowsOfRoleHolders = $null
            NetLogons          = $null
            ObjectsReplicated  = $null
        }

        if (-not (Test-Connection $ComputerName -Count 1 -Quiet)) {
            foreach ($prop in $results.PSObject.Properties.Name) {
                if ($prop -ne 'ServerName') { $results.$prop = 'Failed' }
            }
            return $results
        }

        $params = @(
            "/s:$ComputerName",
            '/test:Connectivity',
            '/test:DFSREvent',
            '/test:KccEvent',
            '/test:KnowsOfRoleHolders',
            '/test:NetLogons',
            '/test:ObjectsReplicated'
        )

        $dcdiagOutput = (Dcdiag.exe @params) -split '[\r\n]'
        $testName     = $null
        $testStatus   = $null

        foreach ($line in $dcdiagOutput) {
            if ($line -match 'Starting test:') {
                $testName = ($line -replace '.*Starting test:').Trim()
            }
            if ($line -match 'passed test|failed test') {
                $testStatus = if ($line -match 'passed test') { 'Passed' } else { 'Failed' }
            }
            if ($testName -and $testStatus) {
                if ($results.PSObject.Properties.Name -contains $testName) {
                    $results.$testName = $testStatus
                }
                $testName   = $null
                $testStatus = $null
            }
        }

        return $results
    }

    function Get-DCOSDriveFreeSpaceGB {
        param($ComputerName)
        if (-not (Test-Connection $ComputerName -Count 1 -Quiet)) { return 'Fail' }
        try {
            $os     = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $drive  = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName `
                        -Filter "DeviceID='$($os.SystemDrive)'" -ErrorAction Stop
            return [math]::Round($drive.FreeSpace / 1GB, 2)
        }
        catch { return 'WMI Failure' }
    }

    function Get-DCCPUUsage {
        param($ComputerName)
        if (-not (Test-Connection $ComputerName -Count 1 -Quiet)) { return 'Fail' }
        try {
            $avg = Get-WmiObject Win32_Processor -ComputerName $ComputerName -ErrorAction Stop |
                   Measure-Object -Property LoadPercentage -Average |
                   Select-Object -ExpandProperty Average
            return [math]::Round($avg, 2)
        }
        catch { return 'WMI Failure' }
    }

    function Get-DCMemoryUsage {
        param($ComputerName)
        if (-not (Test-Connection $ComputerName -Count 1 -Quiet)) { return 'Fail' }
        try {
            $os    = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $used  = $os.TotalVisibleMemorySize - $os.FreePhysicalMemory
            return [math]::Round(($used / $os.TotalVisibleMemorySize) * 100, 2)
        }
        catch { return 'WMI Failure' }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($dc in (Get-AllDomainControllers $DomainName)) {
        $diag = Get-DCDiagResults $dc.HostName

        $results.Add([PSCustomObject]@{
            Server                 = ($dc.HostName.Split('.')[0]).ToUpper()
            Site                   = $dc.Site
            'DCDIAG: Connectivity' = $diag.Connectivity
            'DCDIAG: DFSREvent'    = $diag.DFSREvent
            'DCDIAG: KccEvent'     = $diag.KccEvent
            'DCDIAG: FSMO'         = $diag.KnowsOfRoleHolders
            'DCDIAG: NetLogons'    = $diag.NetLogons
            'Replication'          = $diag.ObjectsReplicated
            'OS Free Space (GB)'   = Get-DCOSDriveFreeSpaceGB $dc.HostName
            'CPU Usage (%)'        = Get-DCCPUUsage           $dc.HostName
            'Memory Usage (%)'     = Get-DCMemoryUsage        $dc.HostName
            'Uptime (days)'        = Get-DCUptimeDays         $dc.HostName
        })
    }

    return $results
}

# ========== COLLECT DATA FROM ALL DOMAINS ==========

$perDomainResults = @{}
foreach ($domain in $allDomains) {
    $pdc = $domainPDCs[$domain]
    Write-Host "Collecting health data from domain '$domain' via PDC '$pdc'..."
    $perDomainResults[$domain] = Invoke-Command -ComputerName $pdc `
        -ScriptBlock $domainHealthScriptBlock -ArgumentList $domain
}

# ========== HTML HELPER FUNCTION ==========

function New-StatusCell {
    param(
        $Value,
        [string]$Width = '70px'
    )
    $style = "height:25px;width:$Width;border:1px solid #000;padding:6px;text-align:center;"
    $color = switch ($Value) {
        { $_ -in 'Success','Passed','Pass' } { 'background-color:#6BBF59;color:#000;' }
        'Warn'                               { 'background-color:#FFD966;color:#000;' }
        { $_ -in 'Fail','Failed' }           { 'background-color:#D9534F;color:#fff;' }
        default                              { '' }
    }
    return "<td style='$style$color'>$Value</td>"
}

function New-MetricCell {
    param($Value, [double]$WarnThreshold, [double]$DangerThreshold, [string]$Width = '70px')
    $style = "height:25px;width:$Width;border:1px solid #000;padding:6px;text-align:center;"
    if ($Value -is [double] -or $Value -is [int]) {
        $color = if     ($Value -le $WarnThreshold)   { 'background-color:#6BBF59;color:#000;' }
                 elseif ($Value -le $DangerThreshold)  { 'background-color:#FFD966;color:#000;' }
                 else                                  { 'background-color:#D9534F;color:#fff;' }
        return "<td style='$style$color'>$Value</td>"
    }
    return "<td style='${style}background-color:#D9534F;color:#fff;'>$Value</td>"
}

# ========== BUILD HTML REPORT ==========

$htmlHead = @"
<html>
<body style='font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;font-size:10pt;'>
<h1 style='font-size:20px;'>Domain Controller Health Check Report</h1>
<h3 style='font-size:14px;'>Generated: $reportTime</h3>
"@

$tableHeader = @"
<table border='1' cellpadding='0' cellspacing='0'
  style='width:1300px;border-collapse:collapse;font-size:10pt;table-layout:fixed;'>
<tr style='background-color:#f2f2f2;'>
  <th style='width:120px;'>Server</th>
  <th style='width:110px;'>Site</th>
  <th style='width:70px;'>Connectivity</th>
  <th style='width:70px;'>DFSREvent</th>
  <th style='width:70px;'>KccEvent</th>
  <th style='width:70px;'>FSMO</th>
  <th style='width:70px;'>NetLogons</th>
  <th style='width:70px;'>Replication</th>
  <th style='width:70px;'>OS Free Space (GB)</th>
  <th style='width:70px;'>CPU Usage (%)</th>
  <th style='width:70px;'>Memory Usage (%)</th>
  <th style='width:70px;'>Uptime (days)</th>
</tr>
"@

$explanationTable = @"
<h3 style='color:#0056b3;margin-top:30px;'>Column Reference</h3>
<table border='1' cellpadding='4' cellspacing='0'
  style='border-collapse:collapse;width:50%;font-size:12px;'>
  <thead><tr style='background-color:#f2f2f2;'>
    <th>Field</th><th>Description</th>
  </tr></thead>
  <tbody>
    <tr><td>Connectivity</td><td>Checks basic connectivity between DCs.</td></tr>
    <tr><td>DFSREvent</td><td>Checks DFS Replication health for SYSVOL.</td></tr>
    <tr><td>KccEvent</td><td>Checks KCC event log for replication topology errors.</td></tr>
    <tr><td>FSMO</td><td>Confirms the DC knows all FSMO role holders.</td></tr>
    <tr><td>NetLogons</td><td>Validates the secure channel via Netlogon.</td></tr>
    <tr><td>Replication</td><td>Confirms AD objects replicate correctly.</td></tr>
    <tr><td>OS Free Space (GB)</td><td>Available disk space on the system drive.</td></tr>
    <tr><td>CPU Usage (%)</td><td>Current CPU utilisation. Warn >75%, Fail >90%.</td></tr>
    <tr><td>Memory Usage (%)</td><td>Current RAM utilisation. Warn >75%, Fail >90%.</td></tr>
    <tr><td>Uptime (days)</td><td>Days since last reboot. Warn >30 days, Fail >45 days.</td></tr>
  </tbody>
</table>
"@

$htmlTail = @"
<p style='font-size:11px;color:#555;margin-top:20px;'>
  Report generated by Get-ADForestHealth.ps1 — karanth.ovh
</p>
</body></html>
"@

# --------- ASSEMBLE PER-DOMAIN TABLES ---------

$allDomainTables = foreach ($domain in $allDomains) {
    $table = "<h2 style='color:#174ea6;'>Domain: $domain</h2>" + $tableHeader

    foreach ($dc in $perDomainResults[$domain]) {
        $row  = '<tr>'
        $row += "<td style='text-align:center;'><b>$($dc.Server)</b></td>"
        $row += "<td style='text-align:center;'>$($dc.Site)</td>"
        $row += New-StatusCell $dc.'DCDIAG: Connectivity'
        $row += New-StatusCell $dc.'DCDIAG: DFSREvent'
        $row += New-StatusCell $dc.'DCDIAG: KccEvent'
        $row += New-StatusCell $dc.'DCDIAG: FSMO'
        $row += New-StatusCell $dc.'DCDIAG: NetLogons'
        $row += New-StatusCell $dc.'Replication'
        $row += New-MetricCell $dc.'OS Free Space (GB)' -WarnThreshold 40  -DangerThreshold 20
        $row += New-MetricCell $dc.'CPU Usage (%)'      -WarnThreshold 75  -DangerThreshold 90
        $row += New-MetricCell $dc.'Memory Usage (%)'   -WarnThreshold 75  -DangerThreshold 90
        $row += New-MetricCell $dc.'Uptime (days)'      -WarnThreshold 30  -DangerThreshold 45
        $row += '</tr>'
        $table += $row
    }

    $table + '</table>'
}

$htmlBody = $htmlHead + ($allDomainTables -join '<br/><br/>') + $explanationTable + $htmlTail

# ========== OUTPUT ==========

New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
$htmlBody | Out-File -FilePath $outFile -Encoding UTF8
Write-Host "Report written to: $outFile" -ForegroundColor Green

# ========== EMAIL (uncomment to enable) ==========
# Send-MailMessage @smtpSettings -Body $htmlBody -BodyAsHtml `
#     -Encoding ([System.Text.Encoding]::UTF8) -ErrorAction Stop
# Write-Host "Email sent successfully." -ForegroundColor Green