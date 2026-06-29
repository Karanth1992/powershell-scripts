function Register-ADOpsKitScheduledTasks {
<#
.SYNOPSIS
    Interactively registers ADOpsKit functions as Windows Scheduled Tasks.

.DESCRIPTION
    Guides you through selecting which ADOpsKit functions to schedule,
    setting run times and frequency, specifying a service account, and
    choosing an output base path. Registers all selected tasks under the
    \ADOpsKit\ folder in Windows Task Scheduler.

    Each task:
        - Runs under the specified service account
        - Writes dated reports to OutputBasePath\<FunctionName>\yyyy-MM-dd_<report>
        - Logs transcript to OutputBasePath\Logs\<FunctionName>.log
        - Optionally emails the report as an attachment via SMTP after each run

.PARAMETER OutputBasePath
    Root folder for all reports and logs.
    Defaults to C:\ADOpsKit\Reports

.EXAMPLE
    Register-ADOpsKitScheduledTasks

.EXAMPLE
    Register-ADOpsKitScheduledTasks -OutputBasePath "D:\Reports\ADOpsKit"

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Requires: Run as Administrator, ADOpsKit module installed
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$OutputBasePath = 'C:\ADOpsKit\Reports'
    )

    #Requires -RunAsAdministrator

    $ErrorActionPreference = 'Stop'

    # --- helpers ---
    function Write-Banner {
        param([string]$Text)
        $line = '-' * ($Text.Length + 4)
        Write-Host "`n$line" -ForegroundColor DarkCyan
        Write-Host "  $Text" -ForegroundColor Cyan
        Write-Host "$line" -ForegroundColor DarkCyan
    }

    function Read-MenuChoice {
        param([string]$Prompt, [string[]]$Options)
        Write-Host "`n$Prompt" -ForegroundColor White
        for ($i = 0; $i -lt $Options.Count; $i++) {
            Write-Host "  [$($i+1)] $($Options[$i])"
        }
        do {
            $raw = Read-Host "  Enter choice (1-$($Options.Count))"
            $n   = 0
            $valid = [int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Options.Count
            if (-not $valid) { Write-Host "  Invalid - enter a number between 1 and $($Options.Count)." -ForegroundColor Yellow }
        } while (-not $valid)
        return $Options[$n - 1]
    }

    function Read-MultiMenuChoice {
        param([string]$Prompt, [string[]]$Options)
        Write-Host "`n$Prompt" -ForegroundColor White
        Write-Host "  [0] All of the above" -ForegroundColor Green
        for ($i = 0; $i -lt $Options.Count; $i++) {
            Write-Host "  [$($i+1)] $($Options[$i])"
        }
        Write-Host "  Enter numbers separated by commas, or 0 for all."
        do {
            $raw   = (Read-Host "  Choice").Trim()
            $parts = $raw -split ',' | ForEach-Object { $_.Trim() }
            if ($parts -contains '0') { return $Options }
            $selected = @()
            $valid = $true
            foreach ($p in $parts) {
                $n = 0
                if ([int]::TryParse($p, [ref]$n) -and $n -ge 1 -and $n -le $Options.Count) {
                    $selected += $Options[$n - 1]
                } else {
                    Write-Host "  Invalid entry: $p" -ForegroundColor Yellow
                    $valid = $false
                    break
                }
            }
        } while (-not $valid -or $selected.Count -eq 0)
        return $selected
    }

    function Get-PlainText {
        param([SecureString]$Secure)
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
        try { [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
    }

    function New-ADOpsKitTask {
        param(
            [string]$TaskName,
            [string]$Description,
            [string]$ScriptBlock,
            [CimInstance]$Trigger,
            [string]$Account,
            [string]$Password,
            [string]$BasePath,
            [hashtable]$EmailConfig
        )

        $logFile = Join-Path $BasePath "Logs\$TaskName.log"
        $logDir  = Split-Path $logFile
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

        # Build optional email block
        $emailBlock = ''
        if ($EmailConfig -and $EmailConfig.Enabled) {
            $smtpServer  = $EmailConfig.SmtpServer
            $smtpPort    = $EmailConfig.Port
            $fromAddr    = $EmailConfig.From
            $toAddr      = $EmailConfig.To
            $smtpUser    = $EmailConfig.Username
            $smtpPass    = $EmailConfig.Password
            $useSsl      = $EmailConfig.UseSsl

            $emailBlock = @"

    # --- Email report ---
    try {
        `$reportFiles = Get-ChildItem -Path '$BasePath\$TaskName' -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (`$reportFiles) {
            `$smtpCred = New-Object System.Management.Automation.PSCredential('$smtpUser', (ConvertTo-SecureString '$smtpPass' -AsPlainText -Force))
            Send-MailMessage ``
                -SmtpServer '$smtpServer' ``
                -Port $smtpPort ``
                -UseSsl:`$$useSsl ``
                -Credential `$smtpCred ``
                -From '$fromAddr' ``
                -To '$toAddr' ``
                -Subject "ADOpsKit Report: $TaskName `$(Get-Date -Format 'yyyy-MM-dd')" ``
                -Body "Please find the attached ADOpsKit report for $TaskName generated on `$(Get-Date -Format 'yyyy-MM-dd HH:mm')." ``
                -Attachments `$reportFiles.FullName ``
                -ErrorAction Stop
            Write-Host "  Report emailed to $toAddr"
        } else {
            Write-Warning "No report file found to email for $TaskName"
        }
    } catch {
        Write-Warning "Email failed for $TaskName : `$_"
    }
"@
        }

        $fullScript = @"
Start-Transcript -Path '$logFile' -Append -Force
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module ADOpsKit -ErrorAction Stop
    $ScriptBlock
$emailBlock
} catch {
    Write-Error "ADOpsKit task '$TaskName' failed: ``$_"
} finally {
    Stop-Transcript
}
"@

        $psExe    = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $escaped  = $fullScript -replace '"', '\"'
        $action   = New-ScheduledTaskAction -Execute $psExe -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -Command `"$escaped`""
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        $existing = Get-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Confirm:$false
        }

        Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Description $Description `
            -Action $action -Trigger $Trigger -Settings $settings `
            -User $Account -Password $Password -RunLevel Highest | Out-Null

        Write-Host "  [OK] Registered: \ADOpsKit\$TaskName" -ForegroundColor Green
    }

    # --- Available functions ---
    $allFunctions = @(
        'Get-AccountLockoutReport',
        'Get-InsecureLDAPBinds',
        'Get-ADForestHealth',
        'Test-DCPortHealth',
        'Get-EntraConnectSyncStatus',
        'Get-GPOInventory',
        'Get-GPOInventoryWithSettings',
        'Get-ADArchitectureAssessment',
        'Get-ADReplicationTopologyDiagram'
    )

    $dailySuggested  = @('Get-AccountLockoutReport','Get-InsecureLDAPBinds','Get-ADForestHealth','Test-DCPortHealth','Get-EntraConnectSyncStatus')
    $weeklySuggested = @('Get-GPOInventory','Get-GPOInventoryWithSettings','Get-ADArchitectureAssessment','Get-ADReplicationTopologyDiagram')

    # --- Welcome ---
    Write-Banner "ADOpsKit - Scheduled Task Setup"
    Write-Host "`n  This wizard registers ADOpsKit functions as Windows Scheduled Tasks."
    Write-Host "  Tasks will be created under \ADOpsKit\ in Task Scheduler."
    Write-Host "  Reports will be saved to: $OutputBasePath\<FunctionName>\"
    Write-Host ""

    # --- Step 1: Service account ---
    Write-Banner "Step 1 of 4 - Service Account"
    $account = Read-Host "  Enter service account (DOMAIN\username)"
    $securePwd = Read-Host "  Password for $account" -AsSecureString
    $plainPwd  = Get-PlainText -Secure $securePwd

    # --- Step 2: Domain name ---
    Write-Banner "Step 2 of 4 - Domain"
    $domainName = Read-Host "  Enter domain FQDN (e.g. corp.contoso.com)"

    # --- Step 3: Function selection ---
    Write-Banner "Step 3 of 4 - Select Functions"
    Write-Host "`n  Suggested daily  : $($dailySuggested -join ', ')" -ForegroundColor DarkGray
    Write-Host "  Suggested weekly : $($weeklySuggested -join ', ')" -ForegroundColor DarkGray

    $selectedFunctions = Read-MultiMenuChoice `
        -Prompt  "Which functions do you want to schedule?" `
        -Options $allFunctions

    # --- Step 4: Schedule + Email per function ---
    Write-Banner "Step 4 of 4 - Schedule & Email"
    Write-Host "`n  Configure schedule and optional email for each selected function." -ForegroundColor White

    # Collect SMTP server settings once if user wants email for any task
    $sharedSmtp = $null

    $taskConfigs = @()

    foreach ($fn in $selectedFunctions) {
        Write-Host "`n  ---- $fn ----" -ForegroundColor Cyan

        # Schedule
        $freq = Read-MenuChoice -Prompt "  Frequency" -Options @('Daily', 'Weekly')

        if ($freq -eq 'Daily') {
            $timeStr = Read-Host "  Run time (HH:mm, default 06:00)"
            if ([string]::IsNullOrWhiteSpace($timeStr)) { $timeStr = '06:00' }
            $trigger = New-ScheduledTaskTrigger -Daily -At $timeStr
        } else {
            $day     = Read-MenuChoice -Prompt "  Day of week" -Options @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
            $timeStr = Read-Host "  Run time (HH:mm, default 02:00)"
            if ([string]::IsNullOrWhiteSpace($timeStr)) { $timeStr = '02:00' }
            $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $day -At $timeStr
        }

        # Email
        $emailConfig = @{ Enabled = $false }
        $wantEmail = Read-Host "  Email report after run? (Y/N)"
        if ($wantEmail -match '^[Yy]') {

            # Collect SMTP server/port/SSL/auth once and reuse unless user wants different settings
            if ($sharedSmtp -and (Read-Host "  Use same SMTP settings as previous task? (Y/N)") -match '^[Yy]') {
                $smtpServer = $sharedSmtp.SmtpServer
                $smtpPort   = $sharedSmtp.Port
                $useSsl     = $sharedSmtp.UseSsl
                $smtpUser   = $sharedSmtp.Username
                $smtpPass   = $sharedSmtp.Password
            } else {
                $smtpServer = Read-Host "  SMTP server (e.g. smtp.office365.com)"
                $portRaw    = Read-Host "  SMTP port (default 587)"
                $smtpPort   = if ([string]::IsNullOrWhiteSpace($portRaw)) { 587 } else { [int]$portRaw }
                $sslAnswer  = Read-MenuChoice -Prompt "  Use SSL/TLS?" -Options @('Yes', 'No')
                $useSsl     = $sslAnswer -eq 'Yes'
                $authAnswer = Read-MenuChoice -Prompt "  SMTP authentication?" -Options @('Username and password', 'No authentication (relay)')
                if ($authAnswer -eq 'Username and password') {
                    $smtpUser   = Read-Host "  SMTP username"
                    $smtpSecure = Read-Host "  SMTP password" -AsSecureString
                    $smtpPass   = Get-PlainText -Secure $smtpSecure
                } else {
                    $smtpUser = ''
                    $smtpPass = ''
                }
                $sharedSmtp = @{ SmtpServer = $smtpServer; Port = $smtpPort; UseSsl = $useSsl; Username = $smtpUser; Password = $smtpPass }
            }

            $fromAddr = Read-Host "  From address"
            $toAddr   = Read-Host "  To address"

            $emailConfig = @{
                Enabled    = $true
                SmtpServer = $smtpServer
                Port       = $smtpPort
                UseSsl     = $useSsl
                From       = $fromAddr
                To         = $toAddr
                Username   = $smtpUser
                Password   = $smtpPass
            }
            Write-Host "  [OK] Report will be emailed to $toAddr" -ForegroundColor Green
        }

        $taskConfigs += [PSCustomObject]@{
            Name        = $fn
            Frequency   = $freq
            Time        = $timeStr
            Trigger     = $trigger
            EmailConfig = $emailConfig
        }
    }

    # --- Confirm ---
    Write-Banner "Review - Tasks to Register"
    $taskConfigs | ForEach-Object {
        $emailSummary = if ($_.EmailConfig.Enabled) { $_.EmailConfig.To } else { 'No email' }
        [PSCustomObject]@{ Name = $_.Name; Frequency = $_.Frequency; Time = $_.Time; Email = $emailSummary }
    } | Format-Table -AutoSize
    $confirm = Read-Host "`n  Proceed? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`n  Cancelled." -ForegroundColor Yellow
        return
    }

    # --- Create Task Scheduler folder ---
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $root = $scheduler.GetFolder('\')
    try { $root.GetFolder('ADOpsKit') | Out-Null }
    catch { $root.CreateFolder('ADOpsKit') | Out-Null }

    if (-not (Test-Path $OutputBasePath)) {
        New-Item -ItemType Directory -Path $OutputBasePath -Force | Out-Null
    }

    # --- Register tasks ---
    Write-Banner "Registering Tasks"

    $scriptBlocks = @{
        'Get-AccountLockoutReport'         = "Get-AccountLockoutReport -TempPath '$OutputBasePath\Get-AccountLockoutReport' -SharedPath '$OutputBasePath\Get-AccountLockoutReport'"
        'Get-InsecureLDAPBinds'            = "Get-InsecureLDAPBinds -Hours 24 -OutputPath '$OutputBasePath\Get-InsecureLDAPBinds'"
        'Get-ADForestHealth'               = "Get-ADForestHealth -OutputFolder '$OutputBasePath\Get-ADForestHealth'"
        'Test-DCPortHealth'                = "Test-DCPortHealth -TimeoutSeconds 5 -ExportPath '$OutputBasePath\Test-DCPortHealth\`$(Get-Date -Format ''yyyy-MM-dd'')_DCPortHealth.csv'"
        'Get-EntraConnectSyncStatus'       = "Get-EntraConnectSyncStatus -ExportPath '$OutputBasePath\Get-EntraConnectSyncStatus\`$(Get-Date -Format ''yyyy-MM-dd'')_EntraConnectStatus.csv'"
        'Get-GPOInventory'                 = "Get-GPOInventory -DomainName '$domainName' -OutputPath '$OutputBasePath\Get-GPOInventory\`$(Get-Date -Format ''yyyy-MM-dd'')_GPOInventory.html'"
        'Get-GPOInventoryWithSettings'     = "Get-GPOInventoryWithSettings -DomainName '$domainName' -OutputPath '$OutputBasePath\Get-GPOInventoryWithSettings\`$(Get-Date -Format ''yyyy-MM-dd'')_GPOInventoryWithSettings.html'"
        'Get-ADArchitectureAssessment'     = "Get-ADArchitectureAssessment -DomainName '$domainName' -OutputFolder '$OutputBasePath\Get-ADArchitectureAssessment'"
        'Get-ADReplicationTopologyDiagram' = "Get-ADReplicationTopologyDiagram -OutputPath '$OutputBasePath\Get-ADReplicationTopologyDiagram\`$(Get-Date -Format ''yyyy-MM-dd'')_ADReplicationTopology.html'"
    }

    foreach ($cfg in $taskConfigs) {
        New-ADOpsKitTask `
            -TaskName    $cfg.Name `
            -Description "ADOpsKit scheduled task - $($cfg.Name)" `
            -ScriptBlock $scriptBlocks[$cfg.Name] `
            -Trigger     $cfg.Trigger `
            -Account     $account `
            -Password    $plainPwd `
            -BasePath    $OutputBasePath `
            -EmailConfig $cfg.EmailConfig
    }

    # --- Done ---
    Write-Banner "Done"
    Write-Host "`n  Tasks registered under \ADOpsKit\ in Task Scheduler."
    Write-Host "  Reports   : $OutputBasePath\<FunctionName>\"
    Write-Host "  Logs      : $OutputBasePath\Logs\"
    $emailEnabled = $taskConfigs | Where-Object { $_.EmailConfig.Enabled }
    if ($emailEnabled) {
        Write-Host "  Email     : $($emailEnabled.Count) task(s) configured to send reports by email." -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "  Verify with:"
    Write-Host "    Get-ScheduledTask -TaskPath '\ADOpsKit\' | Select-Object TaskName, State" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Test a task immediately:"
    Write-Host "    Start-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName 'Test-DCPortHealth'" -ForegroundColor DarkGray
}
