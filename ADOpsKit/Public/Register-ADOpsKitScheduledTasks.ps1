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
            [string]$BasePath
        )

        $logFile = Join-Path $BasePath "Logs\$TaskName.log"
        $logDir  = Split-Path $logFile
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

        $fullScript = @"
Start-Transcript -Path '$logFile' -Append -Force
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module ADOpsKit -ErrorAction Stop
    $ScriptBlock
} catch {
    Write-Error "ADOpsKit task '$TaskName' failed: `$_"
} finally {
    Stop-Transcript
}
"@

        $psExe    = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $escaped  = $fullScript -replace '"', '\"'
        $action   = New-ScheduledTaskAction -Execute $psExe -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -Command `"$escaped`""
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
        $principal = New-ScheduledTaskPrincipal -UserId $Account -LogonType Password -RunLevel Highest

        $existing = Get-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Confirm:$false
        }

        Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Description $Description `
            -Action $action -Trigger $Trigger -Principal $principal -Settings $settings -Password $Password | Out-Null

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

    # --- Service account ---
    Write-Banner "Step 1 of 4 - Service Account"
    $account = Read-Host "  Enter service account (DOMAIN\username)"
    $securePwd = Read-Host "  Password for $account" -AsSecureString
    $plainPwd  = Get-PlainText -Secure $securePwd

    # --- Domain name (for functions that need it) ---
    Write-Banner "Step 2 of 4 - Domain"
    $domainName = Read-Host "  Enter domain FQDN (e.g. corp.contoso.com)"

    # --- Function selection ---
    Write-Banner "Step 3 of 4 - Select Functions"
    Write-Host "`n  Suggested daily  : $($dailySuggested -join ', ')" -ForegroundColor DarkGray
    Write-Host "  Suggested weekly : $($weeklySuggested -join ', ')" -ForegroundColor DarkGray

    $selectedFunctions = Read-MultiMenuChoice `
        -Prompt  "Which functions do you want to schedule?" `
        -Options $allFunctions

    # --- Schedule per function ---
    Write-Banner "Step 4 of 4 - Schedule"

    $taskConfigs = @()

    foreach ($fn in $selectedFunctions) {
        Write-Host "`n  Configuring: $fn" -ForegroundColor White

        $freq = Read-MenuChoice -Prompt "  Frequency for $fn" -Options @('Daily', 'Weekly')

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

        $taskConfigs += [PSCustomObject]@{
            Name      = $fn
            Frequency = $freq
            Time      = $timeStr
            Trigger   = $trigger
        }
    }

    # --- Confirm ---
    Write-Banner "Review - Tasks to Register"
    $taskConfigs | Format-Table Name, Frequency, Time -AutoSize
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
        'Get-AccountLockoutReport'        = "Get-AccountLockoutReport -TempPath '$OutputBasePath\Get-AccountLockoutReport' -SharedPath '$OutputBasePath\Get-AccountLockoutReport'"
        'Get-InsecureLDAPBinds'           = "Get-InsecureLDAPBinds -Hours 24 -OutputPath '$OutputBasePath\Get-InsecureLDAPBinds'"
        'Get-ADForestHealth'              = "Get-ADForestHealth -OutputFolder '$OutputBasePath\Get-ADForestHealth'"
        'Test-DCPortHealth'               = "Test-DCPortHealth -TimeoutSeconds 5 -ExportPath '$OutputBasePath\Test-DCPortHealth\`$(Get-Date -Format ''yyyy-MM-dd'')_DCPortHealth.csv'"
        'Get-EntraConnectSyncStatus'      = "Get-EntraConnectSyncStatus -ExportPath '$OutputBasePath\Get-EntraConnectSyncStatus\`$(Get-Date -Format ''yyyy-MM-dd'')_EntraConnectStatus.csv'"
        'Get-GPOInventory'                = "Get-GPOInventory -DomainName '$domainName' -OutputPath '$OutputBasePath\Get-GPOInventory\`$(Get-Date -Format ''yyyy-MM-dd'')_GPOInventory.html'"
        'Get-GPOInventoryWithSettings'    = "Get-GPOInventoryWithSettings -DomainName '$domainName' -OutputPath '$OutputBasePath\Get-GPOInventoryWithSettings\`$(Get-Date -Format ''yyyy-MM-dd'')_GPOInventoryWithSettings.html'"
        'Get-ADArchitectureAssessment'    = "Get-ADArchitectureAssessment -DomainName '$domainName' -OutputFolder '$OutputBasePath\Get-ADArchitectureAssessment'"
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
            -BasePath    $OutputBasePath
    }

    # --- Done ---
    Write-Banner "Done"
    Write-Host "`n  Tasks registered under \ADOpsKit\ in Task Scheduler."
    Write-Host "  Reports   : $OutputBasePath\<FunctionName>\"
    Write-Host "  Logs      : $OutputBasePath\Logs\"
    Write-Host ""
    Write-Host "  Verify with:"
    Write-Host "    Get-ScheduledTask -TaskPath '\ADOpsKit\' | Select-Object TaskName, State" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Test a task immediately:"
    Write-Host "    Start-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName 'Test-DCPortHealth'" -ForegroundColor DarkGray
}
