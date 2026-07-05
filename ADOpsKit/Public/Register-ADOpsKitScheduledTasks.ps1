function Register-ADOpsKitScheduledTasks {
<#
.SYNOPSIS
    Interactively registers ADOpsKit functions as Windows Scheduled Tasks.

.DESCRIPTION
    Guides you through selecting which ADOpsKit functions to schedule,
    setting run times and frequency, specifying a service account, and
    choosing an output base path. Registers all selected tasks under the
    \ADOpsKit\ folder in Windows Task Scheduler.

    This function MAKES CHANGES: it registers/replaces scheduled tasks,
    creates folders, writes task scripts, and restricts folder permissions.
    Supports -WhatIf / -Confirm. WinRM is not required.

    Service account handling:
        - Regular accounts are validated up front with a local batch logon
          check (LogonUser / LOGON32_LOGON_BATCH) which verifies both the
          password AND the 'Log on as a batch job' right in one call, so a
          mistyped password fails immediately instead of at the end of the
          wizard. Each failed check counts as one bad-password attempt
          toward the account lockout threshold.
        - Group Managed Service Accounts (gMSA) are supported as a
          passwordless alternative. The gMSA must be installed on / allowed
          to retrieve its password from this computer; this is verified
          with Test-ADServiceAccount when the ActiveDirectory module is
          available.

    Each task:
        - Runs under the specified service account or gMSA
        - Writes dated reports to OutputBasePath\<FunctionName>\yyyy-MM-dd_<report>
        - Logs transcript to OutputBasePath\Logs\<FunctionName>.log
          (rotated to .log.old when it exceeds 10 MB)
        - Optionally emails the report as an attachment via SMTP after each run
        - Deletes its own reports older than RetentionDays after each run
        - Exits 0 on success, 1 if the function failed, 2 if the report
          email could not be sent - visible as Last Run Result in Task
          Scheduler

    Security notes:
        - Task scripts with SMTP authentication embed the SMTP password.
          The Scripts folder ACL is therefore restricted to SYSTEM,
          Administrators, and the service account.
        - The saved configuration file never contains passwords.

    After a successful run the chosen settings (minus passwords) are saved
    to OutputBasePath\ADOpsKitTasks.config.json. Re-running with -ConfigPath
    replays that setup, prompting only for passwords and confirmation.

.PARAMETER OutputBasePath
    Root folder for all reports, logs, task scripts, and the saved config.
    Defaults to C:\ADOpsKit\Reports

.PARAMETER ConfigPath
    Path to a previously saved ADOpsKitTasks.config.json. Replays the saved
    setup (account, domain, functions, schedules, email settings) so only
    passwords and the final confirmation are prompted.

.PARAMETER RetentionDays
    Days to keep dated report files in each task's output folder. Each task
    deletes its own reports older than this after each run. 0 disables
    cleanup. Default: 90.

.EXAMPLE
    Register-ADOpsKitScheduledTasks

.EXAMPLE
    Register-ADOpsKitScheduledTasks -OutputBasePath 'D:\Reports\ADOpsKit' -RetentionDays 30

.EXAMPLE
    Register-ADOpsKitScheduledTasks -ConfigPath 'C:\ADOpsKit\Reports\ADOpsKitTasks.config.json'

.EXAMPLE
    Register-ADOpsKitScheduledTasks -WhatIf

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Requires: Run as Administrator, ADOpsKit module installed.
              gMSA verification additionally uses the ActiveDirectory module
              when present (skipped with a warning otherwise).
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$OutputBasePath = 'C:\ADOpsKit\Reports',

        [ValidateNotNullOrEmpty()]
        [string]$ConfigPath,

        [ValidateRange(0, 3650)]
        [int]$RetentionDays = 90
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

    function Read-RunTime {
        param([string]$Prompt, [string]$Default)
        do {
            $raw = Read-Host "$Prompt (HH:mm, default $Default)"
            if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $Default }
            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParseExact($raw.Trim(), [string[]]@('HH:mm', 'H:mm'),
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
            if (-not $ok) { Write-Host "  Invalid time '$raw' - use 24-hour HH:mm (e.g. 06:30)." -ForegroundColor Yellow }
        } while (-not $ok)
        return $parsed.ToString('HH:mm')
    }

    function Get-PlainText {
        param([SecureString]$Secure)
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
        try { [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
    }

    function ConvertTo-EscapedLiteral {
        # Escapes a value for embedding inside a single-quoted string in generated task scripts
        param([AllowEmptyString()][string]$Value)
        return $Value -replace "'", "''"
    }

    function ConvertTo-EscapedExpandable {
        # Escapes a value for embedding inside a double-quoted string in generated task scripts
        param([AllowEmptyString()][string]$Value)
        return $Value.Replace('`', '``').Replace('"', '`"').Replace('$', '`$')
    }

    function Get-ConfigProp {
        # Safe property read from a JSON-imported object (tolerates missing properties)
        param($Object, [string]$Name, $Default)
        if ($null -ne $Object -and $Object.PSObject.Properties[$Name] -and $null -ne $Object.$Name) {
            return $Object.$Name
        }
        return $Default
    }

    function Test-ServiceAccountCredential {
        <#
            Validates the account/password pair with a local batch logon
            (LogonUser, LOGON32_LOGON_BATCH). This verifies the password AND
            the 'Log on as a batch job' right - exactly what a scheduled task
            needs. Local API call only; no WinRM.
            Note: a failed check counts as one bad-password attempt against
            the account lockout policy.
        #>
        param(
            [string]$Account,
            [string]$Password
        )

        if (-not ('ADOpsKitInternal.LogonApi' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ADOpsKitInternal {
    public static class LogonApi {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
        }

        $domainPart = $null
        $userPart   = $Account
        if ($Account -match '^(?<dom>[^\\]+)\\(?<usr>.+)$') {
            $domainPart = $Matches['dom']
            $userPart   = $Matches['usr']
        } elseif ($Account -notmatch '@') {
            # Bare username - treat as local account. UPNs pass through with a null domain.
            $domainPart = '.'
        }

        $token = [IntPtr]::Zero
        try {
            # logonType 4 = LOGON32_LOGON_BATCH, logonProvider 0 = default
            $ok = [ADOpsKitInternal.LogonApi]::LogonUser($userPart, $domainPart, $Password, 4, 0, [ref]$token)
            if ($ok) {
                return [pscustomobject]@{ Status = 'Valid'; Message = 'Credentials valid; batch logon right confirmed.' }
            }
            $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $status = switch ($code) {
                1326    { 'BadCredentials' }
                1385    { 'NoBatchRight' }
                1909    { 'LockedOut' }
                1330    { 'PasswordExpired' }
                1907    { 'PasswordMustChange' }
                1331    { 'AccountDisabled' }
                1327    { 'AccountRestriction' }
                default { 'Unknown' }
            }
            $msg = (New-Object System.ComponentModel.Win32Exception($code)).Message
            return [pscustomobject]@{ Status = $status; Message = "$msg (Win32 error $code)" }
        } catch {
            return [pscustomobject]@{ Status = 'Unknown'; Message = $_.Exception.Message }
        } finally {
            if ($token -ne [IntPtr]::Zero) { [void][ADOpsKitInternal.LogonApi]::CloseHandle($token) }
        }
    }

    function Test-GmsaAccount {
        <#
            Verifies this computer can use the gMSA (retrieve its managed
            password). Returns $true / $false, or $null when verification is
            not possible (no ActiveDirectory module, no DC reachable).
        #>
        param([string]$Account)
        $name = ($Account -split '\\')[-1]
        try {
            Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
            return [bool](Test-ADServiceAccount -Identity $name -ErrorAction Stop)
        } catch {
            Write-Warning "Could not verify gMSA '$Account': $($_.Exception.Message)"
            return $null
        }
    }

    function Protect-ScriptsFolder {
        <#
            Restricts the Scripts folder to SYSTEM, Administrators, and the
            service account. Task scripts with SMTP authentication embed the
            SMTP password, so ordinary users must not be able to read them.
        #>
        param([string]$Path, [string]$Account)
        try {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
            foreach ($entry in @(
                @{ Id = 'NT AUTHORITY\SYSTEM';    Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
                @{ Id = 'BUILTIN\Administrators'; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
                @{ Id = $Account;                 Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
            )) {
                $ref  = New-Object System.Security.Principal.NTAccount($entry.Id)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $ref, $entry.Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
            Write-Host "  [OK] Restricted permissions on $Path (SYSTEM, Administrators, $Account)" -ForegroundColor Green
        } catch {
            Write-Warning "Could not restrict permissions on '$Path': $($_.Exception.Message). Task scripts may contain SMTP credentials - restrict access manually."
        }
    }

    function New-ADOpsKitTask {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$TaskName,
            [string]$Description,
            [string]$ScriptBlock,
            [CimInstance]$Trigger,
            [string]$Account,
            [string]$Password,
            [switch]$IsGmsa,
            [string]$BasePath,
            [int]$RetentionDays,
            [hashtable]$EmailConfig
        )

        if (-not $PSCmdlet.ShouldProcess("\ADOpsKit\$TaskName", 'Register scheduled task and write task script')) { return }

        $logFile = Join-Path $BasePath "Logs\$TaskName.log"
        $logDir  = Split-Path $logFile
        if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

        $sqLog       = ConvertTo-EscapedLiteral $logFile
        $sqReportDir = ConvertTo-EscapedLiteral (Join-Path $BasePath $TaskName)

        # Build optional email block
        $emailBlock = ''
        if ($EmailConfig -and $EmailConfig.Enabled) {
            $sqServer = ConvertTo-EscapedLiteral $EmailConfig.SmtpServer
            $smtpPort = [int]$EmailConfig.Port
            $sqFrom   = ConvertTo-EscapedLiteral $EmailConfig.From
            $sqTo     = ConvertTo-EscapedLiteral $EmailConfig.To

            $sslLine = ''
            if ($EmailConfig.UseSsl) {
                $sslLine = "            `$mailParams['UseSsl'] = `$true"
            }
            $credLine = ''
            if ($EmailConfig.Username) {
                $sqUser   = ConvertTo-EscapedLiteral $EmailConfig.Username
                $sqPass   = ConvertTo-EscapedLiteral $EmailConfig.Password
                $credLine = "            `$mailParams['Credential'] = New-Object System.Management.Automation.PSCredential('$sqUser', (ConvertTo-SecureString '$sqPass' -AsPlainText -Force))"
            }

            $emailBlock = @"

    # --- Email report ---
    try {
        `$reportFiles = Get-ChildItem -Path '$sqReportDir' -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (`$reportFiles) {
            `$mailParams = @{
                SmtpServer  = '$sqServer'
                Port        = $smtpPort
                From        = '$sqFrom'
                To          = '$sqTo'
                Subject     = "ADOpsKit Report: $TaskName `$(Get-Date -Format 'yyyy-MM-dd')"
                Body        = "Please find the attached ADOpsKit report for $TaskName generated on `$(Get-Date -Format 'yyyy-MM-dd HH:mm')."
                Attachments = `$reportFiles.FullName
                ErrorAction = 'Stop'
            }
$sslLine
$credLine
            Send-MailMessage @mailParams
            Write-Host '  Report emailed to $sqTo'
        } else {
            Write-Warning "No report file found to email for $TaskName"
            `$exitCode = 2
        }
    } catch {
        Write-Warning "Email failed for $TaskName : `$_"
        `$exitCode = 2
    }
"@
        }

        # Optional retention block
        $retentionBlock = ''
        if ($RetentionDays -gt 0) {
            $retentionBlock = @"

    # --- Retention: remove reports older than $RetentionDays days ---
    try {
        Get-ChildItem -Path '$sqReportDir' -File -ErrorAction Stop |
            Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } |
            Remove-Item -Force -ErrorAction Stop
    } catch {
        Write-Warning "Retention cleanup failed for $TaskName : `$_"
    }
"@
        }

        # Write script to a .ps1 file - avoids all escaping issues with -Command
        $scriptDir  = Join-Path $BasePath 'Scripts'
        if (-not (Test-Path -LiteralPath $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }
        $scriptFile = Join-Path $scriptDir "$TaskName.ps1"

        $fullScript = @"
# Generated by Register-ADOpsKitScheduledTasks (ADOpsKit) on $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# Exit codes: 0 = success, 1 = task function failed, 2 = report email problem
`$exitCode = 0
`$logFile  = '$sqLog'
if ((Test-Path -LiteralPath `$logFile) -and ((Get-Item -LiteralPath `$logFile).Length -gt 10MB)) {
    Move-Item -LiteralPath `$logFile -Destination (`$logFile + '.old') -Force
}
Start-Transcript -Path `$logFile -Append -Force
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Import-Module ADOpsKit -ErrorAction Stop
    $ScriptBlock
$emailBlock
$retentionBlock
} catch {
    Write-Error "ADOpsKit task '$TaskName' failed: `$_"
    `$exitCode = 1
} finally {
    Stop-Transcript
}
exit `$exitCode
"@
        $fullScript | Set-Content -LiteralPath $scriptFile -Encoding UTF8

        $psExe  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $action = New-ScheduledTaskAction -Execute $psExe -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$scriptFile`""
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        $existing = Get-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Confirm:$false
        }

        if ($IsGmsa) {
            $principal = New-ScheduledTaskPrincipal -UserId $Account -LogonType Password -RunLevel Highest
            Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Description $Description `
                -Action $action -Trigger $Trigger -Settings $settings -Principal $principal | Out-Null
        } else {
            Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Description $Description `
                -Action $action -Trigger $Trigger -Settings $settings `
                -User $Account -Password $Password -RunLevel Highest | Out-Null
        }

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

    # --- Load saved config (replay mode) ---
    $importedConfig = $null
    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            throw "Config file not found: $ConfigPath"
        }
        try {
            $importedConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        } catch {
            throw "Could not parse config file '$ConfigPath': $($_.Exception.Message)"
        }
        if (-not $PSBoundParameters.ContainsKey('OutputBasePath')) {
            $cfgBase = [string](Get-ConfigProp $importedConfig 'OutputBasePath' '')
            if ($cfgBase) { $OutputBasePath = $cfgBase }
        }
        if (-not $PSBoundParameters.ContainsKey('RetentionDays')) {
            $RetentionDays = [int](Get-ConfigProp $importedConfig 'RetentionDays' $RetentionDays)
        }
    }

    # --- Welcome ---
    Write-Banner "ADOpsKit - Scheduled Task Setup"
    Write-Host "`n  This wizard registers ADOpsKit functions as Windows Scheduled Tasks."
    Write-Host "  Tasks will be created under \ADOpsKit\ in Task Scheduler."
    Write-Host "  Reports will be saved to: $OutputBasePath\<FunctionName>\"
    if ($RetentionDays -gt 0) {
        Write-Host "  Reports older than $RetentionDays days are removed after each run." -ForegroundColor DarkGray
    }
    if ($importedConfig) {
        Write-Host "  Replaying saved configuration from: $ConfigPath" -ForegroundColor Cyan
    }
    Write-Host ""

    # --- Step 1: Service account ---
    Write-Banner "Step 1 of 4 - Service Account"

    if ($importedConfig) {
        $account = [string](Get-ConfigProp $importedConfig 'Account' '')
        if (-not $account) { throw "Config file has no 'Account' value." }
        $isGmsa = ([string](Get-ConfigProp $importedConfig 'AccountType' 'Regular')) -eq 'gMSA'
        Write-Host "  Account (from config): $account$(if ($isGmsa) { ' (gMSA)' })"
    } else {
        $typeChoice = Read-MenuChoice -Prompt "  Account type" -Options @(
            'Regular service account (DOMAIN\username + password)',
            'Group Managed Service Account (gMSA - passwordless)'
        )
        $isGmsa = $typeChoice -like 'Group Managed*'
    }

    $plainPwd = ''
    if ($isGmsa) {
        $accountOk = $false
        do {
            if (-not $importedConfig) {
                $account = Read-Host '  Enter gMSA account (DOMAIN\name$)'
                if ($account -notmatch '\$$') { $account = $account + '$' }
            }
            Write-Host "  Verifying gMSA on this computer..." -ForegroundColor DarkGray
            $gmsaCheck = Test-GmsaAccount -Account $account
            if ($gmsaCheck -eq $true) {
                Write-Host "  [OK] gMSA verified - this computer can retrieve its managed password." -ForegroundColor Green
                $accountOk = $true
            } elseif ($gmsaCheck -eq $false) {
                Write-Host "  [FAIL] This computer cannot use gMSA '$account'." -ForegroundColor Red
                Write-Host "         Check PrincipalsAllowedToRetrieveManagedPassword and run Install-ADServiceAccount." -ForegroundColor Yellow
                if ($importedConfig) {
                    if ((Read-Host "  Continue anyway? (Y/N)") -match '^[Yy]') { $accountOk = $true }
                    else { Write-Host "`n  Cancelled." -ForegroundColor Yellow; return }
                } else {
                    if ((Read-Host "  Try a different account? (Y/N)") -notmatch '^[Yy]') {
                        Write-Host "`n  Cancelled." -ForegroundColor Yellow; return
                    }
                }
            } else {
                if ((Read-Host "  Could not verify the gMSA. Continue anyway? (Y/N)") -match '^[Yy]') {
                    Write-Host "  [SKIP] Proceeding with unverified gMSA." -ForegroundColor Yellow
                    $accountOk = $true
                } else { Write-Host "`n  Cancelled." -ForegroundColor Yellow; return }
            }
        } while (-not $accountOk)
    } else {
        $credentialsOk = $false
        do {
            if (-not $importedConfig) {
                $account = Read-Host "  Enter service account (DOMAIN\username)"
            }
            $securePwd = Read-Host "  Password for $account" -AsSecureString
            $plainPwd  = Get-PlainText -Secure $securePwd

            Write-Host "  Validating credentials (batch logon check)..." -ForegroundColor DarkGray
            $check = Test-ServiceAccountCredential -Account $account -Password $plainPwd

            switch ($check.Status) {
                'Valid' {
                    Write-Host "  [OK] Credentials valid; 'Log on as a batch job' right confirmed." -ForegroundColor Green
                    $credentialsOk = $true
                }
                'NoBatchRight' {
                    Write-Host "  [OK] Credentials valid." -ForegroundColor Green
                    Write-Host "  [WARN] '$account' currently lacks the 'Log on as a batch job' right here." -ForegroundColor Yellow
                    Write-Host "         Task Scheduler normally grants it at registration, but a Group Policy" -ForegroundColor Yellow
                    Write-Host "         managing that right centrally can strip it again and break the tasks." -ForegroundColor Yellow
                    $credentialsOk = $true
                }
                'BadCredentials' {
                    Write-Host "  [FAIL] Wrong username or password for $account." -ForegroundColor Red
                    Write-Host "         Note: each failed check counts toward the account lockout threshold." -ForegroundColor Yellow
                    if ((Read-Host "  Try again? (Y/N)") -notmatch '^[Yy]') {
                        Write-Host "`n  Cancelled." -ForegroundColor Yellow; return
                    }
                }
                'Unknown' {
                    Write-Warning "Could not validate credentials: $($check.Message)"
                    if ((Read-Host "  Continue anyway? (Y/N)") -match '^[Yy]') {
                        Write-Host "  [SKIP] Proceeding with unvalidated credentials." -ForegroundColor Yellow
                        $credentialsOk = $true
                    } else { Write-Host "`n  Cancelled." -ForegroundColor Yellow; return }
                }
                default {
                    # LockedOut, PasswordExpired, PasswordMustChange, AccountDisabled, AccountRestriction
                    Write-Host "  [FAIL] $($check.Status) - $($check.Message)" -ForegroundColor Red
                    if ((Read-Host "  Try again? (Y/N)") -notmatch '^[Yy]') {
                        Write-Host "`n  Cancelled." -ForegroundColor Yellow; return
                    }
                }
            }
        } while (-not $credentialsOk)
    }

    # --- Step 2: Domain name ---
    Write-Banner "Step 2 of 4 - Domain"
    if ($importedConfig) {
        $domainName = [string](Get-ConfigProp $importedConfig 'DomainName' '')
        if ($domainName) {
            Write-Host "  Domain (from config): $domainName"
        } else {
            $domainName = Read-Host "  Enter domain FQDN (e.g. corp.contoso.com)"
        }
    } else {
        $domainName = Read-Host "  Enter domain FQDN (e.g. corp.contoso.com)"
    }

    # --- Steps 3 & 4: Function selection, schedule, email ---
    $taskConfigs = @()

    if ($importedConfig) {
        Write-Banner "Steps 3 & 4 of 4 - Tasks (from config)"
        $smtpPwdCache = @{}
        $cfgTasks = @(Get-ConfigProp $importedConfig 'Tasks' @())
        foreach ($t in $cfgTasks) {
            $name = [string](Get-ConfigProp $t 'Name' '')
            if ($allFunctions -notcontains $name) {
                Write-Warning "Skipping unknown function in config: '$name'"
                continue
            }
            $freq = [string](Get-ConfigProp $t 'Frequency' 'Daily')
            if ($freq -ne 'Weekly') { $freq = 'Daily' }
            $day     = [string](Get-ConfigProp $t 'DayOfWeek' 'Monday')
            $timeStr = [string](Get-ConfigProp $t 'Time' '06:00')
            $parsedTime = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($timeStr, [string[]]@('HH:mm', 'H:mm'),
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::None, [ref]$parsedTime)) {
                Write-Warning "Invalid time '$timeStr' for $name in config - using 06:00."
                $timeStr = '06:00'
            }
            $trigger = if ($freq -eq 'Weekly') {
                New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $day -At $timeStr
            } else {
                New-ScheduledTaskTrigger -Daily -At $timeStr
            }

            $emailConfig = @{ Enabled = $false }
            $emailNode = Get-ConfigProp $t 'Email' $null
            if ($emailNode -and [bool](Get-ConfigProp $emailNode 'Enabled' $false)) {
                $smtpServer = [string](Get-ConfigProp $emailNode 'SmtpServer' '')
                $smtpUser   = [string](Get-ConfigProp $emailNode 'Username' '')
                $smtpPass   = ''
                if ($smtpUser) {
                    $cacheKey = "$smtpServer|$smtpUser"
                    if (-not $smtpPwdCache.ContainsKey($cacheKey)) {
                        $sec = Read-Host "  SMTP password for '$smtpUser' on $smtpServer" -AsSecureString
                        $smtpPwdCache[$cacheKey] = Get-PlainText -Secure $sec
                    }
                    $smtpPass = $smtpPwdCache[$cacheKey]
                }
                $emailConfig = @{
                    Enabled    = $true
                    SmtpServer = $smtpServer
                    Port       = [int](Get-ConfigProp $emailNode 'Port' 587)
                    UseSsl     = [bool](Get-ConfigProp $emailNode 'UseSsl' $true)
                    From       = [string](Get-ConfigProp $emailNode 'From' '')
                    To         = [string](Get-ConfigProp $emailNode 'To' '')
                    Username   = $smtpUser
                    Password   = $smtpPass
                }
            }

            $taskConfigs += [PSCustomObject]@{
                Name        = $name
                Frequency   = $freq
                DayOfWeek   = if ($freq -eq 'Weekly') { $day } else { '' }
                Time        = $timeStr
                Trigger     = $trigger
                EmailConfig = $emailConfig
            }
        }
        if ($taskConfigs.Count -eq 0) {
            Write-Warning "No valid tasks found in config file - nothing to register."
            return
        }
    } else {
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

        foreach ($fn in $selectedFunctions) {
            Write-Host "`n  ---- $fn ----" -ForegroundColor Cyan

            # Schedule
            $freq = Read-MenuChoice -Prompt "  Frequency" -Options @('Daily', 'Weekly')
            $day  = ''

            if ($freq -eq 'Daily') {
                $timeStr = Read-RunTime -Prompt "  Run time" -Default '06:00'
                $trigger = New-ScheduledTaskTrigger -Daily -At $timeStr
            } else {
                $day     = Read-MenuChoice -Prompt "  Day of week" -Options @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
                $timeStr = Read-RunTime -Prompt "  Run time" -Default '02:00'
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
                DayOfWeek   = $day
                Time        = $timeStr
                Trigger     = $trigger
                EmailConfig = $emailConfig
            }
        }
    }

    # --- Confirm ---
    Write-Banner "Review - Tasks to Register"
    $taskConfigs | ForEach-Object {
        $emailSummary = if ($_.EmailConfig.Enabled) { $_.EmailConfig.To } else { 'No email' }
        [PSCustomObject]@{ Name = $_.Name; Frequency = $_.Frequency; Day = $_.DayOfWeek; Time = $_.Time; Email = $emailSummary }
    } | Format-Table -AutoSize
    $confirm = Read-Host "`n  Proceed? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`n  Cancelled." -ForegroundColor Yellow
        return
    }

    # --- Create Task Scheduler folder ---
    if ($PSCmdlet.ShouldProcess('\ADOpsKit', 'Create Task Scheduler folder')) {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $root = $scheduler.GetFolder('\')
        try { $root.GetFolder('ADOpsKit') | Out-Null }
        catch { $root.CreateFolder('ADOpsKit') | Out-Null }
    }

    if (-not (Test-Path -LiteralPath $OutputBasePath)) {
        New-Item -ItemType Directory -Path $OutputBasePath -Force | Out-Null
    }

    # --- Lock down the Scripts folder (task scripts can embed SMTP credentials) ---
    $scriptDir = Join-Path $OutputBasePath 'Scripts'
    if (-not (Test-Path -LiteralPath $scriptDir)) {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    }
    if ($PSCmdlet.ShouldProcess($scriptDir, 'Restrict permissions to SYSTEM, Administrators and the service account')) {
        Protect-ScriptsFolder -Path $scriptDir -Account $account
    }

    # --- Register tasks ---
    Write-Banner "Registering Tasks"

    $sqBase   = ConvertTo-EscapedLiteral $OutputBasePath
    $dqBase   = ConvertTo-EscapedExpandable $OutputBasePath
    $sqDomain = ConvertTo-EscapedLiteral $domainName

    $scriptBlocks = @{
        'Get-AccountLockoutReport'         = "Get-AccountLockoutReport -TempPath '$sqBase\Get-AccountLockoutReport' -SharedPath '$sqBase\Get-AccountLockoutReport'"
        'Get-InsecureLDAPBinds'            = "Get-InsecureLDAPBinds -Hours 24 -OutputPath '$sqBase\Get-InsecureLDAPBinds'"
        'Get-ADForestHealth'               = "Get-ADForestHealth -OutputFolder '$sqBase\Get-ADForestHealth'"
        'Test-DCPortHealth'                = "`$date = Get-Date -Format 'yyyy-MM-dd'; Test-DCPortHealth -TimeoutSeconds 5 -ExportPath `"$dqBase\Test-DCPortHealth\`${date}_DCPortHealth.csv`""
        'Get-EntraConnectSyncStatus'       = "`$date = Get-Date -Format 'yyyy-MM-dd'; Get-EntraConnectSyncStatus -ExportPath `"$dqBase\Get-EntraConnectSyncStatus\`${date}_EntraConnectStatus.csv`""
        'Get-GPOInventory'                 = "`$date = Get-Date -Format 'yyyy-MM-dd'; Get-GPOInventory -DomainName '$sqDomain' -OutputPath `"$dqBase\Get-GPOInventory\`${date}_GPOInventory.html`""
        'Get-GPOInventoryWithSettings'     = "`$date = Get-Date -Format 'yyyy-MM-dd'; Get-GPOInventoryWithSettings -DomainName '$sqDomain' -OutputPath `"$dqBase\Get-GPOInventoryWithSettings\`${date}_GPOInventoryWithSettings.html`""
        'Get-ADArchitectureAssessment'     = "Get-ADArchitectureAssessment -DomainName '$sqDomain' -OutputFolder '$sqBase\Get-ADArchitectureAssessment'"
        'Get-ADReplicationTopologyDiagram' = "`$date = Get-Date -Format 'yyyy-MM-dd'; Get-ADReplicationTopologyDiagram -OutputPath `"$dqBase\Get-ADReplicationTopologyDiagram\`${date}_ADReplicationTopology.html`""
    }

    foreach ($cfg in $taskConfigs) {
        New-ADOpsKitTask `
            -TaskName      $cfg.Name `
            -Description   "ADOpsKit scheduled task - $($cfg.Name)" `
            -ScriptBlock   $scriptBlocks[$cfg.Name] `
            -Trigger       $cfg.Trigger `
            -Account       $account `
            -Password      $plainPwd `
            -IsGmsa:$isGmsa `
            -BasePath      $OutputBasePath `
            -RetentionDays $RetentionDays `
            -EmailConfig   $cfg.EmailConfig
    }

    # --- Save replayable config (never contains passwords) ---
    $configFile = Join-Path $OutputBasePath 'ADOpsKitTasks.config.json'
    if (-not $WhatIfPreference) {
        try {
            $configExport = [ordered]@{
                SavedOn        = (Get-Date).ToString('s')
                Account        = $account
                AccountType    = if ($isGmsa) { 'gMSA' } else { 'Regular' }
                DomainName     = $domainName
                OutputBasePath = $OutputBasePath
                RetentionDays  = $RetentionDays
                Tasks          = @(
                    foreach ($cfg in $taskConfigs) {
                        $emailOut = [ordered]@{ Enabled = $false }
                        if ($cfg.EmailConfig.Enabled) {
                            $emailOut = [ordered]@{
                                Enabled    = $true
                                SmtpServer = $cfg.EmailConfig.SmtpServer
                                Port       = $cfg.EmailConfig.Port
                                UseSsl     = [bool]$cfg.EmailConfig.UseSsl
                                From       = $cfg.EmailConfig.From
                                To         = $cfg.EmailConfig.To
                                Username   = $cfg.EmailConfig.Username
                            }
                        }
                        [ordered]@{
                            Name      = $cfg.Name
                            Frequency = $cfg.Frequency
                            DayOfWeek = $cfg.DayOfWeek
                            Time      = $cfg.Time
                            Email     = $emailOut
                        }
                    }
                )
            }
            $configExport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configFile -Encoding UTF8
        } catch {
            Write-Warning "Could not save config file '$configFile': $($_.Exception.Message)"
        }
    }

    # --- Done ---
    Write-Banner "Done"
    Write-Host "`n  Tasks registered under \ADOpsKit\ in Task Scheduler."
    Write-Host "  Reports   : $OutputBasePath\<FunctionName>\"
    Write-Host "  Logs      : $OutputBasePath\Logs\ (rotated at 10 MB)"
    if ($RetentionDays -gt 0) {
        Write-Host "  Retention : reports older than $RetentionDays days are removed after each run"
    }
    Write-Host "  Exit codes: 0 = success, 1 = function failed, 2 = email problem (see Last Run Result)"
    $emailEnabled = $taskConfigs | Where-Object { $_.EmailConfig.Enabled }
    if ($emailEnabled) {
        Write-Host "  Email     : $(@($emailEnabled).Count) task(s) configured to send reports by email." -ForegroundColor Cyan
    }
    if (Test-Path -LiteralPath $configFile) {
        Write-Host "  Config    : $configFile"
        Write-Host ""
        Write-Host "  Re-run this setup later (passwords prompted, everything else saved):"
        Write-Host "    Register-ADOpsKitScheduledTasks -ConfigPath '$configFile'" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Verify with:"
    Write-Host "    Get-ScheduledTask -TaskPath '\ADOpsKit\' | Select-Object TaskName, State" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Test a task immediately:"
    Write-Host "    Start-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName 'Test-DCPortHealth'" -ForegroundColor DarkGray
}
