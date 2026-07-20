function Register-ADDCDiagHealthMonitor {
<#
.SYNOPSIS
    Registers a Windows Scheduled Task that runs Test-ADDCDiagHealth on a
    short repeating interval, turning it into a near-real-time domain
    controller monitoring agent.

.DESCRIPTION
    Creates a task under \ADOpsKit\ in Task Scheduler with a repeating
    trigger (default every 5 minutes, indefinitely) that calls
    Test-ADDCDiagHealth with the parameters supplied here.

    This function MAKES CHANGES: it writes a wrapper script to
    -ScriptsFolder, registers/replaces the scheduled task, and restricts
    the scripts folder ACL. Supports -WhatIf / -Confirm. WinRM is not
    required.

    Run-as account:
        - Defaults to the built-in SYSTEM account (no password to store,
          no rotation to manage) - sufficient for the default dcdiag test
          set against DCs in the same domain as this computer.
        - Pass -RunAsCredential for a delegated account instead, e.g. for
          cross-domain/cross-forest monitoring where SYSTEM's computer
          account does not have visibility.

    Security notes:
        - If -SmtpCredential is supplied, its password is stored in the
          generated wrapper script as a machine-scoped DPAPI-encrypted
          blob (same pattern used by Register-ADOpsKitScheduledTasks).
          The plaintext is never written to disk, and the blob only
          decrypts on this computer - if the script is copied elsewhere,
          re-run this function there. The Scripts folder ACL is
          additionally restricted to SYSTEM, Administrators, and the
          run-as account.
        - Most internal SMTP relays for alerting do not require
          authentication (IP allow-listed); prefer that where possible.

    DO NOT REGISTER THIS ON A DOMAIN CONTROLLER. dcdiag itself is cheap
    per run, but a recurring task means that computer carries the
    polling workload (process spawns, event-log reads, RPC/LDAP calls to
    every other DC) continuously, on top of its normal DC duties. Run it
    from a non-DC host instead - a member server, admin jump box, or a
    monitoring VM - which only ever queries the DCs remotely. This
    function checks the local computer's domain role at run time and
    writes a warning (but does not block) if it detects it is running on
    a DC.

.PARAMETER TaskName
    Name of the scheduled task. Default: ADDCDiagHealthMonitor

.PARAMETER IntervalMinutes
    How often to run the check, in minutes. Default: 5

.PARAMETER ScriptsFolder
    Folder the wrapper task script is written to. Default:
    C:\ADOpsKit\Scripts

.PARAMETER RunAsCredential
    Optional credential to run the task as instead of SYSTEM.

.PARAMETER DomainController
    Passed through to Test-ADDCDiagHealth. Defaults to every DC in the
    current domain.

.PARAMETER Tests
    Passed through to Test-ADDCDiagHealth. Optional lighter test list
    (e.g. Connectivity,Advertising,NetLogons,Replications,KccEvent,Services)
    instead of dcdiag's full default set, to reduce per-run load. Leave
    unset to run the full default set.

.PARAMETER PerDCTimeoutSeconds
    Passed through to Test-ADDCDiagHealth. Default 60.

.PARAMETER RepeatAlertAfterHours
    Passed through to Test-ADDCDiagHealth. Default 4.

.PARAMETER StateFilePath
    Passed through to Test-ADDCDiagHealth. Default:
    C:\ADOpsKit\State\Test-ADDCDiagHealth.state.json

.PARAMETER AlertLogPath
    Passed through to Test-ADDCDiagHealth. Default:
    C:\ADOpsKit\Reports\Test-ADDCDiagHealth\AlertLog.csv

.PARAMETER SmtpServer
    SMTP relay for alert email. Required.

.PARAMETER SmtpPort
    SMTP port. Default 25.

.PARAMETER UseSsl
    Use SSL/TLS to the SMTP relay.

.PARAMETER SmtpCredential
    Optional SMTP authentication credential. See Security notes above.

.PARAMETER From
    Alert email From address. Required.

.PARAMETER To
    Alert email recipient address(es). Required.

.EXAMPLE
    Register-ADDCDiagHealthMonitor -SmtpServer smtp.contoso.com -From adalerts@contoso.com -To 'you@contoso.com'
    Registers the monitor to run every 5 minutes as SYSTEM.

.EXAMPLE
    Register-ADDCDiagHealthMonitor -IntervalMinutes 2 -SmtpServer smtp.contoso.com -From adalerts@contoso.com -To 'you@contoso.com','oncall@contoso.com' -WhatIf
    Shows what would be registered for a 2-minute polling interval
    without making any changes.

.EXAMPLE
    Register-ADDCDiagHealthMonitor -Tests Connectivity,Advertising,NetLogons,Replications,KccEvent,Services -SmtpServer smtp.contoso.com -From adalerts@contoso.com -To 'you@contoso.com'
    Registers the monitor with a lighter test list to further reduce
    per-run load on the DCs being checked.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: Run as Administrator, ADOpsKit module installed.
    Makes changes to the local Task Scheduler and filesystem. Does not
    touch Active Directory.
#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$TaskName = 'ADDCDiagHealthMonitor',

        [ValidateRange(1, 60)]
        [int]$IntervalMinutes = 5,

        [ValidateNotNullOrEmpty()]
        [string]$ScriptsFolder = 'C:\ADOpsKit\Scripts',

        [pscredential]$RunAsCredential,

        [string[]]$DomainController,

        [string[]]$Tests,

        [ValidateRange(5, 600)]
        [int]$PerDCTimeoutSeconds = 60,

        [ValidateRange(1, 24)]
        [int]$RepeatAlertAfterHours = 4,

        [string]$StateFilePath = 'C:\ADOpsKit\State\Test-ADDCDiagHealth.state.json',

        [string]$AlertLogPath = 'C:\ADOpsKit\Reports\Test-ADDCDiagHealth\AlertLog.csv',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SmtpServer,

        [ValidateRange(1, 65535)]
        [int]$SmtpPort = 25,

        [switch]$UseSsl,

        [pscredential]$SmtpCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$From,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$To
    )

    #Requires -RunAsAdministrator

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function ConvertTo-ADOKPSLiteral {
        param([string]$Value)
        "'" + ($Value -replace "'", "''") + "'"
    }

    # ============ WARN IF RUNNING ON A DOMAIN CONTROLLER ============
    # DomainRole: 4 = Backup DC, 5 = Primary DC. WMI, not WinRM.

    try {
        $domainRole = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).DomainRole
        if ($domainRole -in 4, 5) {
            Write-Warning "This computer appears to be a domain controller (DomainRole=$domainRole). Registering this recurring task here means this DC will carry the polling workload continuously, on top of its DC duties. Prefer running Register-ADDCDiagHealthMonitor from a non-DC host (member server, jump box, or monitoring VM) that queries the DCs remotely instead."
        }
    }
    catch {
        Write-Verbose "Could not determine local domain role via WMI: $($_.Exception.Message)"
    }

    # ============ RESOLVE MODULE MANIFEST PATH ============
    # $PSScriptRoot here is ADOpsKit\Public (this file's own folder),
    # regardless of where the caller invoked the function from.

    $moduleRoot   = Split-Path -Path $PSScriptRoot -Parent
    $manifestPath = Join-Path $moduleRoot 'ADOpsKit.psd1'

    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "Could not resolve ADOpsKit.psd1 next to this function (looked in '$moduleRoot'). Reinstall ADOpsKit and retry."
    }

    # ============ BUILD WRAPPER TASK SCRIPT ============

    if (-not (Test-Path -LiteralPath $ScriptsFolder)) {
        if ($PSCmdlet.ShouldProcess($ScriptsFolder, 'Create scripts folder')) {
            New-Item -ItemType Directory -Path $ScriptsFolder -Force | Out-Null
        }
    }

    $scriptPath = Join-Path $ScriptsFolder "$TaskName.ps1"

    $paramLines = [System.Collections.Generic.List[string]]::new()
    if ($DomainController) {
        $dcList = ($DomainController | ForEach-Object { ConvertTo-ADOKPSLiteral $_ }) -join ','
        $paramLines.Add("    -DomainController @($dcList)")
    }
    if ($Tests) {
        $testList = ($Tests | ForEach-Object { ConvertTo-ADOKPSLiteral $_ }) -join ','
        $paramLines.Add("    -Tests @($testList)")
    }
    $paramLines.Add("    -PerDCTimeoutSeconds $PerDCTimeoutSeconds")
    $paramLines.Add("    -RepeatAlertAfterHours $RepeatAlertAfterHours")
    $paramLines.Add("    -StateFilePath $(ConvertTo-ADOKPSLiteral $StateFilePath)")
    $paramLines.Add("    -AlertLogPath $(ConvertTo-ADOKPSLiteral $AlertLogPath)")
    $paramLines.Add("    -SmtpServer $(ConvertTo-ADOKPSLiteral $SmtpServer)")
    $paramLines.Add("    -SmtpPort $SmtpPort")
    if ($UseSsl) { $paramLines.Add("    -UseSsl") }
    $paramLines.Add("    -From $(ConvertTo-ADOKPSLiteral $From)")
    $toList = ($To | ForEach-Object { ConvertTo-ADOKPSLiteral $_ }) -join ','
    $paramLines.Add("    -To @($toList)")

    $credentialBlock = ''
    if ($SmtpCredential) {
        $smtpUserLiteral = ConvertTo-ADOKPSLiteral $SmtpCredential.UserName
        # Machine-scoped DPAPI: only an encrypted blob is written into the
        # generated script. It decrypts only on this computer, so the
        # plaintext password never reaches disk.
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SmtpCredential.Password)
        try {
            $plainSmtpPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $encSmtpPwd = Protect-ADOKMachineSecret -PlainText $plainSmtpPwd
        $credentialBlock = @"
Add-Type -AssemblyName System.Security
`$smtpPwdBytes  = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('$encSmtpPwd'), `$null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
`$smtpSecurePwd = ConvertTo-SecureString ([System.Text.Encoding]::UTF8.GetString(`$smtpPwdBytes)) -AsPlainText -Force
`$smtpPwdBytes  = `$null
`$smtpCred      = [pscredential]::new($smtpUserLiteral, `$smtpSecurePwd)
"@
        $paramLines.Add("    -SmtpCredential `$smtpCred")
    }

    $scriptContent = @"
# Auto-generated by Register-ADDCDiagHealthMonitor on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').
# Do not edit by hand - re-run Register-ADDCDiagHealthMonitor to change settings.
`$ErrorActionPreference = 'Stop'
Import-Module -Name $(ConvertTo-ADOKPSLiteral $manifestPath) -Force
$credentialBlock
Test-ADDCDiagHealth ``
$($paramLines -join " ``
")
"@

    if ($PSCmdlet.ShouldProcess($scriptPath, 'Write monitor task script')) {
        Set-Content -LiteralPath $scriptPath -Value $scriptContent -Encoding UTF8
    }

    # Restrict ACL: SYSTEM, Administrators, and the run-as account only -
    # defense in depth; the script contains at most a machine-scoped
    # DPAPI-encrypted SMTP password (no plaintext).
    if ($PSCmdlet.ShouldProcess($ScriptsFolder, 'Restrict folder ACL')) {
        try {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $identities = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
            if ($RunAsCredential) { $identities += $RunAsCredential.UserName }
            foreach ($identity in $identities) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
                )
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $ScriptsFolder -AclObject $acl
        }
        catch {
            if ($SmtpCredential) {
                # The NTFS ACL is the only thing standing between a local, unprivileged
                # user and the DPAPI-encrypted SMTP password (LocalMachine-scoped DPAPI
                # blobs can be decrypted by any local principal, not just admins) - so a
                # failure to lock down this folder must not be treated as a soft warning
                # when a secret was actually written into it.
                throw "Could not restrict ACL on '$ScriptsFolder': $($_.Exception.Message). " +
                      "This folder now contains a DPAPI-encrypted SMTP password, and the ACL is its only " +
                      "access control - refusing to continue. Restrict '$ScriptsFolder' manually (SYSTEM, " +
                      "Administrators, and the run-as account only) and re-run, or re-run without -SmtpCredential."
            }
            else {
                Write-Warning "Could not restrict ACL on '$ScriptsFolder': $($_.Exception.Message). Restrict it manually."
            }
        }
    }

    # ============ REGISTER SCHEDULED TASK ============

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes ([Math]::Max(5, $IntervalMinutes * 2))) `
        -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    if ($PSCmdlet.ShouldProcess("\ADOpsKit\$TaskName", "Register scheduled task (every $IntervalMinutes minute(s))")) {
        if ($RunAsCredential) {
            $runAsBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($RunAsCredential.Password)
            try {
                $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($runAsBstr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($runAsBstr)
            }
            try {
                Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Action $action -Trigger $trigger `
                    -Settings $settings -User $RunAsCredential.UserName -Password $plainPwd -RunLevel Highest -Force | Out-Null
            }
            finally {
                $plainPwd = $null
            }
        }
        else {
            Register-ScheduledTask -TaskPath '\ADOpsKit\' -TaskName $TaskName -Action $action -Trigger $trigger `
                -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        }
        Write-Host "[OK] Registered scheduled task \ADOpsKit\$TaskName - runs every $IntervalMinutes minute(s)." -ForegroundColor Green
    }

    [PSCustomObject]@{
        TaskName        = $TaskName
        TaskPath        = "\ADOpsKit\$TaskName"
        IntervalMinutes = $IntervalMinutes
        RunAs           = if ($RunAsCredential) { $RunAsCredential.UserName } else { 'NT AUTHORITY\SYSTEM' }
        ScriptPath      = $scriptPath
        StateFilePath   = $StateFilePath
        AlertLogPath    = $AlertLogPath
    }
}
