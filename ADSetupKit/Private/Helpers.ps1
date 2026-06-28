function Write-ADSKBanner {
    param([string]$Text)
    $line = '-' * ($Text.Length + 4)
    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor DarkCyan
}

function Write-ADSKOk   { param([string]$Text) Write-Host "  [OK]   $Text" -ForegroundColor Green }
function Write-ADSKWarn { param([string]$Text) Write-Host "  [WARN] $Text" -ForegroundColor Yellow }
function Write-ADSKInfo { param([string]$Text) Write-Host "  [INFO] $Text" -ForegroundColor Cyan }
function Write-ADSKFail { param([string]$Text) Write-Host "  [FAIL] $Text" -ForegroundColor Red }

function Test-ADSKAdministrator {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-ADSKMenuChoice {
    param([string]$Prompt, [string[]]$Options)
    Write-Host "`n$Prompt" -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  [$($i+1)] $($Options[$i])"
    }
    do {
        $raw = Read-Host "  Choice (1-$($Options.Count))"
        $n   = 0
        $ok  = [int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Options.Count
        if (-not $ok) { Write-Host "  Invalid. Enter a number between 1 and $($Options.Count)." -ForegroundColor Yellow }
    } while (-not $ok)
    return $Options[$n - 1]
}

function Read-ADSKMultiMenuChoice {
    param([string]$Prompt, [string[]]$Options, [string]$AllLabel = 'All of the above')
    Write-Host "`n$Prompt" -ForegroundColor White
    Write-Host "  [0] $AllLabel" -ForegroundColor Green
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  [$($i+1)] $($Options[$i])"
    }
    Write-Host "  Enter numbers separated by commas, or 0 for all."
    do {
        $raw   = (Read-Host "  Choice").Trim()
        $parts = $raw -split ',' | ForEach-Object { $_.Trim() }
        if ($parts -contains '0') { return $Options }
        $selected = @()
        $valid    = $true
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

function Register-ADSKStartupTask {
    param([string]$TaskName, [string]$ScriptPath)
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' `
                  -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger  = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -RunLevel Highest -Force | Out-Null
}
