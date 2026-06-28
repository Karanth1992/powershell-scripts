function Install-ADSKApplications {
<#
.SYNOPSIS
    Runs a set of PowerShell or batch installer scripts from a folder in sequence.

.DESCRIPTION
    Scans the specified folder for .ps1 and .bat files and executes them in
    alphabetical order. Prefix filenames with numbers to control order
    (e.g. 01-chrome.ps1, 02-agent.ps1).

    Each script is run with a timeout. Results are logged to a summary file
    in the same folder. Scripts that fail do not stop the sequence  -  all
    scripts are attempted and failures are reported at the end.

.PARAMETER ScriptFolder
    Path to the folder containing installer scripts (.ps1 and/or .bat files).

.PARAMETER LogPath
    Path to the log file. Defaults to ScriptFolder\ADSKApplications.log

.PARAMETER TimeoutSeconds
    Timeout per script in seconds. Defaults to 300 (5 minutes).

.EXAMPLE
    Install-ADSKApplications -ScriptFolder 'C:\Installers'

.EXAMPLE
    Install-ADSKApplications -ScriptFolder 'D:\Setup\Apps' -TimeoutSeconds 600

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Naming convention: prefix scripts with numbers to control order.
    Example: 01-dotnet.ps1, 02-chrome.ps1, 03-agent.bat
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptFolder,
        [string]$LogPath,
        [int]$TimeoutSeconds = 300
    )

    if (-not (Test-Path $ScriptFolder)) { throw "Folder not found: $ScriptFolder" }
    if (-not $LogPath) { $LogPath = Join-Path $ScriptFolder 'ADSKApplications.log' }

    $scripts = Get-ChildItem -Path $ScriptFolder -Include '*.ps1','*.bat' -File |
               Sort-Object Name

    if ($scripts.Count -eq 0) {
        Write-ADSKWarn "No .ps1 or .bat files found in $ScriptFolder"
        return
    }

    Write-ADSKBanner "Application Installation"
    Write-ADSKInfo "$($scripts.Count) script(s) found. Logging to $LogPath"

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $start   = Get-Date

    foreach ($script in $scripts) {
        Write-Host "`n  Running: $($script.Name)" -ForegroundColor White
        $scriptStart = Get-Date

        try {
            if ($script.Extension -eq '.ps1') {
                $proc = Start-Process -FilePath 'powershell.exe' `
                    -ArgumentList "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($script.FullName)`"" `
                    -PassThru -NoNewWindow -RedirectStandardOutput "$LogPath.tmp"
            } else {
                $proc = Start-Process -FilePath 'cmd.exe' `
                    -ArgumentList "/c `"$($script.FullName)`"" `
                    -PassThru -NoNewWindow -RedirectStandardOutput "$LogPath.tmp"
            }
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) {
                $proc.Kill()
                throw "Script timed out after ${TimeoutSeconds}s"
            }

            $elapsed = [math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 1)
            $status  = if ($proc.ExitCode -eq 0) { 'Passed' } else { "Failed (exit $($proc.ExitCode))" }

            if ($proc.ExitCode -eq 0) { Write-ADSKOk "$($script.Name)  -  $status (${elapsed}s)" }
            else                       { Write-ADSKFail "$($script.Name)  -  $status (${elapsed}s)" }
        } catch {
            $elapsed = [math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 1)
            $status  = "Error: $_"
            Write-ADSKFail "$($script.Name)  -  $status"
        }

        $results.Add([PSCustomObject]@{
            Script     = $script.Name
            Status     = $status
            ElapsedSec = $elapsed
            RunAt      = $scriptStart
        })

        if (Test-Path "$LogPath.tmp") {
            Add-Content -Path $LogPath -Value "=== $($script.Name) ==="
            Get-Content "$LogPath.tmp" | Add-Content -Path $LogPath
            Remove-Item "$LogPath.tmp" -Force
        }
    }

    $totalElapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
    $passed  = ($results | Where-Object { $_.Status -eq 'Passed' }).Count
    $failed  = ($results | Where-Object { $_.Status -ne 'Passed' }).Count

    Write-ADSKBanner "Application Install Summary"
    $results | Format-Table Script, Status, ElapsedSec -AutoSize
    Write-Host "  Total: $($scripts.Count) scripts | Passed: $passed | Failed: $failed | Time: ${totalElapsed}s" -ForegroundColor White

    $results | Export-Csv -NoTypeInformation -Path ($LogPath -replace '\.log$', '.csv')
    Write-ADSKOk "Full log: $LogPath"

    if ($failed -gt 0) {
        Write-ADSKWarn "$failed script(s) failed. Review the log before proceeding."
    }
}
