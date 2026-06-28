function Rename-ADSKComputer {
<#
.SYNOPSIS
    Renames the local computer.

.DESCRIPTION
    Renames the local computer to the specified name.
    Optionally restarts immediately after renaming.
    The rename takes effect after a restart.

.PARAMETER NewName
    The new computer name to assign.

.PARAMETER Restart
    If specified, restarts the computer immediately after renaming.

.EXAMPLE
    Rename-ADSKComputer -NewName 'DC-1'

.EXAMPLE
    Rename-ADSKComputer -NewName 'DC-1' -Restart

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$NewName,
        [switch]$Restart
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    $current = $env:COMPUTERNAME
    Write-ADSKInfo "Current name : $current"
    Write-ADSKInfo "New name     : $NewName"

    Rename-Computer -NewName $NewName -Force
    Write-ADSKOk "Computer renamed to $NewName. Restart required to take effect."

    if ($Restart) {
        Write-ADSKWarn "Restarting in 10 seconds..."
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}
