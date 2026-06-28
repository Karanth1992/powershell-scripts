function Install-ADSKRoles {
<#
.SYNOPSIS
    Interactively installs Windows Server roles and features.

.DESCRIPTION
    Presents a menu of commonly needed Windows Server roles and features.
    Multiple selections are supported. Selected roles are installed using
    Install-WindowsFeature with management tools included.

.PARAMETER Roles
    Optional array of role names to install non-interactively.
    If omitted, an interactive menu is shown.

.EXAMPLE
    Install-ADSKRoles

.EXAMPLE
    Install-ADSKRoles -Roles @('AD-Domain-Services','DNS','DHCP')

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator
#>
    [CmdletBinding()]
    param(
        [string[]]$Roles
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    $roleMap = [ordered]@{
        'AD Domain Services (ADDS)'       = 'AD-Domain-Services'
        'DNS Server'                      = 'DNS'
        'DHCP Server'                     = 'DHCP'
        'File Services'                   = 'File-Services'
        'Print Services'                  = 'Print-Services'
        'Web Server (IIS)'                = 'Web-Server'
        'Group Policy Management (GPMC)'  = 'GPMC'
        'RSAT - AD Tools'                 = 'RSAT-AD-Tools'
        'RSAT - DNS Tools'                = 'RSAT-DNS-Server'
        'RSAT - DHCP Tools'               = 'RSAT-DHCP'
    }

    if (-not $Roles) {
        $labels   = @($roleMap.Keys)
        $selected = Read-ADSKMultiMenuChoice -Prompt "Select roles to install:" -Options $labels -AllLabel "All recommended (ADDS + DNS + GPMC)"
        $Roles    = $selected | ForEach-Object { $roleMap[$_] }
    }

    Write-ADSKBanner "Installing Roles"
    Write-ADSKInfo "Roles: $($Roles -join ', ')"

    $result = Install-WindowsFeature -Name $Roles -IncludeManagementTools -ErrorAction Stop

    if ($result.Success) {
        Write-ADSKOk "All selected roles installed successfully."
        if ($result.RestartNeeded -eq 'Yes') {
            Write-ADSKWarn "A restart is required to complete role installation."
        }
    } else {
        Write-ADSKFail "One or more roles failed to install."
        $result | Format-List
    }

    return $result
}
