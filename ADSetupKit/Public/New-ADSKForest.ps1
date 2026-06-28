function New-ADSKForest {
<#
.SYNOPSIS
    Promotes the local server to the first domain controller in a new Active Directory forest.

.DESCRIPTION
    Installs a new Active Directory forest on the local server.
    Installs the AD-Domain-Services role if not already present,
    then runs Install-ADDSForest with safe defaults.
    A restart is required and will be triggered automatically.

.PARAMETER DomainName
    FQDN of the new forest root domain. Example: corp.contoso.com

.PARAMETER DomainNetBiosName
    NetBIOS name for the domain. Defaults to the first label of DomainName (e.g. CORP).

.PARAMETER SafeModePassword
    DSRM password as a SecureString.

.PARAMETER DatabasePath
    Path for the AD database. Defaults to C:\Windows\NTDS

.PARAMETER LogPath
    Path for the AD log files. Defaults to C:\Windows\NTDS

.PARAMETER SysvolPath
    Path for SYSVOL. Defaults to C:\Windows\SYSVOL

.PARAMETER ForestMode
    Forest functional level. Defaults to WinThreshold (Windows Server 2016+).

.PARAMETER DomainMode
    Domain functional level. Defaults to WinThreshold.

.EXAMPLE
    $pwd = Read-Host "DSRM Password" -AsSecureString
    New-ADSKForest -DomainName 'corp.contoso.com' -SafeModePassword $pwd

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator. Server will restart after promotion.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [string]$DomainNetBiosName,
        [Parameter(Mandatory)][SecureString]$SafeModePassword,
        [string]$DatabasePath  = 'C:\Windows\NTDS',
        [string]$LogPath       = 'C:\Windows\NTDS',
        [string]$SysvolPath    = 'C:\Windows\SYSVOL',
        [string]$ForestMode    = 'WinThreshold',
        [string]$DomainMode    = 'WinThreshold'
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }
    if (-not $DomainNetBiosName) { $DomainNetBiosName = ($DomainName -split '\.')[0].ToUpper() }

    Write-ADSKBanner "New Forest Promotion"
    Write-ADSKInfo "Forest FQDN  : $DomainName"
    Write-ADSKInfo "NetBIOS      : $DomainNetBiosName"
    Write-ADSKInfo "Forest Mode  : $ForestMode"
    Write-ADSKInfo "Domain Mode  : $DomainMode"

    # Ensure ADDS role is installed
    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-ADSKInfo "Installing AD-Domain-Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Write-ADSKOk "Role installed."
    }

    Write-ADSKInfo "Starting forest promotion. Server will restart automatically..."

    Install-ADDSForest `
        -DomainName            $DomainName `
        -DomainNetbiosName     $DomainNetBiosName `
        -SafeModeAdministratorPassword $SafeModePassword `
        -DatabasePath          $DatabasePath `
        -LogPath               $LogPath `
        -SysvolPath            $SysvolPath `
        -ForestMode            $ForestMode `
        -DomainMode            $DomainMode `
        -InstallDns            `
        -NoRebootOnCompletion:$false `
        -Force
}
