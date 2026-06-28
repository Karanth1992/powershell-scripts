function Add-ADSKDomainController {
<#
.SYNOPSIS
    Promotes the local server as an additional domain controller in an existing domain.

.DESCRIPTION
    Joins the server as a replica domain controller to an existing Active Directory domain.
    Installs the AD-Domain-Services role if not already present.
    A restart is required and is triggered automatically.

.PARAMETER DomainName
    FQDN of the existing domain. Example: corp.contoso.com

.PARAMETER Credential
    Domain admin credentials for the promotion.

.PARAMETER SafeModePassword
    DSRM password as a SecureString.

.PARAMETER SiteName
    AD site to place this DC in. Defaults to Default-First-Site-Name.

.PARAMETER DatabasePath
    Path for the AD database. Defaults to C:\Windows\NTDS

.PARAMETER LogPath
    Path for the AD log files. Defaults to C:\Windows\NTDS

.PARAMETER SysvolPath
    Path for SYSVOL. Defaults to C:\Windows\SYSVOL

.EXAMPLE
    $cred = Get-Credential
    $pwd  = Read-Host "DSRM Password" -AsSecureString
    Add-ADSKDomainController -DomainName 'corp.contoso.com' -Credential $cred -SafeModePassword $pwd

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator. Server will restart after promotion.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [Parameter(Mandatory)][SecureString]$SafeModePassword,
        [string]$SiteName     = 'Default-First-Site-Name',
        [string]$DatabasePath = 'C:\Windows\NTDS',
        [string]$LogPath      = 'C:\Windows\NTDS',
        [string]$SysvolPath   = 'C:\Windows\SYSVOL'
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    Write-ADSKBanner "Additional DC Promotion"
    Write-ADSKInfo "Domain : $DomainName"
    Write-ADSKInfo "Site   : $SiteName"

    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-ADSKInfo "Installing AD-Domain-Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Write-ADSKOk "Role installed."
    }

    Write-ADSKInfo "Starting DC promotion. Server will restart automatically..."

    Install-ADDSDomainController `
        -DomainName            $DomainName `
        -Credential            $Credential `
        -SafeModeAdministratorPassword $SafeModePassword `
        -SiteName              $SiteName `
        -DatabasePath          $DatabasePath `
        -LogPath               $LogPath `
        -SysvolPath            $SysvolPath `
        -InstallDns            `
        -NoRebootOnCompletion:$false `
        -Force
}
