function New-ADSKChildDomain {
<#
.SYNOPSIS
    Creates a new child domain under an existing parent domain.

.DESCRIPTION
    Promotes the local server to the first DC of a new child domain.
    Installs the AD-Domain-Services role if not already present.
    A restart is required and is triggered automatically.

.PARAMETER ChildDomainName
    The single-label name for the child domain. Example: 'uk' creates uk.corp.contoso.com

.PARAMETER ParentDomainName
    FQDN of the parent domain. Example: corp.contoso.com

.PARAMETER Credential
    Enterprise Admin credentials from the parent domain.

.PARAMETER SafeModePassword
    DSRM password as a SecureString.

.PARAMETER SiteName
    AD site to place this DC in. Defaults to Default-First-Site-Name.

.EXAMPLE
    $cred = Get-Credential
    $pwd  = Read-Host "DSRM Password" -AsSecureString
    New-ADSKChildDomain -ChildDomainName 'uk' -ParentDomainName 'corp.contoso.com' -Credential $cred -SafeModePassword $pwd

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator, Enterprise Admin credentials.
    Server will restart after promotion.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ChildDomainName,
        [Parameter(Mandatory)][string]$ParentDomainName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [Parameter(Mandatory)][SecureString]$SafeModePassword,
        [string]$SiteName = 'Default-First-Site-Name'
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    $fullDomain = "$ChildDomainName.$ParentDomainName"
    Write-ADSKBanner "New Child Domain Promotion"
    Write-ADSKInfo "Child Domain : $fullDomain"
    Write-ADSKInfo "Parent       : $ParentDomainName"
    Write-ADSKInfo "Site         : $SiteName"

    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-ADSKInfo "Installing AD-Domain-Services role..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Write-ADSKOk "Role installed."
    }

    Write-ADSKInfo "Starting child domain promotion. Server will restart automatically..."

    Install-ADDSDomain `
        -NewDomainName         $ChildDomainName `
        -ParentDomainName      $ParentDomainName `
        -NewDomainType         ChildDomain `
        -Credential            $Credential `
        -SafeModeAdministratorPassword $SafeModePassword `
        -SiteName              $SiteName `
        -InstallDns            `
        -NoRebootOnCompletion:$false `
        -Force
}
