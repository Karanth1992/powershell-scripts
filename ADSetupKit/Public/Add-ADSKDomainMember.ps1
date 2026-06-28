function Add-ADSKDomainMember {
<#
.SYNOPSIS
    Joins the local server to an existing Active Directory domain.

.DESCRIPTION
    Joins the local server to the specified domain as a member server.
    Optionally moves the computer account to a specific OU.
    A restart is required to complete the join.

.PARAMETER DomainName
    FQDN of the domain to join. Example: corp.contoso.com

.PARAMETER Credential
    Domain admin credentials.

.PARAMETER OUPath
    Optional OU distinguished name to place the computer account in.
    Example: 'OU=Servers,DC=corp,DC=contoso,DC=com'

.PARAMETER Restart
    If specified, restarts the server immediately after joining.

.EXAMPLE
    $cred = Get-Credential
    Add-ADSKDomainMember -DomainName 'corp.contoso.com' -Credential $cred -Restart

.NOTES
    Author:  K Shankar R Karanth
    Website: https://karanth.ovh
    Requires: Run as Administrator.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [string]$OUPath,
        [switch]$Restart
    )

    if (-not (Test-ADSKAdministrator)) { throw "Run as Administrator." }

    Write-ADSKBanner "Domain Join"
    Write-ADSKInfo "Domain : $DomainName"
    if ($OUPath) { Write-ADSKInfo "OU     : $OUPath" }

    $params = @{
        DomainName = $DomainName
        Credential = $Credential
        Force      = $true
    }
    if ($OUPath) { $params['OUPath'] = $OUPath }
    if ($Restart) { $params['Restart'] = $true }

    Add-Computer @params
    Write-ADSKOk "Successfully joined $DomainName. Restart to complete."
}
