<#
.SYNOPSIS
    Bulk-creates Active Directory user accounts from a CSV input file.

.DESCRIPTION
    Reads user records from a CSV file and creates one AD account per
    row using New-ADUser. Each row is validated and processed
    independently, so one bad or duplicate row does not stop the rest
    of the batch.

    Accounts are created with ChangePasswordAtLogon enabled. If a row
    does not supply a Password column, a random 16-character password
    that satisfies typical AD complexity policy is generated for that
    account and reported back in the results so it can be communicated
    to the user out of band.

    This script makes changes to Active Directory (creates user
    objects) and supports -WhatIf / -Confirm via SupportsShouldProcess.

    Expected CSV columns: FirstName, LastName, SamAccountName, OUPath
    (all required), plus optional Password, EmailAddress, Department,
    Title.

    Data source: ActiveDirectory module (New-ADUser, Get-ADUser).
    WinRM: not used - all work is done locally against the
    ActiveDirectory module's own LDAP connection.

    Output: none. Results are written to the console as a table and
    summary only; no CSV/HTML report or log file is produced.

.PARAMETER CsvPath
    Path to the input CSV file containing user records to create.

.PARAMETER UpnSuffix
    UPN suffix appended to SamAccountName when a row does not supply
    its own EmailAddress. Defaults to "corp.example.com" - override
    this for the target domain.

.EXAMPLE
    .\New-BulkADUser.ps1 -CsvPath "C:\Temp\NewUsers.csv" -WhatIf
    Previews what would be created without making any changes.

.EXAMPLE
    .\New-BulkADUser.ps1 -CsvPath "C:\Temp\NewUsers.csv" -UpnSuffix "contoso.com"
    Creates the accounts described in the CSV using the given UPN suffix.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ActiveDirectory module, permission to create user
              objects under the OU paths supplied in the CSV
    Read-only/Mutating: Mutating - creates AD user accounts. Supports
              -WhatIf and -Confirm via SupportsShouldProcess.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$UpnSuffix = "corp.example.com"
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

function New-RandomPassword {
    # Only builds an in-memory string - no system state changes, so
    # ShouldProcess does not apply here.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param()

    # Generates a 16-character password that satisfies typical AD complexity policy
    $upper = 65..90 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $lower = 97..122 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $digits = 48..57 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $symbols = @('!','@','#','%','^','*') | Get-Random -Count 4
    -join (($upper + $lower + $digits + $symbols) | Sort-Object { Get-Random })
}

function ConvertTo-SecurePasswordString {
    # Suppressed: New-ADUser's AccountPassword parameter requires a SecureString.
    # The password here is freshly generated or supplied via CSV for one-time use
    # (ChangePasswordAtLogon is set by the caller) and is never persisted as plaintext.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )
    ConvertTo-SecureString -String $PlainText -AsPlainText -Force
}

if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

Write-Verbose "Importing user records from $CsvPath"
$rows = Import-Csv -LiteralPath $CsvPath
Write-Verbose "Loaded $($rows.Count) row(s) from CSV"
$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($row in $rows) {
    Write-Verbose "Processing row for SamAccountName '$($row.SamAccountName)'"

    $result = [pscustomobject]@{
        SamAccountName = $row.SamAccountName
        Status         = 'Unknown'
        Detail         = ''
    }

    if ([string]::IsNullOrWhiteSpace($row.FirstName) -or
        [string]::IsNullOrWhiteSpace($row.LastName) -or
        [string]::IsNullOrWhiteSpace($row.SamAccountName) -or
        [string]::IsNullOrWhiteSpace($row.OUPath)) {
        $result.Status = 'Skipped'
        $result.Detail = 'Missing a required field (FirstName, LastName, SamAccountName, or OUPath)'
        $results.Add($result)
        continue
    }

    $existing = Get-ADUser -Filter "SamAccountName -eq '$($row.SamAccountName)'" -ErrorAction SilentlyContinue
    if ($existing) {
        $result.Status = 'Skipped'
        $result.Detail = 'An account with this SamAccountName already exists'
        $results.Add($result)
        continue
    }

    $plainPassword = if ([string]::IsNullOrWhiteSpace($row.Password)) { New-RandomPassword } else { $row.Password }
    $securePassword = ConvertTo-SecurePasswordString -PlainText $plainPassword
    $displayName = "$($row.FirstName) $($row.LastName)"
    $upn = if ($row.EmailAddress) { $row.EmailAddress } else { "$($row.SamAccountName)@$UpnSuffix" }

    $newUserParams = @{
        Name                  = $displayName
        SamAccountName        = $row.SamAccountName
        UserPrincipalName     = $upn
        GivenName             = $row.FirstName
        Surname               = $row.LastName
        DisplayName           = $displayName
        Path                  = $row.OUPath
        AccountPassword       = $securePassword
        Enabled               = $true
        ChangePasswordAtLogon = $true
        PasswordNeverExpires  = $false
    }
    if ($row.Department) { $newUserParams['Department'] = $row.Department }
    if ($row.Title) { $newUserParams['Title'] = $row.Title }
    if ($row.EmailAddress) { $newUserParams['EmailAddress'] = $row.EmailAddress }

    if ($PSCmdlet.ShouldProcess($row.SamAccountName, 'Create AD user')) {
        try {
            New-ADUser @newUserParams -ErrorAction Stop
            $result.Status = 'Created'
            $result.Detail = if ([string]::IsNullOrWhiteSpace($row.Password)) { "Generated password: $plainPassword" } else { 'Password supplied via CSV' }
        }
        catch {
            $result.Status = 'Failed'
            $result.Detail = $_.Exception.Message
        }
    }
    else {
        $result.Status = 'Skipped'
        $result.Detail = 'WhatIf - no account created'
    }

    $results.Add($result)
}

Write-Verbose "Finished processing $($results.Count) row(s)"
$results | Format-Table -AutoSize
$summary = $results | Group-Object Status | Select-Object Name, Count
Write-Output "`nSummary:"
$summary | Format-Table -AutoSize