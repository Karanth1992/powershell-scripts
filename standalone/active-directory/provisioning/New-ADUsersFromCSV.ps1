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
    # Generates a 16-character password that satisfies typical AD complexity policy
    $upper = 65..90 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $lower = 97..122 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $digits = 48..57 | Get-Random -Count 4 | ForEach-Object { [char]$_ }
    $symbols = @('!','@','#','%','^','*') | Get-Random -Count 4
    -join (($upper + $lower + $digits + $symbols) | Sort-Object { Get-Random })
}

if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

$rows = Import-Csv -LiteralPath $CsvPath
$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($row in $rows) {

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
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
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

$results | Format-Table -AutoSize
$summary = $results | Group-Object Status | Select-Object Name, Count
Write-Output "`nSummary:"
$summary | Format-Table -AutoSize