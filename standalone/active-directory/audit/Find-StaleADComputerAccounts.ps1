[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = "C:\Temp\Reports\StaleComputerAccounts",

    [Parameter(Mandatory = $false)]
    [switch]$Disable
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -LiteralPath $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
}

$cutoffDate = (Get-Date).AddDays(-$InactiveDays)

# Step 1: find candidates using the replicated lastLogonTimestamp attribute
$searchParams = @{
    AccountInactive = $true
    TimeSpan        = (New-TimeSpan -Days $InactiveDays)
    ComputersOnly   = $true
}
if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }

$candidates = Search-ADAccount @searchParams
$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($candidate in $candidates) {

    # Step 2: pull the extra properties Search-ADAccount does not return,
    # so every row can be reviewed before anything is disabled
    $computer = Get-ADComputer -Identity $candidate.DistinguishedName `
        -Properties LastLogonDate, PasswordLastSet, OperatingSystem, Enabled, PrimaryGroupID, ServicePrincipalName

    $isDomainController = $computer.PrimaryGroupID -in 516, 521

    $isClusterObject = $false
    foreach ($spn in $computer.ServicePrincipalName) {
        if ($spn -match 'MSClusterVirtualServer|MSServerClusterMgmtAPI') {
            $isClusterObject = $true
            break
        }
    }

    $result = [pscustomobject]@{
        Name              = $computer.Name
        DistinguishedName = $computer.DistinguishedName
        LastLogonDate     = $computer.LastLogonDate
        PasswordLastSet   = $computer.PasswordLastSet
        OperatingSystem   = $computer.OperatingSystem
        Status            = 'Unknown'
        Detail            = ''
    }

    if (-not $computer.Enabled) {
        $result.Status = 'Skipped'
        $result.Detail = 'Account is already disabled'
    }
    elseif ($isDomainController) {
        $result.Status = 'Skipped'
        $result.Detail = 'PrimaryGroupID indicates a domain controller (516/521) - never touched automatically'
    }
    elseif ($isClusterObject) {
        $result.Status = 'Skipped'
        $result.Detail = 'ServicePrincipalName suggests a cluster name object - verify manually before touching'
    }
    elseif ($computer.PasswordLastSet -and $computer.PasswordLastSet -gt $cutoffDate) {
        $result.Status = 'Review'
        $result.Detail = 'PasswordLastSet is more recent than the inactivity threshold - confirm before disabling'
    }
    else {
        # Step 3: disable only when explicitly requested; ShouldProcess honours -WhatIf and -Confirm
        if ($Disable) {
            if ($PSCmdlet.ShouldProcess($computer.DistinguishedName, 'Disable stale AD computer account')) {
                try {
                    Disable-ADAccount -Identity $computer.DistinguishedName -ErrorAction Stop
                    $result.Status = 'Disabled'
                    $result.Detail = "Disabled after $InactiveDays+ days of inactivity"
                }
                catch {
                    $result.Status = 'Failed'
                    $result.Detail = $_.Exception.Message
                }
            }
            else {
                $result.Status = 'Skipped'
                $result.Detail = 'WhatIf - no account disabled'
            }
        }
        else {
            $result.Status = 'Candidate'
            $result.Detail = 'Re-run with -Disable to act on this account'
        }
    }

    $results.Add($result)
}

# Always export a CSV of what was found and what happened to it, before anything else
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvPath = Join-Path -Path $ReportPath -ChildPath "StaleComputerAccounts_$timestamp.csv"
$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation

$results | Format-Table -AutoSize
$summary = $results | Group-Object Status | Select-Object Name, Count
Write-Output "`nSummary:"
$summary | Format-Table -AutoSize
Write-Output "Report written to: $csvPath"