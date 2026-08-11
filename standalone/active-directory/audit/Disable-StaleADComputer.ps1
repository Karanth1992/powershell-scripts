<#
.SYNOPSIS
    Finds and optionally disables stale (inactive) Active Directory
    computer accounts.

.DESCRIPTION
    Uses Search-ADAccount to find computer objects that have been
    inactive for longer than the given threshold, then classifies
    each candidate before touching anything:
    - Domain controllers (PrimaryGroupID 516/521) are always skipped
    - Cluster name objects (SPN matches a cluster service) are
      always skipped
    - Accounts already disabled are skipped
    - Accounts whose PasswordLastSet is more recent than the
      inactivity threshold are flagged for manual Review rather
      than acted on
    - Everything else is reported as a Candidate

    By default the script is read-only and only reports candidates.
    Pass -Disable to actually disable qualifying accounts; disabling
    is gated by SupportsShouldProcess, so -WhatIf/-Confirm apply.

    Data source: ActiveDirectory module (Search-ADAccount,
    Get-ADComputer, Disable-ADAccount).
    WinRM: not used - all work is done locally against the
    ActiveDirectory module's own LDAP connection.

    Output: a timestamped CSV report is always written to ReportPath,
    listing every candidate found and the action taken (or not taken)
    for each. Default: C:\Temp\Reports\StaleComputerAccounts.

.PARAMETER InactiveDays
    Number of days of inactivity before a computer account is
    considered stale. Default is 90.

.PARAMETER SearchBase
    Optional distinguished name to limit the search to a specific OU
    or subtree. If omitted, the whole domain is searched.

.PARAMETER ReportPath
    Folder where the CSV report is written. Defaults to
    C:\Temp\Reports\StaleComputerAccounts. Created automatically if
    it does not exist.

.PARAMETER Disable
    Switch to actually disable qualifying stale accounts. Without
    this switch the script only reports candidates and makes no
    changes.

.EXAMPLE
    .\Disable-StaleADComputer.ps1
    Reports stale computer accounts (90+ days inactive) without
    disabling anything.

.EXAMPLE
    .\Disable-StaleADComputer.ps1 -InactiveDays 180 -Disable -WhatIf
    Previews which accounts inactive for 180+ days would be disabled,
    without making changes.

.EXAMPLE
    .\Disable-StaleADComputer.ps1 -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" -Disable
    Disables qualifying stale accounts under the given OU only.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ActiveDirectory module, permission to disable computer
              objects in scope
    Read-only/Mutating: Read-only by default; mutating (disables
              accounts) only when -Disable is supplied. Supports
              -WhatIf and -Confirm via SupportsShouldProcess.
#>

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

Write-Verbose "Searching for computer accounts inactive $InactiveDays+ days$(if ($SearchBase) { " under $SearchBase" })"
$candidates = Search-ADAccount @searchParams
Write-Verbose "Found $($candidates.Count) candidate(s)"
$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($candidate in $candidates) {
    Write-Verbose "Evaluating $($candidate.DistinguishedName)"

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
Write-Verbose "Writing report to $csvPath"
$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation

$results | Format-Table -AutoSize
$summary = $results | Group-Object Status | Select-Object Name, Count
Write-Output "`nSummary:"
$summary | Format-Table -AutoSize
Write-Output "Report written to: $csvPath"