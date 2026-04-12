<#
.SYNOPSIS
    Reports currently locked Active Directory accounts and the
    computers that caused the lockouts.

.DESCRIPTION
    Queries all locked out accounts using Search-ADAccount, then
    parses Security Event ID 4740 on the PDC Emulator to identify
    which computers triggered each lockout.

    Outputs three report formats:
    - Plain text list of locked accounts
    - CSV with lockout source computers per user
    - Colour-coded HTML report sorted by username

    All reports are copied to a shared path and optionally
    emailed to a distribution group.

.PARAMETER TempPath
    Local path for temporary file storage during report generation.
    Defaults to C:\temp.

.PARAMETER SharedPath
    Network share path where final reports are written.
    Defaults to \\server\AccountLockout.

.PARAMETER LookbackMilliseconds
    How far back to search event logs in milliseconds.
    Default is 4233600000 (7 weeks).

.EXAMPLE
    .\Get-AccountLockoutReport.ps1
    Runs with default paths and 7-week lookback.

.EXAMPLE
    .\Get-AccountLockoutReport.ps1 -TempPath "D:\temp" -SharedPath "\\fileserver\Reports\Lockouts" -LookbackMilliseconds 86400000
    Runs with custom paths and a 24-hour lookback window.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Requires: ActiveDirectory module, read access to Security
              event log on PDC Emulator, run as Domain Admin
              or equivalent
#>

param (
    [string]$TempPath            = "C:\temp",
    [string]$SharedPath          = "\\server\AccountLockout",
    [int]$LookbackMilliseconds   = 4233600000
)

# ============ FUNCTIONS ============

function Remove-ExistingFile {
    param([string[]]$Files)
    foreach ($f in $Files) {
        if (Test-Path $f) {
            Remove-Item $f -ErrorAction SilentlyContinue
        }
    }
}

function Write-ProgressInfo {
    param(
        [string]$Message,
        [string]$Color = 'Yellow'
    )
    Write-Host $Message -ForegroundColor $Color
}

function Send-ReportEmail {
    param(
        [string]$From,
        [string]$To,
        [string]$Subject,
        [string]$Body,
        [string[]]$Attachments,
        [string]$SmtpServer
    )
    try {
        Send-MailMessage -From $From -To $To -Subject $Subject `
            -Body $Body -Attachments $Attachments -SmtpServer $SmtpServer
        Write-ProgressInfo "Email sent to $To" -Color Green
    }
    catch {
        Write-ProgressInfo "Failed to send email: $_" -Color Red
    }
}

# ============ EMAIL CONFIGURATION ============
# Update these before enabling email reporting

$emailFrom = 'ad.monitoring@example.com'
$emailTo   = 'domainadmins@example.com'
$emailSmtp = 'smtp.example.com'

# ============ FILE PATHS ============

$fileLockList    = "$TempPath\List_of_locked_users.txt"
$fileLockCsvTemp = "$TempPath\Computers_Causing_locked_users.csv"
$fileLockCsvSort = "$TempPath\sorted.csv"
$fileLockHtml    = "$TempPath\Computers_Causing_Lockouts.html"
$shareLocklist   = "$SharedPath\List_of_locked_users.txt"
$shareLockCsv    = "$SharedPath\Computers_Causing_locked_users.csv"
$shareLockHtml   = "$SharedPath\Computers_Causing_Lockouts.html"

Remove-ExistingFile -Files @($fileLockList, $fileLockCsvTemp, $fileLockCsvSort)

# ============ DISCOVER PDC AND LOCKED USERS ============

$startDate   = Get-Date
$pdc         = Get-ADDomainController -Discover -Service PrimaryDC
$lockedUsers = Search-ADAccount -LockedOut | Select-Object -ExpandProperty Name
$userCount   = $lockedUsers.Count

$lockedUsers | Out-File $fileLockList

Write-ProgressInfo "Locked out accounts found: $userCount" -Color Red
Write-ProgressInfo "Querying PDC $($pdc.Name) for lockout source computers..." -Color Yellow

# ============ QUERY EVENT ID 4740 PER USER ============

$pass = 1
foreach ($user in $lockedUsers) {
    Write-ProgressInfo "Processing: $user ($pass of $userCount)" -Color Blue

    try {
        $xPath = "*[System[EventID=4740 and TimeCreated[timediff(@SystemTime) <= $LookbackMilliseconds]]" +
                 " and EventData[Data[@Name='TargetUserName']='$user']]"

        Get-WinEvent -ComputerName $pdc.Name -LogName Security `
            -FilterXPath $xPath -ErrorAction Stop |
            Select-Object TimeCreated,
                @{ Name = 'User Name';    Expression = { $_.Properties[0].Value } },
                @{ Name = 'Source Host';  Expression = { $_.Properties[1].Value } } |
            Export-Csv -Path $fileLockCsvTemp -Append -NoTypeInformation -Force
    }
    catch {
        Write-ProgressInfo "Error processing $user : $_" -Color Red
    }

    $pass++
}

$endDate  = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $startDate -End $endDate).TotalMinutes, 2)

# ============ BUILD HTML REPORT ============

$htmlHead = @'
<title>Computers Causing Lockouts</title>
<style>
body  { background:#f3f4f6; color:#22223b; font-family:"Segoe UI",Arial,sans-serif; font-size:16px; margin:20px; }
h1    { color:#2a394f; border-bottom:2px solid #c9d6e3; padding-bottom:8px; }
table { border-collapse:collapse; width:100%; background:#fff; margin-top:20px; }
th,td { border:1px solid #e1e5ee; padding:10px; text-align:left; }
th    { background:#eaf0fa; }
tr:nth-child(even) td { background:#f8f8fc; }
</style>
'@

$htmlBody = '<h1>Computers Causing Lockouts — Sorted by User Name</h1>'

# ============ SORT CSV AND WRITE REPORTS ============

try {
    if (Test-Path $fileLockCsvTemp) {
        Import-Csv -Path $fileLockCsvTemp |
            Sort-Object 'User Name' |
            Export-Csv -Path $fileLockCsvSort -NoTypeInformation

        Import-Csv -Path $fileLockCsvSort |
            ConvertTo-Html -Head $htmlHead -Body $htmlBody |
            Out-File $fileLockHtml -Force
    }
    else {
        Write-ProgressInfo "No event data found — CSV not generated." -Color Yellow
    }
}
catch {
    Write-ProgressInfo "Error generating HTML report: $_" -Color Red
}

# ============ COPY TO SHARED PATH ============

Remove-ExistingFile -Files @($shareLocklist, $shareLockCsv, $shareLockHtml)

Copy-Item $fileLockCsvTemp $shareLockCsv  -Force
Copy-Item $fileLockHtml    $shareLockHtml -Force
Copy-Item $fileLockList    $shareLocklist -Force

Write-ProgressInfo "Reports written to $SharedPath" -Color Green

<# ============ EMAIL SUMMARY (uncomment to enable) ============

 $emailSubject = "User Lockout Report — $userCount account(s) locked"
 $emailBody = @"
 There are $userCount account(s) locked out at this time.
 Generated by scheduled task on $env:COMPUTERNAME
 Started: $startDate — Duration: $duration minutes

 Attachments:
 1. List of locked accounts
 2. CSV report of lockout source computers
 3. HTML report of lockout source computers

 Reports also available at:
 $shareLockCsv
 $shareLockHtml
 $shareLocklist

 NOTE: Only accounts with Event ID 4740 recorded on the PDC
 Emulator within the lookback window are included. Reports
 may not be fully inclusive if events have been overwritten.
 "@

 Send-ReportEmail -From $emailFrom -To $emailTo -Subject $emailSubject `
     -Body $emailBody -Attachments @($fileLockList, $fileLockCsvTemp, $fileLockHtml) `
     -SmtpServer $emailSmtp
#>
Write-ProgressInfo "Complete. Duration: $duration minutes." -Color Green