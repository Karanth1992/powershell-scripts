function Get-AccountLockoutReport {
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
    Defaults to $env:TEMP.

.PARAMETER SharedPath
    Network share path where final reports are written.
    Defaults to \\server\AccountLockout.

.PARAMETER LookbackMilliseconds
    How far back to search event logs in milliseconds.
    Default is 4233600000 (7 weeks).

.EXAMPLE
    Get-AccountLockoutReport
    Runs with default paths and 7-week lookback.

.EXAMPLE
    Get-AccountLockoutReport -TempPath "D:\temp" -SharedPath "\\fileserver\Reports\Lockouts" -LookbackMilliseconds 86400000
    Runs with custom paths and a 24-hour lookback window.

.NOTES
    Author:   K Shankar R Karanth
    Website:  https://karanth.ovh
    Version:  1.0
    Run as Domain Admin or equivalent with read access to the
    Security event log on the PDC Emulator.
#>

    [CmdletBinding()]
    param (
        [string]$TempPath            = 'C:\ADOpsKit\Reports\Get-AccountLockoutReport',
        [string]$SharedPath          = 'C:\ADOpsKit\Reports\Get-AccountLockoutReport',
        [long]$LookbackMilliseconds  = 4233600000
    )

    Set-StrictMode -Version Latest

    # ============ FUNCTIONS ============

    function Remove-ExistingFile {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
        param([string[]]$Files)
        foreach ($f in $Files) {
            if (Test-Path -LiteralPath $f) {
                if ($PSCmdlet.ShouldProcess($f, 'Remove existing file')) {
                    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
                }
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
            Write-Warning "Failed to send account lockout report email to '$To': $($_.Exception.Message)"
        }
    }

    # ============ EMAIL CONFIGURATION ============
    # Update these before enabling email reporting

    # $emailFrom = 'ad.monitoring@example.com'
    # $emailTo   = 'domainadmins@example.com'
    # $emailSmtp = 'smtp.example.com'

    # ============ FILE PATHS ============

    if (-not (Test-Path -LiteralPath $TempPath)) { New-Item -ItemType Directory -Path $TempPath -Force | Out-Null }

    $datePrefix      = Get-Date -Format 'yyyy-MM-dd'
    $fileLockList    = "$TempPath\${datePrefix}_List_of_locked_users.txt"
    $fileLockCsvTemp = "$TempPath\${datePrefix}_Computers_Causing_locked_users.csv"
    $fileLockCsvSort = "$TempPath\${datePrefix}_sorted.csv"
    $fileLockHtml    = "$TempPath\${datePrefix}_Computers_Causing_Lockouts.html"
    $shareLocklist   = "$SharedPath\${datePrefix}_List_of_locked_users.txt"
    $shareLockCsv    = "$SharedPath\${datePrefix}_Computers_Causing_locked_users.csv"
    $shareLockHtml   = "$SharedPath\${datePrefix}_Computers_Causing_Lockouts.html"

    Remove-ExistingFile -Files @($fileLockList, $fileLockCsvTemp, $fileLockCsvSort)

    # ============ DISCOVER PDC AND LOCKED USERS ============

    $startDate   = Get-Date
    $pdc         = Get-ADDomainController -Discover -Service PrimaryDC
    # Force array context: Select-Object -ExpandProperty returns a bare string
    # (no .Count) rather than a one-element array when exactly one account is
    # locked out, which would otherwise make $userCount silently blank.
    $lockedUsers = @(Search-ADAccount -LockedOut | Select-Object -ExpandProperty Name)
    $userCount   = $lockedUsers.Count

    $lockedUsers | Out-File -LiteralPath $fileLockList

    Write-ProgressInfo "Locked out accounts found: $userCount" -Color Red
    Write-ProgressInfo "Querying PDC $($pdc.Name) for lockout source computers..." -Color Yellow

    # ============ QUERY EVENT ID 4740 PER USER ============

    $pass = 1
    foreach ($user in $lockedUsers) {
        Write-ProgressInfo "Processing: $user ($pass of $userCount)" -Color Blue

        try {
            $userXPathLiteral = ConvertTo-ADOKXPathStringLiteral -Value $user
            $xPath = "*[System[EventID=4740 and TimeCreated[timediff(@SystemTime) <= $LookbackMilliseconds]]" +
                     " and EventData[Data[@Name='TargetUserName']=$userXPathLiteral]]"

            Get-WinEvent -ComputerName $pdc.Name -LogName Security `
                -FilterXPath $xPath -ErrorAction Stop |
                Select-Object TimeCreated,
                    @{ Name = 'User Name';    Expression = { $_.Properties[0].Value } },
                    @{ Name = 'Source Host';  Expression = { $_.Properties[1].Value } } |
                Export-Csv -LiteralPath $fileLockCsvTemp -Append -NoTypeInformation -Force
        }
        catch {
            Write-ProgressInfo "Error processing $user : $_" -Color Red
            Write-Warning "Error querying lockout source events for '$user': $($_.Exception.Message)"
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

    $htmlBody = '<h1>Computers Causing Lockouts &mdash; Sorted by User Name</h1>'

    # ============ SORT CSV AND WRITE REPORTS ============

    try {
        if (Test-Path -LiteralPath $fileLockCsvTemp) {
            Import-Csv -LiteralPath $fileLockCsvTemp |
                Sort-Object 'User Name' |
                Export-Csv -LiteralPath $fileLockCsvSort -NoTypeInformation

            Import-Csv -LiteralPath $fileLockCsvSort |
                ConvertTo-Html -Head $htmlHead -Body $htmlBody |
                Out-File -LiteralPath $fileLockHtml -Force
        }
        else {
            Write-ProgressInfo "No event data found - CSV not generated." -Color Yellow
        }
    }
    catch {
        Write-ProgressInfo "Error generating HTML report: $_" -Color Red
        Write-Warning "Error generating account lockout HTML report: $($_.Exception.Message)"
    }

    # ============ COPY TO SHARED PATH ============

    $tempAndSharedAreSameLocation =
        [System.IO.Path]::GetFullPath($TempPath).TrimEnd('\') -ieq
        [System.IO.Path]::GetFullPath($SharedPath).TrimEnd('\')

    if ($tempAndSharedAreSameLocation) {
        # TempPath and SharedPath resolve to the same folder (the default).
        # The report files are already there - clearing "the shared copy"
        # first would delete the files that were just generated, so the
        # clear-then-copy step below is skipped entirely in this case.
        Write-ProgressInfo "TempPath and SharedPath are the same location - reports already at $SharedPath" -Color Green
    }
    else {
        Remove-ExistingFile -Files @($shareLocklist, $shareLockCsv, $shareLockHtml)

        $copyFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($copyPair in @(
            @{ Source = $fileLockCsvTemp; Destination = $shareLockCsv },
            @{ Source = $fileLockHtml;    Destination = $shareLockHtml },
            @{ Source = $fileLockList;    Destination = $shareLocklist }
        )) {
            if (Test-Path -LiteralPath $copyPair.Source) {
                try {
                    Copy-Item -LiteralPath $copyPair.Source -Destination $copyPair.Destination -Force -ErrorAction Stop
                }
                catch {
                    Write-ProgressInfo "Failed to copy $($copyPair.Source) to $($copyPair.Destination): $($_.Exception.Message)" -Color Red
                    Write-Warning "Failed to copy '$($copyPair.Source)' to '$($copyPair.Destination)': $($_.Exception.Message)"
                    $copyFailures.Add($copyPair.Destination)
                }
            }
        }

        if ($copyFailures.Count -gt 0) {
            Write-ProgressInfo "Reports partially written to $SharedPath - $($copyFailures.Count) file(s) failed to copy, see above." -Color Red
            Write-Warning "Account lockout reports partially written to '$SharedPath' - $($copyFailures.Count) file(s) failed to copy: $($copyFailures -join ', ')"
        }
        else {
            Write-ProgressInfo "Reports written to $SharedPath" -Color Green
        }
    }

    # ============ EMAIL SUMMARY (uncomment to enable) ============
    # $emailSubject = "User Lockout Report - $userCount account(s) locked"
    # $emailBody = "There are $userCount account(s) locked out at this time.`n" +
    #              "Generated by scheduled task on $env:COMPUTERNAME`n" +
    #              "Started: $startDate - Duration: $duration minutes`n`n" +
    #              "Attachments:`n" +
    #              "1. List of locked accounts`n" +
    #              "2. CSV report of lockout source computers`n" +
    #              "3. HTML report of lockout source computers`n`n" +
    #              "Reports also available at:`n$shareLockCsv`n$shareLockHtml`n$shareLocklist`n`n" +
    #              "NOTE: Only accounts with Event ID 4740 recorded on the PDC Emulator within" +
    #              " the lookback window are included."
    # Send-ReportEmail -From $emailFrom -To $emailTo -Subject $emailSubject `
    #     -Body $emailBody -Attachments @($fileLockList, $fileLockCsvTemp, $fileLockHtml) `
    #     -SmtpServer $emailSmtp
    Write-ProgressInfo "Complete. Duration: $duration minutes." -Color Green
}
