Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Invoke-ADRealtimeHeartbeat" {

    Context "Parameter defaults" {

        It "Should default OutputFolder to C:\ADOpsKit\Reports\Invoke-ADRealtimeHeartbeat" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputFolder' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Invoke-ADRealtimeHeartbeat'
        }

        It "Should default ReportRetentionDays to 30" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ReportRetentionDays' }
            $param.DefaultValue.ToString() | Should -Be '30'
        }

        It "Should default TcpTimeoutMs to 3000" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TcpTimeoutMs' }
            $param.DefaultValue.ToString() | Should -Be '3000'
        }

        It "Should default TcpPort to 53, 88, 135, 389, 445" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TcpPort' }
            $param.DefaultValue.ToString() | Should -Match '53.*88.*135.*389.*445'
        }

        It "Should default DeepCheckTimeoutMs to 5000" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'DeepCheckTimeoutMs' }
            $param.DefaultValue.ToString() | Should -Be '5000'
        }

        It "Should default RequiredService to NTDS, Netlogon, KDC, DNS, DFSR, W32Time" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RequiredService' }
            $param.DefaultValue.ToString() | Should -Match "NTDS.*Netlogon.*KDC.*DNS.*DFSR.*W32Time"
        }

        It "Should default SuppressRepeatMinutes to 15" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SuppressRepeatMinutes' }
            $param.DefaultValue.ToString() | Should -Be '15'
        }

        It "Should default SmtpPort to 25" {
            $ast   = (Get-Command Invoke-ADRealtimeHeartbeat).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SmtpPort' }
            $param.DefaultValue.ToString() | Should -Be '25'
        }
    }

    Context "Parameter validation" {

        # These all fail at Assert-Configuration, before the output folder
        # is created or Active Directory is contacted, so they are safe to
        # run without domain connectivity or any side effects.

        It "Should throw when -SendEmail is supplied without -To" {
            { Invoke-ADRealtimeHeartbeat -SendEmail -From 'a@b.com' -SmtpServer 'smtp.contoso.com' } |
                Should -Throw '*no -To recipient addresses*'
        }

        It "Should throw when -SendEmail is supplied without -From" {
            { Invoke-ADRealtimeHeartbeat -SendEmail -To 'a@b.com' -SmtpServer 'smtp.contoso.com' } |
                Should -Throw '*-From is empty*'
        }

        It "Should throw when -SendEmail is supplied without -SmtpServer" {
            { Invoke-ADRealtimeHeartbeat -SendEmail -To 'a@b.com' -From 'a@b.com' } |
                Should -Throw '*-SmtpServer is empty*'
        }

        It "Should throw when -SendSlack is supplied without a webhook URL" {
            { Invoke-ADRealtimeHeartbeat -SendSlack } |
                Should -Throw '*Slack webhook*'
        }
    }

    Context "-VersionInfo returns metadata without running any checks" {

        It "Should return version metadata" {
            $result = Invoke-ADRealtimeHeartbeat -VersionInfo
            $result.ScriptName | Should -Be 'Invoke-ADRealtimeHeartbeat'
            $result.Version    | Should -Not -BeNullOrEmpty
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outputFolder = Join-Path $TestDrive 'heartbeat'
            $script:result = Invoke-ADRealtimeHeartbeat -OutputFolder $script:outputFolder
        }

        It "Should return one result per domain controller" {
            $script:result.Count | Should -BeGreaterThan 0
        }

        It "Should report OverallStatus for each result" {
            $script:result | ForEach-Object { $_.OverallStatus | Should -Not -BeNullOrEmpty }
        }

        It "Should write latest.html and latest.json" {
            Join-Path $script:outputFolder 'latest.html' | Should -Exist
            Join-Path $script:outputFolder 'latest.json' | Should -Exist
        }

        It "Should write a dated report into the history folder" {
            Get-ChildItem (Join-Path $script:outputFolder 'history') -Filter '*.html' | Should -Not -BeNullOrEmpty
        }

        It "Should write the alert state file" {
            Join-Path $script:outputFolder 'ADRealtimeHeartbeat-State.json' | Should -Exist
        }
    }
}
