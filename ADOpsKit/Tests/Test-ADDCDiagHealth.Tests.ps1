Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Test-ADDCDiagHealth" {

    Context "Parameter defaults" {

        It "Should default PerDCTimeoutSeconds to 60" {
            $ast   = (Get-Command Test-ADDCDiagHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'PerDCTimeoutSeconds' }
            $param.DefaultValue.ToString() | Should -Be '60'
        }

        It "Should default RepeatAlertAfterHours to 4" {
            $ast   = (Get-Command Test-ADDCDiagHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RepeatAlertAfterHours' }
            $param.DefaultValue.ToString() | Should -Be '4'
        }

        It "Should default StateFilePath to C:\ADOpsKit\State\Test-ADDCDiagHealth.state.json" {
            $ast   = (Get-Command Test-ADDCDiagHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'StateFilePath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\State\\Test-ADDCDiagHealth\.state\.json'
        }

        It "Should default AlertLogPath to C:\ADOpsKit\Reports\Test-ADDCDiagHealth\AlertLog.csv" {
            $ast   = (Get-Command Test-ADDCDiagHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'AlertLogPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Test-ADDCDiagHealth\\AlertLog\.csv'
        }

        It "Should default SmtpPort to 25" {
            $ast   = (Get-Command Test-ADDCDiagHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SmtpPort' }
            $param.DefaultValue.ToString() | Should -Be '25'
        }
    }

    Context "Parameter validation" {

        It "Should throw when -SmtpServer is supplied without -From and -To" {
            # Fails on the up-front validation check before any DC or network
            # activity, so this is safe to run without domain connectivity.
            { Test-ADDCDiagHealth -DomainController 'NONEXISTENT-DC' -SmtpServer 'smtp.contoso.com' } |
                Should -Throw '*Both -From and -To are required*'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        It "Should report Unreachable for a nonexistent DC name without throwing" {
            $statePath = Join-Path $TestDrive 'state.json'
            $logPath   = Join-Path $TestDrive 'alertlog.csv'
            $result    = Test-ADDCDiagHealth -DomainController 'NONEXISTENT-DC-12345' -StateFilePath $statePath -AlertLogPath $logPath
            $result.Status | Should -Be 'Unreachable'
        }
    }
}
