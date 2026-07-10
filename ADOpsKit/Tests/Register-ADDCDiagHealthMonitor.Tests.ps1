Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

# This function requires -RunAsAdministrator, mandatory SmtpServer/From/To,
# and registers a Scheduled Task + restricts filesystem ACLs when invoked -
# no invocation tests here by design (matches Register-ADOpsKitScheduledTasks,
# which is likewise only covered indirectly via the module export/help checks).
Describe "Register-ADDCDiagHealthMonitor" {

    Context "Parameter defaults" {

        It "Should default TaskName to ADDCDiagHealthMonitor" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TaskName' }
            $param.DefaultValue.ToString() | Should -Be "'ADDCDiagHealthMonitor'"
        }

        It "Should default IntervalMinutes to 5" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'IntervalMinutes' }
            $param.DefaultValue.ToString() | Should -Be '5'
        }

        It "Should default ScriptsFolder to C:\ADOpsKit\Scripts" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ScriptsFolder' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Scripts'
        }

        It "Should default PerDCTimeoutSeconds to 60" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'PerDCTimeoutSeconds' }
            $param.DefaultValue.ToString() | Should -Be '60'
        }

        It "Should default RepeatAlertAfterHours to 4" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RepeatAlertAfterHours' }
            $param.DefaultValue.ToString() | Should -Be '4'
        }

        It "Should default SmtpPort to 25" {
            $ast   = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SmtpPort' }
            $param.DefaultValue.ToString() | Should -Be '25'
        }
    }

    Context "Mandatory parameters" {

        BeforeAll {
            $script:ast = (Get-Command Register-ADDCDiagHealthMonitor).ScriptBlock.Ast
        }

        It "-<_> should be mandatory" -ForEach @('SmtpServer', 'From', 'To') {
            $paramName = $_
            $param = $script:ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $paramName }
            $mandatoryAttr = $param.Attributes | Where-Object { $_.TypeName.Name -eq 'Parameter' } |
                ForEach-Object { $_.NamedArguments } | Where-Object { $_.ArgumentName -eq 'Mandatory' }
            $mandatoryAttr | Should -Not -BeNullOrEmpty
        }
    }

    Context "Supports ShouldProcess" {

        It "Should support -WhatIf" {
            (Get-Command Register-ADDCDiagHealthMonitor).Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }
}
