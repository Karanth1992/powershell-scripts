Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Register-ADOpsKitScheduledTasks" {

    Context "Parameter defaults" {

        It "Should default OutputBasePath to C:\ADOpsKit\Reports" {
            $ast   = (Get-Command Register-ADOpsKitScheduledTasks).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputBasePath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports'
        }

        It "Should default RetentionDays to 90" {
            $ast   = (Get-Command Register-ADOpsKitScheduledTasks).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RetentionDays' }
            $param.DefaultValue.ToString() | Should -Be '90'
        }
    }

    Context "Parameter validation" {

        It "Should support -WhatIf / -Confirm" {
            (Get-Command Register-ADOpsKitScheduledTasks).Parameters.Keys | Should -Contain 'WhatIf'
            (Get-Command Register-ADOpsKitScheduledTasks).Parameters.Keys | Should -Contain 'Confirm'
        }

        It "Should reject RetentionDays outside 0-3650" {
            # Fails at parameter binding via ValidateRange, before the
            # interactive wizard or any elevation/task-scheduler access.
            { Register-ADOpsKitScheduledTasks -RetentionDays -1 -WhatIf } | Should -Throw
            { Register-ADOpsKitScheduledTasks -RetentionDays 3651 -WhatIf } | Should -Throw
        }

        It "Should reject an empty -ConfigPath" {
            # Fails at parameter binding via ValidateNotNullOrEmpty.
            { Register-ADOpsKitScheduledTasks -ConfigPath '' -WhatIf } | Should -Throw
        }
    }

    # No Integration context here: this function is interactive (Read-Host
    # driven wizard), requires -RunAsAdministrator, and registers real
    # Windows Scheduled Tasks — not safe to drive unattended in a test run.
}
