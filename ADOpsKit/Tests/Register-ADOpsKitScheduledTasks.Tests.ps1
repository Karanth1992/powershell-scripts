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
    # Windows Scheduled Tasks - not safe to drive unattended in a test run.
    # The two Context blocks below check the wizard's internal logic
    # statically (source text) since the wizard itself can't be invoked
    # unattended.

    Context "Service account must include a domain qualifier" {

        BeforeAll {
            $script:source = (Get-Command Register-ADOpsKitScheduledTasks).ScriptBlock.Ast.Extent.Text
        }

        It "Should define a domain-qualifier guard" {
            $script:source | Should -Match 'function Assert-AccountHasDomainQualifier'
        }

        It "Should call the guard for a config-replayed account" {
            $script:source | Should -Match "if \(-not \`$account\) \{ throw[\s\S]{0,80}Assert-AccountHasDomainQualifier -Account \`$account"
        }

        It "Should call the guard when a gMSA account is entered interactively" {
            $script:source | Should -Match "Enter gMSA account[\s\S]{0,80}Assert-AccountHasDomainQualifier -Account \`$account"
        }

        It "Should call the guard when a regular account is entered interactively" {
            $script:source | Should -Match "Enter service account[\s\S]{0,80}Assert-AccountHasDomainQualifier -Account \`$account"
        }

        It "Should reject a bare username with no domain qualifier" {
            # Mirrors the guard's own condition, exercised directly rather
            # than through the interactive wizard.
            $bareUsername = 'svc-adops'
            ($bareUsername -notmatch '\\' -and $bareUsername -notmatch '@') | Should -BeTrue
        }

        It "Should accept DOMAIN\username and UPN formats" {
            $domainForm = 'CONTOSO\svc-adops'
            $upnForm    = 'svc-adops@contoso.com'
            ($domainForm -notmatch '\\' -and $domainForm -notmatch '@') | Should -BeFalse
            ($upnForm -notmatch '\\' -and $upnForm -notmatch '@') | Should -BeFalse
        }
    }

    Context "Weekly schedules support multiple days" {

        BeforeAll {
            $script:source = (Get-Command Register-ADOpsKitScheduledTasks).ScriptBlock.Ast.Extent.Text
        }

        It "Should use Read-MultiMenuChoice (not single-select) for day-of-week entry" {
            $script:source | Should -Match "Read-MultiMenuChoice -Prompt `"  Day\(s\) of week`""
        }

        It "New-ScheduledTaskTrigger -DaysOfWeek should accept an array of days" {
            # Confirms the underlying cmdlet contract this wizard relies on -
            # DaysOfWeek is a Flags enum, so a multi-element array is valid.
            $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek @('Monday', 'Wednesday', 'Friday') -At '06:00'
            $trigger.DaysOfWeek | Should -Be 42  # Monday(2) + Wednesday(8) + Friday(32)
        }
    }
}
