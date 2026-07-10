Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-AccountLockoutReport" {

    Context "Parameter defaults" {

        It "Should default TempPath to C:\ADOpsKit\Reports\Get-AccountLockoutReport" {
            $ast   = (Get-Command Get-AccountLockoutReport).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TempPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-AccountLockoutReport'
        }

        It "Should default SharedPath to C:\ADOpsKit\Reports\Get-AccountLockoutReport" {
            $ast   = (Get-Command Get-AccountLockoutReport).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SharedPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-AccountLockoutReport'
        }

        It "Should default LookbackMilliseconds to 4233600000 (7 weeks)" {
            $ast   = (Get-Command Get-AccountLockoutReport).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'LookbackMilliseconds' }
            $param.DefaultValue.ToString() | Should -Be '4233600000'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:tempPath = Join-Path $TestDrive 'lockout-temp'
            Get-AccountLockoutReport -TempPath $script:tempPath -SharedPath $script:tempPath
        }

        It "Should create the temp/shared output folder" {
            $script:tempPath | Should -Exist
        }

        It "Should write a list-of-locked-users text file" {
            $datePrefix = Get-Date -Format 'yyyy-MM-dd'
            Join-Path $script:tempPath "${datePrefix}_List_of_locked_users.txt" | Should -Exist
        }
    }
}
