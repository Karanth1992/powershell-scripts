Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Enable-DCPerformanceBaseline" {

    Context "Function shape" {

        It "Should take no parameters (deploys to all DCs in the current domain)" {
            $ast = (Get-Command Enable-DCPerformanceBaseline).ScriptBlock.Ast
            $ast.Body.ParamBlock.Parameters | Should -BeNullOrEmpty
        }

        It "Should support CmdletBinding" {
            (Get-Command Enable-DCPerformanceBaseline).CmdletBinding | Should -BeTrue
        }
    }

    # No Integration context here: this function has no -WhatIf support and
    # deploys a real logman Data Collector Set to every DC in the domain via
    # WMI/DCOM, so it is not safe to invoke automatically in a test run.
}
