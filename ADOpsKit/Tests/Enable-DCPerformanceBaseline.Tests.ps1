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

        It "Should support -WhatIf (SupportsShouldProcess)" {
            (Get-Command Enable-DCPerformanceBaseline).Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }
    }

    # No Integration context here: even with -WhatIf support, this function's
    # credential/connectivity requirements (WMI/DCOM + SMB to every DC) make it
    # unsuitable for an automated -WhatIf smoke test in this suite.
}
