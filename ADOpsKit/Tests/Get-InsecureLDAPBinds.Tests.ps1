BeforeAll {
    Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force
}

Describe "Get-InsecureLDAPBinds" {

    Context "Parameter defaults" {

        It "Should default Hours to 24" {
            $ast   = (Get-Command Get-InsecureLDAPBinds).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Hours' }
            $param.DefaultValue.ToString() | Should -Be '24'
        }

        It "Should default OutputPath to C:\ADOpsKit\Reports\Get-InsecureLDAPBinds" {
            $ast   = (Get-Command Get-InsecureLDAPBinds).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-InsecureLDAPBinds'
        }
    }

    Context "Output directory auto-creation" -Tag 'Integration' {

        It "Should create OutputPath directory if it does not exist" {
            $testPath = "C:\ADOpsKit\Reports\Get-InsecureLDAPBinds-Test-$(Get-Random)"
            try {
                Get-InsecureLDAPBinds -OutputPath $testPath -Hours 1
                $testPath | Should -Exist
            } finally {
                if (Test-Path $testPath) { Remove-Item $testPath -Recurse -Force }
            }
        }
    }
}
