BeforeAll {
    Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force
}

Describe "Test-DCPortHealth" {

    Context "Parameter defaults" {

        It "Should default ExportPath to C:\ADOpsKit\Reports\Test-DCPortHealth\" {
            $ast   = (Get-Command Test-DCPortHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ExportPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Test-DCPortHealth'
        }

        It "Should default TimeoutSeconds to 3" {
            $ast   = (Get-Command Test-DCPortHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TimeoutSeconds' }
            $param.DefaultValue.ToString() | Should -Be '3'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        It "Should create the output CSV file" {
            $outPath = "C:\ADOpsKit\Reports\Test-DCPortHealth\$(Get-Date -Format 'yyyy-MM-dd')_DCPortHealth.csv"
            Test-DCPortHealth
            $outPath | Should -Exist
        }

        It "Should return results with a Service column that is never null" {
            $csv = Import-Csv "C:\ADOpsKit\Reports\Test-DCPortHealth\$(Get-Date -Format 'yyyy-MM-dd')_DCPortHealth.csv"
            $csv | ForEach-Object {
                $_.Service | Should -Not -BeNullOrEmpty
            }
        }

        It "Should report results for port 389 (LDAP)" {
            $csv = Import-Csv "C:\ADOpsKit\Reports\Test-DCPortHealth\$(Get-Date -Format 'yyyy-MM-dd')_DCPortHealth.csv"
            $ldap = $csv | Where-Object { $_.Port -eq '389' }
            $ldap | Should -Not -BeNullOrEmpty
        }

        It "Should report results for port 88 (Kerberos)" {
            $csv = Import-Csv "C:\ADOpsKit\Reports\Test-DCPortHealth\$(Get-Date -Format 'yyyy-MM-dd')_DCPortHealth.csv"
            $kerb = $csv | Where-Object { $_.Port -eq '88' }
            $kerb | Should -Not -BeNullOrEmpty
        }

        It "Should have at least one DC in results" {
            $csv = Import-Csv "C:\ADOpsKit\Reports\Test-DCPortHealth\$(Get-Date -Format 'yyyy-MM-dd')_DCPortHealth.csv"
            ($csv | Select-Object -ExpandProperty DomainController -Unique).Count | Should -BeGreaterThan 0
        }
    }
}
