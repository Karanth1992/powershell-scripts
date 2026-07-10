Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-ADArchitectureAssessment" {

    Context "Parameter defaults" {

        It "Should default OutputFolder to C:\ADOpsKit\Reports\Get-ADArchitectureAssessment" {
            $ast   = (Get-Command Get-ADArchitectureAssessment).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputFolder' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-ADArchitectureAssessment'
        }

        It "Should default StaleUserDays to 90" {
            $ast   = (Get-Command Get-ADArchitectureAssessment).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'StaleUserDays' }
            $param.DefaultValue.ToString() | Should -Be '90'
        }

        It "Should default StaleComputerDays to 90" {
            $ast   = (Get-Command Get-ADArchitectureAssessment).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'StaleComputerDays' }
            $param.DefaultValue.ToString() | Should -Be '90'
        }

        It "Should default PortTimeoutMs to 1000" {
            $ast   = (Get-Command Get-ADArchitectureAssessment).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'PortTimeoutMs' }
            $param.DefaultValue.ToString() | Should -Be '1000'
        }

        It "Should default TcpPortsToTest to the standard AD/DNS/LDAP/Kerberos/WSUS port set" {
            $ast   = (Get-Command Get-ADArchitectureAssessment).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TcpPortsToTest' }
            $param.DefaultValue.ToString() | Should -Match '53.*88.*135.*139.*389.*445.*464.*636.*3268.*3269.*5985.*5986.*8530.*8531.*9389'
        }
    }

    Context "Parameter validation" {

        It "Should reject StaleUserDays outside 1-3650" {
            { Get-ADArchitectureAssessment -StaleUserDays 0 -SkipPortChecks -SkipServiceChecks } |
                Should -Throw
        }

        It "Should reject PortTimeoutMs below 100" {
            { Get-ADArchitectureAssessment -PortTimeoutMs 50 -SkipPortChecks -SkipServiceChecks } |
                Should -Throw
        }

        It "Should reject TcpPortsToTest values outside 1-65535" {
            { Get-ADArchitectureAssessment -TcpPortsToTest @(70000) -SkipPortChecks -SkipServiceChecks } |
                Should -Throw
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outputFolder = Join-Path $TestDrive 'ad-arch-assessment'
            Get-ADArchitectureAssessment -OutputFolder $script:outputFolder -SkipPortChecks -SkipServiceChecks
        }

        It "Should create the output folder" {
            $script:outputFolder | Should -Exist
        }

        It "Should write an HTML report file" {
            Get-ChildItem $script:outputFolder -Filter '*.html' | Should -Not -BeNullOrEmpty
        }

        It "Should write a JSON report file" {
            Get-ChildItem $script:outputFolder -Filter '*.json' | Should -Not -BeNullOrEmpty
        }
    }
}
