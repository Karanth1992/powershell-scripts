Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-DCDecommissionReadiness" {

    Context "Parameter defaults and requirements" {

        It "Should require -DCName" {
            (Get-Command Get-DCDecommissionReadiness).Parameters['DCName'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory | Should -Contain $true
        }

        It "Should default DaysBack to 7" {
            $ast   = (Get-Command Get-DCDecommissionReadiness).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'DaysBack' }
            $param.DefaultValue.ToString() | Should -Be '7'
        }

        It "Should default OutputPath to C:\ADOpsKit\Reports\Get-DCDecommissionReadiness" {
            $ast   = (Get-Command Get-DCDecommissionReadiness).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-DCDecommissionReadiness'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outputPath = Join-Path $TestDrive 'decomm'
            $adDomain = (Get-ADDomain).DNSRoot
            $dc = (Get-ADDomainController -Filter * -Server $adDomain | Select-Object -First 1).HostName
            $script:result = Get-DCDecommissionReadiness -DCName $dc -DaysBack 1 -OutputPath $script:outputPath
        }

        It "Should throw for an unreachable DC name without hanging" {
            { Get-DCDecommissionReadiness -DCName 'NONEXISTENT-DC-12345' -OutputPath $TestDrive } |
                Should -Throw '*Cannot reach*'
        }

        It "Should return a result object with the expected sections" {
            $script:result.BasicInfo | Should -Not -BeNullOrEmpty
            $script:result.FSMO | Should -Not -BeNullOrEmpty
            $script:result.GlobalCatalog | Should -Not -BeNullOrEmpty
        }

        It "Should write an HTML report file" {
            Get-ChildItem $script:outputPath -Filter '*.html' | Should -Not -BeNullOrEmpty
        }
    }
}
