Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-GPOInventoryWithSettings" {

    Context "Parameter defaults and requirements" {

        It "Should require -DomainName" {
            (Get-Command Get-GPOInventoryWithSettings).Parameters['DomainName'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory | Should -Contain $true
        }

        It "Should default OutputPath under C:\ADOpsKit\Reports\Get-GPOInventoryWithSettings" {
            $ast   = (Get-Command Get-GPOInventoryWithSettings).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-GPOInventoryWithSettings'
        }

        It "Should not require -DomainController" {
            (Get-Command Get-GPOInventoryWithSettings).Parameters['DomainController'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory | Should -Not -Contain $true
        }

        It "Should not require -SaveGpoReportXmlFolder" {
            (Get-Command Get-GPOInventoryWithSettings).Parameters['SaveGpoReportXmlFolder'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory | Should -Not -Contain $true
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outputPath = Join-Path $TestDrive 'gpo-inventory-settings.html'
            Get-GPOInventoryWithSettings -DomainName (Get-ADDomain).DNSRoot -OutputPath $script:outputPath
        }

        It "Should write an HTML report file" {
            $script:outputPath | Should -Exist
        }

        It "HTML report should reference configured settings" {
            $content = Get-Content $script:outputPath -Raw
            $content | Should -Match 'ConfiguredSettings|Configured Settings'
        }
    }
}
