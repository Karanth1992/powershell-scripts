Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-GPOInventory" {

    Context "Parameter defaults and requirements" {

        It "Should require -DomainName" {
            (Get-Command Get-GPOInventory).Parameters['DomainName'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                Select-Object -ExpandProperty Mandatory | Should -Contain $true
        }

        It "Should default OutputPath under C:\ADOpsKit\Reports\Get-GPOInventory" {
            $ast   = (Get-Command Get-GPOInventory).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-GPOInventory'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outputPath = Join-Path $TestDrive 'gpo-inventory.html'
            Get-GPOInventory -DomainName (Get-ADDomain).DNSRoot -OutputPath $script:outputPath
        }

        It "Should write an HTML report file" {
            $script:outputPath | Should -Exist
        }

        It "HTML report should contain the GPO inventory table headers" {
            $content = Get-Content $script:outputPath -Raw
            $content | Should -Match 'GPO'
        }
    }
}
