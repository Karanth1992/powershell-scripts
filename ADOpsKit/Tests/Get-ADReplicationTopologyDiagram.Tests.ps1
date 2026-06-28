BeforeAll {
    Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force
}

Describe "Get-ADReplicationTopologyDiagram" {

    Context "Parameter defaults" {

        It "Should default OutputPath to C:\ADOpsKit\Reports\Get-ADReplicationTopologyDiagram\" {
            $ast   = (Get-Command Get-ADReplicationTopologyDiagram).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-ADReplicationTopologyDiagram'
        }

        It "Default OutputPath filename should include a date format expression" {
            $ast   = (Get-Command Get-ADReplicationTopologyDiagram).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
            $param.DefaultValue.ToString() | Should -Match 'yyyy-MM-dd'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            $script:outPath = "C:\ADOpsKit\Reports\Get-ADReplicationTopologyDiagram\$(Get-Date -Format 'yyyy-MM-dd')_ADReplicationTopology.html"
            Get-ADReplicationTopologyDiagram -OutputPath $script:outPath
        }

        It "Should create the output HTML file" {
            $script:outPath | Should -Exist
        }

        It "HTML should contain an SVG element" {
            $content = Get-Content $script:outPath -Raw
            $content | Should -Match '<svg'
        }

        It "HTML should list at least one domain controller" {
            $content = Get-Content $script:outPath -Raw
            $content | Should -Match 'Domain Controller'
        }

        It "HTML should contain replication link data" {
            $content = Get-Content $script:outPath -Raw
            $content | Should -Match 'Replication'
        }
    }
}
