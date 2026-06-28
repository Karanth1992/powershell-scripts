Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-ADForestHealth" {

    Context "Parameter defaults" {

        It "Should default OutputFolder to C:\ADOpsKit\Reports\Get-ADForestHealth" {
            $ast   = (Get-Command Get-ADForestHealth).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputFolder' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-ADForestHealth'
        }
    }

    Context "Integration - requires domain connectivity" -Tag 'Integration' {

        BeforeAll {
            Get-ADForestHealth
            $reportFolder = 'C:\ADOpsKit\Reports\Get-ADForestHealth'
            $script:reportFile = Get-ChildItem $reportFolder -Filter "*.html" |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        }

        It "Should create the output folder" {
            'C:\ADOpsKit\Reports\Get-ADForestHealth' | Should -Exist
        }

        It "Should write an HTML report file" {
            $script:reportFile | Should -Not -BeNullOrEmpty
        }

        It "Report filename should be prefixed with today's date" {
            $script:reportFile.Name | Should -Match "^\d{4}-\d{2}-\d{2}_"
        }

        It "HTML report should contain DC health table headers" {
            $content = Get-Content $script:reportFile.FullName -Raw
            $content | Should -Match 'Connectivity'
            $content | Should -Match 'Replication'
        }

        It "HTML report should reference the forest name" {
            $forestName = (Get-ADForest).Name
            $content    = Get-Content $script:reportFile.FullName -Raw
            $content | Should -Match $forestName
        }
    }
}
