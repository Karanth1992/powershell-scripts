Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

# Sourced from the manifest rather than hardcoded so this suite cannot go
# stale when a function is added to FunctionsToExport.
$manifestData = Import-PowerShellDataFile "$PSScriptRoot\..\ADOpsKit.psd1"

Describe "ADOpsKit Module" {

    BeforeAll {
        # Re-fetched here (in addition to the script-scope copy above) because
        # Pester v5 only carries -ForEach data across from Discovery to Run;
        # plain variable references inside It blocks need a BeforeAll copy.
        $script:manifestData = Import-PowerShellDataFile "$PSScriptRoot\..\ADOpsKit.psd1"
    }

    Context "Module loads correctly" {

        It "Should import without errors" {
            { Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force } | Should -Not -Throw
        }

        It "Should be version 1.1.2 or higher" {
            (Get-Module ADOpsKit).Version | Should -BeGreaterOrEqual ([version]'1.1.2')
        }

        It "Should export exactly as many functions as declared in the manifest's FunctionsToExport" {
            (Get-Command -Module ADOpsKit).Count | Should -Be $script:manifestData.FunctionsToExport.Count
        }
    }

    Context "All expected functions are exported" {

        It "Should export <_>" -ForEach $manifestData.FunctionsToExport {
            Get-Command -Module ADOpsKit -Name $_ | Should -Not -BeNullOrEmpty
        }
    }

    Context "Comment-based help is present on all functions" {

        $functions = Get-Command -Module ADOpsKit

        It "<_.Name> should have a Synopsis" -ForEach $functions {
            (Get-Help $_.Name).Synopsis | Should -Not -BeNullOrEmpty
        }

        It "<_.Name> should have a Description" -ForEach $functions {
            (Get-Help $_.Name).Description | Should -Not -BeNullOrEmpty
        }
    }
}
