Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "ADOpsKit Module" {

    Context "Module loads correctly" {

        It "Should import without errors" {
            { Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force } | Should -Not -Throw
        }

        It "Should be version 1.1.2 or higher" {
            (Get-Module ADOpsKit).Version | Should -BeGreaterOrEqual ([version]'1.1.2')
        }

        It "Should export exactly 11 functions" {
            (Get-Command -Module ADOpsKit).Count | Should -Be 11
        }
    }

    Context "All expected functions are exported" {

        $expectedFunctions = @(
            'Get-AccountLockoutReport',
            'Get-InsecureLDAPBinds',
            'Enable-DCPerformanceBaseline',
            'Get-ADForestHealth',
            'Test-DCPortHealth',
            'Get-ADArchitectureAssessment',
            'Get-ADReplicationTopologyDiagram',
            'Get-GPOInventory',
            'Get-GPOInventoryWithSettings',
            'Get-EntraConnectSyncStatus',
            'Register-ADOpsKitScheduledTasks'
        )

        It "Should export <_>" -ForEach $expectedFunctions {
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
