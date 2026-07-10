Import-Module "$PSScriptRoot\..\ADOpsKit.psd1" -Force -ErrorAction Stop

Describe "Get-EntraConnectSyncStatus" {

    Context "Parameter defaults" {

        It "Should default ComputerName to `$env:COMPUTERNAME" {
            $ast   = (Get-Command Get-EntraConnectSyncStatus).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ComputerName' }
            $param.DefaultValue.ToString() | Should -Match 'env:COMPUTERNAME'
        }

        It "Should default ExportPath under C:\ADOpsKit\Reports\Get-EntraConnectSyncStatus" {
            $ast   = (Get-Command Get-EntraConnectSyncStatus).ScriptBlock.Ast
            $param = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ExportPath' }
            $param.DefaultValue.ToString() | Should -Match 'C:\\ADOpsKit\\Reports\\Get-EntraConnectSyncStatus'
        }
    }

    # No unit-level invocation here: whether the ADSync module is present is
    # environment-dependent (it IS installed on real Entra Connect servers),
    # and calling this function queries live ADSync scheduler/connector state.
    # Per workspace rules, that only happens under the Integration tag, and
    # only against machines the caller has explicitly chosen to test against.

    Context "Integration - requires an Entra Connect server with ADSync module" -Tag 'Integration' {

        It "Should not throw when run locally on an Entra Connect server" {
            { Get-EntraConnectSyncStatus -ExportPath '' } | Should -Not -Throw
        }

        It "Should export connector CSV when run on the Entra Connect server" {
            $exportPath = Join-Path $TestDrive 'entraconnect.csv'
            Get-EntraConnectSyncStatus -ExportPath $exportPath
            $exportPath | Should -Exist
        }
    }
}
