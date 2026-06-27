# Changelog

All notable changes to this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## ADOpsKit Module

### [1.1.2] – 2026-06-28

#### Fixed
- `Register-ADOpsKitScheduledTasks` — `AmbiguousParameterSet` error when registering tasks. Root cause: `-Principal` and `-Password` belong to mutually exclusive parameter sets on `Register-ScheduledTask`. Fixed by replacing `New-ScheduledTaskPrincipal` with `-User`, `-Password`, and `-RunLevel` parameters directly on `Register-ScheduledTask`.

### [1.1.1] – 2026-06-28

#### Fixed
- `Test-DCPortHealth` — service names displayed as blank next to each port. Root cause: iterating `.Keys` on an `[ordered]` hashtable with integer keys causes PowerShell to treat the key as a positional index rather than a key lookup, returning `$null`. Fixed by switching to `.GetEnumerator()`.
- PSScriptAnalyzer CI — added `PSAvoidUsingPlainTextForPassword` exclusion for `Register-ADOpsKitScheduledTasks`. The `Register-ScheduledTask` Windows API only accepts plain-text passwords, making `SecureString` not applicable here.

### [1.1.0] – 2026-06-28

#### Added
- All 9 report-generating functions now default output to `C:\ADOpsKit\Reports\<FunctionName>\` with `yyyy-MM-dd_` prefixed filenames. Directories are auto-created on first run.
- `Register-ADOpsKitScheduledTasks` — interactive wizard to schedule any combination of ADOpsKit functions as Windows Scheduled Tasks. Prompts for service account, domain, function selection, frequency (daily/weekly), and run time. Registers tasks under `\ADOpsKit\` in Task Scheduler with transcript logging to `C:\ADOpsKit\Reports\Logs\`.
- `en-US\about_ADOpsKit.help.txt` — module help file accessible via `Get-Help about_ADOpsKit`.

#### Changed
- Override output path on any function using `-OutputPath` or `-OutputFolder`.

### [1.0.1] – 2026-06-27

#### Added
- Initial release to PowerShell Gallery.
- 10 exported functions: `Get-ADReplicationTopologyDiagram`, `Get-ADForestHealth`, `Test-DCPortHealth`, `Get-AccountLockoutReport`, `Get-InsecureLDAPBinds`, `Get-GPOInventory`, `Get-GPOInventoryWithSettings`, `Get-ADArchitectureAssessment`, `Enable-DCPerformanceBaseline`, `Get-EntraConnectSyncStatus`.
- `Private\Helpers.ps1` — shared internal helpers (TCP port test, LDAP searcher, XML escaping).
- PSScriptAnalyzer GitHub Actions CI workflow scoped to `ADOpsKit/`.
- `.pssa.psd1` with justified rule exclusions for AD automation patterns.

---

## Repository

## [2.0.0] – 2026-06-27

### Added
- **ADOpsKit** PowerShell module published to [PowerShell Gallery](https://www.powershellgallery.com/packages/ADOpsKit).
  - All 10 scripts wrapped as exported functions.
  - `Private/Helpers.ps1` — shared internal helpers (LDAP searcher, TCP port test, XML escape).
  - `ADOpsKit.psd1` manifest with PSGallery metadata (tags, LicenseUri, ProjectUri).
- `Get-ADReplicationTopologyDiagram` — self-contained HTML replication topology diagram using LDAP + `repadmin`. No ADWS, no WinRM, no CDN dependency.
- `.pssa.psd1` — PSScriptAnalyzer settings scoped to the module.

### Changed
- Standalone scripts reorganised under `standalone/` folder.
- README updated to lead with ADOpsKit module install instructions.
- PSScriptAnalyzer CI workflow scoped to `ADOpsKit/` only.

## [1.2.0] – 2026-06-01

### Added
- `azure-ad/Get-EntraConnectSyncStatus.ps1` — Entra Connect sync health checker.
- Sub-folder structure inside `active-directory/`: `health/`, `audit/`, `inventory/`, `reference/`.
- PSScriptAnalyzer GitHub Actions CI workflow.
- `.editorconfig` and `.gitattributes` for consistent encoding and line endings.

### Changed
- Reorganised `active-directory/` scripts into logical sub-folders.

## [1.1.0] – 2026-05-01

### Added
- `Get-GPOInventoryWithSettings-DC.ps1` — extended GPO inventory parsing configured settings from `Get-GPOReport` XML.
- `Get-ADArchitectureAssessment.ps1` — broad AD architecture inventory.

## [1.0.0] – 2026-03-01

### Added
- Initial release with six core scripts:
  - `Get-ADForestHealth.ps1`
  - `Test-DCPortHealth.ps1`
  - `Enable-DCPerformanceBaseline.ps1`
  - `Get-InsecureLDAPBinds.ps1`
  - `Get-AccountLockoutReport.ps1`
  - `Get-GPOInventory.ps1`
- `AD-PowerShell-Cheatsheet.md` quick reference guide.
