# Changelog

All notable changes to this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
