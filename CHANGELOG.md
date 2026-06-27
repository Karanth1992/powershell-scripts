# Changelog

All notable changes to this repository are documented here.

## [1.2.0] – 2026-06-27

### Added
- `azure-ad/Get-EntraConnectSyncStatus.ps1` — Entra Connect (Azure AD Connect) sync health checker covering connector status, pending exports, password sync, and last sync cycle.
- Sub-folder structure inside `active-directory/`: `health/`, `audit/`, `inventory/`, `reference/`.
- PSScriptAnalyzer GitHub Actions CI workflow (`.github/workflows/pssa.yml`).
- `.editorconfig` and `.gitattributes` for consistent encoding and line endings.

### Changed
- Reorganised `active-directory/` scripts into logical sub-folders.

## [1.1.0] – 2026-05-01

### Added
- `Get-GPOInventoryWithSettings-DC.ps1` — extended GPO inventory that parses configured settings from `Get-GPOReport` XML.
- `Get-ADArchitectureAssessment.ps1` — broad AD architecture inventory covering domains, DCs, users, computers, groups, OUs, sites, replication, GPOs, ports, and services.

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
