# Changelog

All notable changes to this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## ADSetupKit Module

### [1.0.0] – 2026-06-28

#### Added
- `Start-ADSKSetupWizard` — 7-step interactive wizard: network config, computer rename, application installation, role selection, AD scenario (new forest / replica DC / child domain / member server / standalone), post-restart task scheduling, and a review/confirm step before execution.
- `Set-ADSKNetworkConfig` — Configure static IP, subnet prefix, default gateway, and DNS servers on any network adapter. Cleans existing DHCP-assigned addresses before applying.
- `Rename-ADSKComputer` — Rename the local server. Optional `-Restart` switch for immediate reboot.
- `Install-ADSKApplications` — Sequentially execute numbered `.ps1` and `.bat` installer scripts from a folder. Per-script timeout enforced. Results exported to CSV + log file.
- `Install-ADSKRoles` — Multi-select interactive menu for installing Windows Server roles (ADDS, DNS, DHCP, File, Print, IIS, GPMC, RSAT). Also callable non-interactively via `-Roles`.
- `New-ADSKForest` — Promote server as first DC in a new Active Directory forest using `Install-ADDSForest`.
- `Add-ADSKDomainController` — Add server as a replica DC to an existing domain using `Install-ADDSDomainController`.
- `New-ADSKChildDomain` — Create a new child domain under a parent domain using `Install-ADDSDomain`.
- `Add-ADSKDomainMember` — Join the local server to an existing domain (member server path). Optional OU placement and restart.
- `New-ADSKSite` — Create an AD replication site, associate a subnet, and optionally create a site link to an existing site.
- `New-ADSKDhcpScope` — Create and activate a DHCP scope with gateway (option 3) and DNS (option 6). Authorises the DHCP server in AD.
- `Set-ADSKDnsForwarder` — Replace DNS forwarder list on the local DNS server. Optional root hints toggle.
- `Private\Helpers.ps1` — Shared banner/status output helpers, admin check, single and multi-select menu readers, and `Register-ADSKStartupTask` for scheduling post-restart scripts.
- `en-US\about_ADSetupKit.help.txt` — Module help file covering all functions, wizard flow, and requirements.

---

## ADOpsKit Module

### Unreleased

#### Fixed
- `Get-AccountLockoutReport` — with default parameters, `-TempPath` and `-SharedPath` point at the same folder. The "clear destination before copy" step deleted the report files that had just been generated there, and the `Test-Path` guards around the subsequent `Copy-Item` calls then silently skipped the copy — so the function produced **no output files at all** when run with defaults, regardless of whether any accounts were locked out. Fixed by skipping the clear-then-copy step entirely when `-TempPath` and `-SharedPath` resolve to the same location.

### [1.3.0] – 2026-07-09

#### Added
- `Test-ADDCDiagHealth` — runs the full dcdiag test suite (every `Starting test:` / `passed test` / `failed test` pair, not a fixed subset) against every domain controller. Checks basic reachability (ping + RPC port 135) before running dcdiag so an offline DC is reported immediately instead of hanging. Persists per-DC state to JSON and only emails an alert on a status change (Healthy ↔ Failing/Unreachable) or a reminder after `-RepeatAlertAfterHours` (default 4) of persistent failure — a healthy forest produces no email at all. `-Tests` parameter allows narrowing to a lighter, targeted test list to reduce per-run load; defaults to dcdiag's full set. Read-only against AD; no WinRM.
- `Register-ADDCDiagHealthMonitor` — registers `Test-ADDCDiagHealth` as a Scheduled Task under `\ADOpsKit\` with a repeating trigger (default every 5 minutes), turning it into a near-real-time DC monitoring agent. Defaults to running as SYSTEM (no password to manage); `-RunAsCredential` supported for cross-domain scenarios. Restricts the generated Scripts folder ACL when an SMTP credential is embedded, matching `Register-ADOpsKitScheduledTasks`. Warns (via WMI `DomainRole`, no WinRM) if run on a domain controller itself, since the recurring task would then add continuous polling load to that DC. `-WhatIf` / `-Confirm` supported.

---

### [1.2.0] – 2026-07-05

#### Added
- `Register-ADOpsKitScheduledTasks` — service account credentials are validated up front with a batch logon check (`LogonUser` / `LOGON32_LOGON_BATCH`), verifying both the password and the *Log on as a batch job* right before any prompts are wasted. Distinguishes wrong password, locked out, expired password, disabled account, and missing batch right.
- `Register-ADOpsKitScheduledTasks` — Group Managed Service Account (gMSA) support as a passwordless alternative; verified with `Test-ADServiceAccount` and registered via `New-ScheduledTaskPrincipal`.
- `Register-ADOpsKitScheduledTasks` — `-ConfigPath` parameter replays a previously saved setup (`ADOpsKitTasks.config.json`, saved without passwords after each successful run); only passwords and the final confirmation are prompted.
- `Register-ADOpsKitScheduledTasks` — `-RetentionDays` parameter (default 90, 0 disables): each task deletes its own reports older than the cutoff after each run. Transcript logs rotate to `.log.old` at 10 MB.
- `Register-ADOpsKitScheduledTasks` — generated task scripts exit 0 (success), 1 (function failed), or 2 (email failed) so failures surface as Last Run Result in Task Scheduler.
- `Register-ADOpsKitScheduledTasks` — `-WhatIf` / `-Confirm` honored via `ShouldProcess` for all mutations.

#### Fixed
- `Register-ADOpsKitScheduledTasks` — values embedded in generated task scripts (passwords, addresses, paths, domain) are now quote-escaped; an apostrophe in an SMTP password no longer breaks the generated script.
- `Register-ADOpsKitScheduledTasks` — the "No authentication (relay)" email option generated a broken `PSCredential('')`; the credential is now only emitted when a username was provided.
- `Register-ADOpsKitScheduledTasks` — run-time prompts (`HH:mm`) are validated with a retry loop instead of throwing at `New-ScheduledTaskTrigger`.

#### Security
- `Register-ADOpsKitScheduledTasks` — the `Scripts` folder ACL is restricted to SYSTEM, Administrators, and the service account, since task scripts with SMTP authentication embed the SMTP password.

### [1.1.6] – 2026-06-29

#### Fixed
- `Register-ADOpsKitScheduledTasks` — task scripts are now written to `.ps1` files under `OutputBasePath\Scripts\` and called with `-File` instead of being embedded in a `-Command` string. This eliminates all escaping issues that caused dated filenames and variables to not expand at runtime.
- `Register-ADOpsKitScheduledTasks` — dated output paths now use `$date = Get-Date -Format 'yyyy-MM-dd'` with `${date}_filename` syntax to correctly expand the date variable inside double-quoted strings.

### [1.1.5] – 2026-06-29

#### Fixed
- `Get-AccountLockoutReport` — `LookbackMilliseconds` parameter type changed from `[int]` to `[long]`. The default value of `4233600000` (49 days in milliseconds) exceeded `Int32` max (2,147,483,647), causing a parameter binding error on every run.
- `Get-AccountLockoutReport` — `Copy-Item` errors when no lockout events are found. The function now guards each copy with `Test-Path` so a clean environment (no lockouts) completes silently.

### [1.1.4] – 2026-06-29

#### Changed
- `Register-ADOpsKitScheduledTasks` — email is now configured **per task** instead of globally. Each function can send its report to a different recipient address. SMTP server settings (server, port, SSL, credentials) are prompted once and can be reused for subsequent tasks. The wizard is now 4 steps instead of 5 (schedule and email collected together per function).

### [1.1.3] – 2026-06-29

#### Added
- `Register-ADOpsKitScheduledTasks` — new "Email Reports" step in the wizard. After each scheduled run, the generated report is emailed as an attachment. Supports SMTP server, port, SSL/TLS, From/To addresses, and optional SMTP authentication (username + password). Email failure is non-fatal — the task logs a warning and continues.

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
