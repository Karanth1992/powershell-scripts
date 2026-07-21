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

### [1.5.0] – 2026-07-21

#### Security
- `Get-DCDecommissionReadiness`, `Get-ADReplicationTopologyDiagram`, `Get-ADForestHealth` — HTML reports embedded AD-sourced values (DC names, OS strings, distinguished names, event log text) without HTML-encoding, a stored-injection risk in reports opened by administrators. All three now route every interpolated value through a shared `ConvertTo-ADOKXmlEscaped` helper.
- `Get-AccountLockoutReport` — a locked-out username containing a single quote (e.g. `o'brien`) broke the XPath event-log filter, silently dropping that user's lockout-source data from the report with no indication anything was missing. Fixed with a proper XPath 1.0 string-literal builder (`concat()`-based, since XPath 1.0 has no quote-escape character).
- `Register-ADDCDiagHealthMonitor` — a decrypted run-as credential's unmanaged memory handle (BSTR) was never freed, and a failure to lock down the ACL on the folder holding a DPAPI-encrypted SMTP secret was only a warning, not a hard stop, even though that ACL is the only thing protecting the secret (machine-scoped DPAPI can be decrypted by any local principal). BSTR is now freed in a `finally` block; ACL failure is now fatal when a secret was actually written.
- `Register-ADOpsKitScheduledTasks` — `-WhatIf` still performed a real domain authentication attempt during credential validation, meaning a mistyped password during a dry run counted toward the service account's real AD lockout threshold. `-WhatIf` now skips live authentication entirely.

#### Fixed
- `Get-EntraConnectSyncStatus` — sync-error and status detection was completely non-functional: four property accesses read fields that never exist on the real ADSync object types (`ExportErrors`/`ImportErrors`/`PendingExport*` on `ConnectorStatistics`, `.State` on the value `Get-ADSyncAutoUpgrade` already returns directly, `SyncEnabled` on the scheduler, and `LastSyncRunStartTime`, which doesn't exist there at all), verified via .NET reflection against a live ADSync install. All always silently evaluated to `$null`/blank, so this function could never have reported a real sync problem. Rewrote to the real schema and added a working last-sync-time source via `Get-ADSyncRunProfileResult`; also dropped the hidden `Invoke-Command`/WinRM remote-execution path, which is unsupported in WinRM-blocked environments regardless.
- `Get-ADForestHealth` — silently required WinRM (`Invoke-Command` to each domain's PDC) despite documentation claiming it worked without it, so it failed outright in any WinRM-blocked environment. Every remote call it makes (`Dcdiag.exe /s:`, `Get-WmiObject -ComputerName`) already targets DCs directly and doesn't need PSRemoting, so the function now runs locally with per-domain failure isolation instead.
- `Get-DCDecommissionReadiness` — under strict variable checking, a failed `Get-ADDomainController`/`Get-Service` call left `$DC`/`$dnsService` unset, which then crashed the function before the HTML report was written. Separately, when the FSMO/replication/subnet/Global-Catalog queries failed, the pre-decommission checklist read the missing result key as falsy and printed "OK" instead of flagging that the check never ran. Both fixed; failed checks now report `UNKNOWN`, not a false "OK".
- `Enable-DCPerformanceBaseline` — the `logman create` command was passed to `Win32_Process.Create()` as a single command line built with PowerShell-only backtick line continuations, which `CreateProcess` cannot interpret, and success/failure was inferred from the wrong return code (process-creation status, not logman's own exit code) — so failures were reported as "may already exist" regardless of the real cause. Rewritten to deploy a real `.ps1` script to each DC over SMB and read back logman's actual exit code and console output.
- `Test-ADDCDiagHealth` — a corrupted alert-state record (e.g. from a process killed mid-write) crashed the monitor and, because state was only saved after the full per-DC loop completed, wedged it permanently with no self-recovery. `Invoke-ADRealtimeHeartbeat` had the same non-atomic state-file write and a related issue where one failed email/Slack send skipped saving state for the entire run. Both scripts now write state atomically (temp file + rename) and self-heal on a corrupt file; `Invoke-ADRealtimeHeartbeat` also isolates each notification send so one failure doesn't affect the others or skip the save.
- `Get-GPOInventoryWithSettings`, `Test-DCPortHealth` — a PowerShell footgun where a function returning an empty collection collapses to `$null` across the call boundary (not an empty array) caused several `.Count` checks to misbehave silently before, and to throw once `Set-StrictMode -Version Latest` was added to every script in this release. Fixed at each call site; one related `$null + $null` concatenation bug in `Get-GPOInventoryWithSettings` was also found and fixed while tracing this.

#### Changed
- Added `Set-StrictMode -Version Latest` to every script that was missing it (10 files), and standardized on `-LiteralPath` over `-Path`/bare positional paths for filesystem cmdlets throughout the module.
- Deduplicated a runspace timeout-wrapper helper that had been copy-pasted between `Invoke-ADRealtimeHeartbeat.ps1` and `Get-ADArchitectureAssessment.ps1` into one shared `Invoke-ADOKWithTimeout` in `Private/Helpers.ps1`.
- Hardened the PowerShell Gallery publish workflow to stage a clean copy of only the intended module files before publishing, rather than publishing the working directory verbatim — the 1.4.0 Gallery package accidentally included a stray, untracked `.claude/settings.local.json` local session file that was sitting in the working tree at publish time.

### [1.4.0] – 2026-07-11

#### Added
- `Invoke-ADRealtimeHeartbeat` — promoted from `standalone/active-directory/health/Invoke-ADRealtimeHeartbeat-v1.1.ps1`, which was added earlier but never exported from the module. A lightweight, frequently-schedulable (every 30-60s) heartbeat check per DC — TCP reachability (LDAP, Kerberos, RPC, SMB, DNS by default), SYSVOL/NETLOGON share reachability, and required-service state via WMI/DCOM — complementary to `Test-ADDCDiagHealth`'s heavier, less-frequent full dcdiag sweep. Writes `latest.html`/`latest.json` plus retained dated history, alerts via email and/or Slack only on state change (with a repeat-alert suppression window), and supports `-WhatIf`. Read-only against AD and remote DCs.
- `Get-DCDecommissionReadiness` — promoted from `standalone/active-directory/audit/Get-DCDecommissionReadiness.ps1`, which was likewise never exported from the module. Pre-decommission scan of a single DC: FSMO role holdings, replication health/queue/failures, recent logon activity (top Kerberos TGT requesters), DNS role and hosted zones, SYSVOL/DFSR health, site/subnet associations, Netlogon secure-channel activity, Directory Service event errors, active sessions, trust relationships, Global Catalog status, and a summary checklist of what needs to happen before demotion. Writes an HTML report and returns a structured result object. While promoting: fixed a latent WinRM dependency (`Get-SmbShare -CimSession` implicitly requires WinRM; swapped for a plain UNC path check, matching this module's WMI/DCOM/SMB-only design) and several `Set-StrictMode`-triggered crashes where `.Count` was accessed on a collection that comes back as a bare scalar (not an array) when exactly one event/result is returned — confirmed live against a domain with exactly one DFSR/Netlogon/DirectoryService event, which reliably triggered every one of them. Also removed a stray `#Requires -Modules ActiveDirectory` statement, which PowerShell enforces at dot-source time (not just when the function runs) — since the module's `.psm1` loader dot-sources every file in `Public\` to build the module, this broke `Import-Module ADOpsKit` entirely on any machine without the RSAT ActiveDirectory module installed (e.g. the CI runner), taking every other function down with it. Replaced with a runtime `Import-Module ActiveDirectory -ErrorAction Stop` inside the function body, matching the pattern already used by `Get-ADForestHealth` and `Get-ADArchitectureAssessment`.

#### Fixed
- `Get-AccountLockoutReport` — with default parameters, `-TempPath` and `-SharedPath` point at the same folder. The "clear destination before copy" step deleted the report files that had just been generated there, and the `Test-Path` guards around the subsequent `Copy-Item` calls then silently skipped the copy — so the function produced **no output files at all** when run with defaults, regardless of whether any accounts were locked out. Fixed by skipping the clear-then-copy step entirely when `-TempPath` and `-SharedPath` resolve to the same location.
- `Register-ADOpsKitScheduledTasks` — a service account entered without a `DOMAIN\` prefix or UPN suffix (e.g. `svc-adops` instead of `CONTOSO\svc-adops`) was silently reinterpreted by the batch-logon check as a **local** account instead of the intended domain account, producing a confusing failure (or a false success against an unrelated same-named local account). Now throws immediately with a clear message when the account has no domain qualifier, for both regular and gMSA accounts, and whether entered interactively or loaded via `-ConfigPath`.
- `Register-ADOpsKitScheduledTasks` — weekly schedules only allowed a single day of week to be selected, even though `New-ScheduledTaskTrigger -DaysOfWeek` already supports multiple days. The day-of-week prompt now uses the same multi-select picker used for function selection.

#### Removed
- `Get-GPOInventory` — removed from the module; `Get-GPOInventoryWithSettings` is a superset (same links/permissions/status/WMI-filter data, plus configured settings) so there was no reason to keep both. The standalone script (`standalone/active-directory/inventory/Get-GPOInventory.ps1`) is unaffected.

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
