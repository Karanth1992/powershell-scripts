# PowerShell Scripts — Active Directory & Hybrid Identity

[![PSScriptAnalyzer](https://github.com/Karanth1992/powershell-scripts/actions/workflows/pssa.yml/badge.svg)](https://github.com/Karanth1992/powershell-scripts/actions/workflows/pssa.yml)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/platform-Windows%20Server-lightgrey)
[![PSGallery](https://img.shields.io/powershellgallery/v/ADOpsKit?label=PSGallery&logo=powershell)](https://www.powershellgallery.com/packages/ADOpsKit)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/ADOpsKit?label=Downloads)](https://www.powershellgallery.com/packages/ADOpsKit)

PowerShell automation tools for Active Directory administration, Hybrid Identity (Entra Connect), GPO management, DC health checks, and security auditing.

Detailed write-ups and walkthroughs for these scripts are published at **[karanth.ovh](https://karanth.ovh)**.

---

## ADOpsKit Module

All scripts in this repository are also available as the **ADOpsKit** PowerShell module, published to the PowerShell Gallery. Install it with a single command — no cloning required.

```powershell
Install-Module ADOpsKit
```

| Function | Purpose |
|----------|---------|
| `Get-ADReplicationTopologyDiagram` | Self-contained HTML topology diagram — DCs, sites, replication links. No ADWS required. |
| `Get-ADArchitectureAssessment` | Broad AD inventory — domains, DCs, users, computers, OUs, sites, replication, GPOs. |
| `Get-ADForestHealth` | Forest-wide DC health report — DCDiag, disk, CPU, memory, uptime. |
| `Test-DCPortHealth` | Tests critical AD TCP ports across all domain controllers. |
| `Enable-DCPerformanceBaseline` | Deploys a `logman` performance Data Collector Set on each DC. |
| `Get-AccountLockoutReport` | Reports locked accounts and traces lockout source via Event ID 4740. |
| `Get-InsecureLDAPBinds` | Detects unsigned and simple LDAP binds via Event ID 2889. |
| `Get-GPOInventoryWithSettings` | GPO inventory with links, permissions, status, WMI filters, and configured settings from `Get-GPOReport` XML. |
| `Get-EntraConnectSyncStatus` | Entra Connect health — sync cycle, connector errors, pending exports, password sync. |
| `Register-ADOpsKitScheduledTasks` | Interactive wizard to schedule any ADOpsKit function as a Windows Scheduled Task. |
| `Test-ADDCDiagHealth` | Runs the full dcdiag test suite against every DC and emails an alert only on status change or a persistent-failure reminder — a near-real-time monitoring check. |
| `Register-ADDCDiagHealthMonitor` | Registers `Test-ADDCDiagHealth` as a Scheduled Task on a short repeating interval (default 5 min), turning it into a real-time DC monitoring agent. |
| `Invoke-ADRealtimeHeartbeat` | Lightweight per-DC heartbeat (TCP ports, SYSVOL/NETLOGON, required services) designed for 30-60 second polling; alerts via email/Slack only on state change. Complements `Test-ADDCDiagHealth`'s heavier, less-frequent full dcdiag sweep. |
| `Get-DCDecommissionReadiness` | Pre-decommission scan of a single DC — FSMO roles, replication health, logon activity, DNS/SYSVOL/DFSR, sites/subnets, trusts, Global Catalog status, and a readiness checklist. |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **1.4.0** | 2026-07-11 | Added `Invoke-ADRealtimeHeartbeat` (30-60s per-DC heartbeat, state-diffed email/Slack alerting) and `Get-DCDecommissionReadiness` (pre-decommission readiness scan). Removed `Get-GPOInventory` (superseded by `Get-GPOInventoryWithSettings`). Fixed `Get-AccountLockoutReport` producing no output with default params, and two `Register-ADOpsKitScheduledTasks` bugs (unqualified account names, single-day weekly schedules) |
| **1.3.0** | 2026-07-09 | Added `Test-ADDCDiagHealth` (full dcdiag suite, state-diffed alerting) and `Register-ADDCDiagHealthMonitor` (5-minute repeating Scheduled Task) for near-real-time DC monitoring with email alerts on status change |
| **1.2.0** | 2026-07-05 | `Register-ADOpsKitScheduledTasks` overhaul — upfront credential validation (batch logon check), gMSA support, `-ConfigPath` setup replay, `-RetentionDays` report cleanup, Scripts folder ACL restriction, task exit codes, log rotation, `-WhatIf` support, quoting fixes |
| **1.1.6** | 2026-06-29 | Fix `Register-ADOpsKitScheduledTasks` — scripts written to `.ps1` files; dated filenames now expand correctly at runtime |
| **1.1.5** | 2026-06-29 | Fix `Get-AccountLockoutReport` — Int32 overflow on default lookback value; fix Copy-Item errors when no lockouts exist |
| **1.1.4** | 2026-06-29 | `Register-ADOpsKitScheduledTasks` — per-task email recipients; each function can send its report to a different address |
| **1.1.3** | 2026-06-29 | `Register-ADOpsKitScheduledTasks` — email reports as attachments after each run (SMTP, SSL, auth support) |
| **1.1.2** | 2026-06-28 | Fix `Register-ADOpsKitScheduledTasks` — ambiguous parameter set error when registering tasks (`-Principal` and `-Password` conflict on `Register-ScheduledTask`) |
| **1.1.1** | 2026-06-28 | Fix `Test-DCPortHealth` — service names showing as blank due to integer key lookup on ordered hashtable |
| **1.1.0** | 2026-06-28 | All functions default output to `C:\ADOpsKit\Reports\<FunctionName>\` with dated filenames. Added `Register-ADOpsKitScheduledTasks` interactive scheduler wizard. Added `Get-Help about_ADOpsKit` help file |
| **1.0.1** | 2026-06-27 | Initial PSGallery publish — 10 functions, PSScriptAnalyzer CI, `Get-ADReplicationTopologyDiagram` added |

Full changelog: [CHANGELOG.md](CHANGELOG.md)

---

## ADSetupKit Module

**ADSetupKit** is a companion module for provisioning Windows Servers from scratch — network configuration, role installation, DC promotion, domain join, application deployment, and post-provisioning tasks.

It lives in its own repository: **[github.com/Karanth1992/ADSetupKit](https://github.com/Karanth1992/ADSetupKit)**

```powershell
git clone https://github.com/Karanth1992/ADSetupKit.git
Import-Module .\ADSetupKit\ADSetupKit.psd1
Start-ADSKSetupWizard
```

---

## Repository Structure

```
powershell-scripts/
├── ADOpsKit/                  ← AD operations & reporting module (PSGallery)
│   ├── Public/                ← Exported functions
│   ├── Private/               ← Internal helpers
│   ├── Tests/                 ← Pester unit tests
│   ├── en-US/                 ← Module help file
│   ├── ADOpsKit.psd1
│   └── ADOpsKit.psm1
└── standalone/                ← Original standalone scripts
    ├── active-directory/
    │   ├── health/            → DC health, port tests, performance baseline
    │   ├── audit/             → LDAP security, account lockouts
    │   ├── inventory/         → AD architecture, GPO inventory
    │   └── reference/         → PowerShell cheat sheet
    └── azure-ad/              → Entra Connect / Hybrid Identity
```

---

## Standalone Scripts

### active-directory/health

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-ADForestHealth.ps1](standalone/active-directory/health/Get-ADForestHealth.ps1) | Forest-wide DC health report — DCDiag, disk, CPU, memory, uptime. | Color-coded HTML |
| [Test-DCPortHealth.ps1](standalone/active-directory/health/Test-DCPortHealth.ps1) | Tests critical AD TCP ports across all domain controllers. | Console table, CSV |
| [Enable-DCPerformanceBaseline.ps1](standalone/active-directory/health/Enable-DCPerformanceBaseline.ps1) | Deploys a `logman` performance Data Collector Set on each DC. | Binary perf logs on each DC |
| [Invoke-ADRealtimeHeartbeat-v1.1.ps1](standalone/active-directory/health/Invoke-ADRealtimeHeartbeat-v1.1.ps1) | Lightweight per-DC heartbeat (TCP ports, SYSVOL/NETLOGON, required services) for 30-60 second polling; alerts via email/Slack only on state change. | `latest.html` / `latest.json` + dated history |

### active-directory/audit

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-InsecureLDAPBinds.ps1](standalone/active-directory/audit/Get-InsecureLDAPBinds.ps1) | Detects unsigned and simple LDAP binds via Event ID 2889. | Dated CSV |
| [Get-AccountLockoutReport.ps1](standalone/active-directory/audit/Get-AccountLockoutReport.ps1) | Reports locked accounts and traces lockout source via Event ID 4740. | TXT, CSV, HTML |
| [Get-DCDecommissionReadiness.ps1](standalone/active-directory/audit/Get-DCDecommissionReadiness.ps1) | Pre-decommission scan of a single DC — FSMO roles, replication health, logon activity, DNS/SYSVOL/DFSR, sites/subnets, trusts, Global Catalog status, and a readiness checklist. | Styled HTML |

### active-directory/inventory

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-ADArchitectureAssessment.ps1](standalone/active-directory/inventory/Get-ADArchitectureAssessment.ps1) | Broad AD inventory — domains, DCs, users, computers, OUs, sites, replication, GPOs, ports, services. | HTML, JSON, CSV |
| [Get-ADReplicationTopologyDiagram.ps1](standalone/active-directory/inventory/Get-ADReplicationTopologyDiagram.ps1) | AD replication topology diagram using LDAP + repadmin. No ADWS required. | Self-contained HTML |
| [Get-GPOInventory.ps1](standalone/active-directory/inventory/Get-GPOInventory.ps1) | GPO inventory with links, permissions, status, and WMI filters. | Styled HTML |
| [Get-GPOInventoryWithSettings-DC.ps1](standalone/active-directory/inventory/Get-GPOInventoryWithSettings-DC.ps1) | Extended GPO inventory including configured settings from `Get-GPOReport` XML. | Styled HTML |

### active-directory/reference

| File | Purpose |
|------|---------|
| [AD-PowerShell-Cheatsheet.md](standalone/active-directory/reference/AD-PowerShell-Cheatsheet.md) | Quick Active Directory PowerShell command reference. |

### azure-ad

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-EntraConnectSyncStatus.ps1](standalone/azure-ad/Get-EntraConnectSyncStatus.ps1) | Entra Connect health check — sync cycle, connector errors, pending exports, password sync, staging mode. | Console summary, CSV |

---

## Requirements

- Windows PowerShell 5.1 or later.
- Active Directory PowerShell module (`RSAT-AD-PowerShell`).
- Group Policy module for GPO inventory scripts.
- ADSync module (installed with Entra Connect) for `azure-ad/` scripts.
- Administrative rights appropriate for the target environment.

---

## Quick Start

### Via PSGallery (recommended)

```powershell
Install-Module ADOpsKit
Get-ADReplicationTopologyDiagram -OutputPath "C:\temp\topology.html"
Get-ADForestHealth
Test-DCPortHealth -ExportPath "C:\temp\ports.csv"

# Interactive scheduled task setup
Register-ADOpsKitScheduledTasks
```

---

## Default Output Paths

All functions save reports to `C:\ADOpsKit\Reports\<FunctionName>\` by default, with dated filenames:

```
C:\ADOpsKit\Reports\
├── Get-ADForestHealth\
│   └── 2026-06-27_ADForestHealth.html
├── Get-GPOInventoryWithSettings\
│   └── 2026-06-27_GPOInventoryWithSettings.html
├── Test-DCPortHealth\
│   └── 2026-06-27_DCPortHealth.csv
└── Logs\
    └── Get-ADForestHealth.log
```

Override the path on any function using `-OutputPath` or `-OutputFolder`.

---

### Via standalone scripts

```powershell
git clone https://github.com/Karanth1992/powershell-scripts.git
cd .\powershell-scripts

.\standalone\active-directory\health\Test-DCPortHealth.ps1 -TimeoutSeconds 5 -ExportPath "C:\temp\DCPortHealth.csv"
.\standalone\active-directory\health\Get-ADForestHealth.ps1
.\standalone\active-directory\inventory\Get-GPOInventory.ps1 -DomainName "corp.contoso.com"
.\standalone\active-directory\inventory\Get-ADReplicationTopologyDiagram.ps1 -OutputPath "C:\temp\topology.html"
```

---

## Safety Notes

- Review each script before running in production.
- Test in a lab or pilot domain first.
- All Active Directory scripts are read-only unless explicitly noted.
- `Enable-DCPerformanceBaseline.ps1` creates a Data Collector Set on domain controllers.
- Port checks are TCP reachability tests only — not a vulnerability scan.

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Module not found | Run as Administrator; `Install-WindowsFeature RSAT-AD-PowerShell` |
| Access denied on remote DCs | Confirm Domain Admin rights or equivalent delegated permissions |
| WMI failures | Ensure DCOM/WMI firewall exceptions are open; WinRM not required for WMI scripts |
| Empty output / no events | Increase `-Hours` or `-LookbackMilliseconds`; confirm audit policy logs the target event IDs |
| Entra Connect script fails | Must run on the Entra Connect server or have WinRM access to it |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards, testing
requirements, and the pull request checklist.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a
public issue for it.

---

## Author

**K Shankar R Karanth** — Active Directory & Hybrid Identity Engineer  
[karanth.ovh](https://karanth.ovh) · [LinkedIn](https://www.linkedin.com/in/karanth-shankar/)

---

## License

MIT — see [LICENSE](LICENSE).
