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
| `Get-GPOInventory` | GPO inventory with links, permissions, status, and WMI filters. |
| `Get-GPOInventoryWithSettings` | Extended GPO inventory including configured settings from `Get-GPOReport` XML. |
| `Get-EntraConnectSyncStatus` | Entra Connect health — sync cycle, connector errors, pending exports, password sync. |
| `Register-ADOpsKitScheduledTasks` | Interactive wizard to schedule any ADOpsKit function as a Windows Scheduled Task. |

---

## Repository Structure

```
powershell-scripts/
├── ADOpsKit/                  ← PowerShell Gallery module
│   ├── Public/                ← Exported functions (one per script)
│   ├── Private/               ← Internal helpers
│   ├── ADOpsKit.psd1          ← Module manifest
│   └── ADOpsKit.psm1          ← Root module
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

### active-directory/audit

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-InsecureLDAPBinds.ps1](standalone/active-directory/audit/Get-InsecureLDAPBinds.ps1) | Detects unsigned and simple LDAP binds via Event ID 2889. | Dated CSV |
| [Get-AccountLockoutReport.ps1](standalone/active-directory/audit/Get-AccountLockoutReport.ps1) | Reports locked accounts and traces lockout source via Event ID 4740. | TXT, CSV, HTML |

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
├── Get-GPOInventory\
│   └── 2026-06-27_GPOInventory.html
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

## Author

**K Shankar R Karanth** — Active Directory & Hybrid Identity Engineer  
[karanth.ovh](https://karanth.ovh) · [LinkedIn](https://www.linkedin.com/in/karanth-shankar/)

---

## License

MIT — see [LICENSE](LICENSE).
