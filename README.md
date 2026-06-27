# PowerShell Scripts — Active Directory & Hybrid Identity

[![PSScriptAnalyzer](https://github.com/Karanth1992/powershell-scripts/actions/workflows/pssa.yml/badge.svg)](https://github.com/Karanth1992/powershell-scripts/actions/workflows/pssa.yml)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/platform-Windows%20Server-lightgrey)

PowerShell automation tools for Active Directory administration, Hybrid Identity (Entra Connect), GPO management, DC health checks, and security auditing.

Detailed write-ups and walkthroughs for these scripts are published at **[karanth.ovh](https://karanth.ovh)**.

---

## Repository Structure

```
powershell-scripts/
├── active-directory/
│   ├── health/        → DC health, port tests, performance baseline
│   ├── audit/         → LDAP security, account lockouts
│   ├── inventory/     → AD architecture, GPO inventory
│   └── reference/     → PowerShell cheat sheet
└── azure-ad/          → Entra Connect / Hybrid Identity
```

---

## active-directory/health

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-ADForestHealth.ps1](active-directory/health/Get-ADForestHealth.ps1) | Forest-wide DC health report — DCDiag, disk, CPU, memory, uptime. | Color-coded HTML |
| [Test-DCPortHealth.ps1](active-directory/health/Test-DCPortHealth.ps1) | Tests critical AD TCP ports across all domain controllers. | Console table, CSV |
| [Enable-DCPerformanceBaseline.ps1](active-directory/health/Enable-DCPerformanceBaseline.ps1) | Deploys a `logman` performance Data Collector Set on each DC. | Binary perf logs on each DC |

## active-directory/audit

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-InsecureLDAPBinds.ps1](active-directory/audit/Get-InsecureLDAPBinds.ps1) | Detects unsigned and simple LDAP binds via Event ID 2889. | Dated CSV |
| [Get-AccountLockoutReport.ps1](active-directory/audit/Get-AccountLockoutReport.ps1) | Reports locked accounts and traces lockout source via Event ID 4740. | TXT, CSV, HTML |

## active-directory/inventory

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-ADArchitectureAssessment.ps1](active-directory/inventory/Get-ADArchitectureAssessment.ps1) | Broad AD inventory — domains, DCs, users, computers, OUs, sites, replication, GPOs, ports, services. | HTML, JSON, CSV |
| [Get-GPOInventory.ps1](active-directory/inventory/Get-GPOInventory.ps1) | GPO inventory with links, permissions, status, and WMI filters. | Styled HTML |
| [Get-GPOInventoryWithSettings-DC.ps1](active-directory/inventory/Get-GPOInventoryWithSettings-DC.ps1) | Extended GPO inventory including configured settings from `Get-GPOReport` XML. | Styled HTML, optional raw XML |

## active-directory/reference

| File | Purpose |
|------|---------|
| [AD-PowerShell-Cheatsheet.md](active-directory/reference/AD-PowerShell-Cheatsheet.md) | Quick Active Directory PowerShell command reference. |

## azure-ad

| Script | Purpose | Output |
|--------|---------|--------|
| [Get-EntraConnectSyncStatus.ps1](azure-ad/Get-EntraConnectSyncStatus.ps1) | Entra Connect health check — sync cycle, connector errors, pending exports, password sync, staging mode. | Console summary, CSV |

---

## Requirements

- Windows PowerShell 5.1 or later.
- Active Directory PowerShell module (`RSAT-AD-PowerShell`).
- Group Policy module for GPO inventory scripts.
- ADSync module (installed with Entra Connect) for `azure-ad/` scripts.
- Administrative rights appropriate for the target environment.

```powershell
Import-Module ActiveDirectory
Import-Module GroupPolicy
```

---

## Quick Start

```powershell
git clone https://github.com/Karanth1992/powershell-scripts.git
cd .\powershell-scripts
```

Run a read-only health or inventory script:

```powershell
# DC port health
.\active-directory\health\Test-DCPortHealth.ps1 -TimeoutSeconds 5 -ExportPath "C:\temp\DCPortHealth.csv"

# Forest health report
.\active-directory\health\Get-ADForestHealth.ps1

# GPO inventory
.\active-directory\inventory\Get-GPOInventory.ps1 -DomainName "corp.contoso.com" -OutputPath "C:\temp\GPOInventory.html"

# Full AD architecture assessment
.\active-directory\inventory\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com" -OutputFolder "C:\temp\ADAssessment"

# Entra Connect sync status (run on or against the Entra Connect server)
.\azure-ad\Get-EntraConnectSyncStatus.ps1 -ComputerName "AADCONN01" -ExportPath "C:\temp\sync.csv"
```

---

## Safety Notes

- Review each script before running in production.
- Test in a lab or pilot domain first.
- All Active Directory scripts are read-only unless explicitly noted.
- `Enable-DCPerformanceBaseline.ps1` creates a Data Collector Set on domain controllers.
- Port checks are TCP reachability tests only — not a vulnerability scan.
- GPO setting inventory does not calculate RSOP for specific users or computers.

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

## Disclaimer

Use these scripts at your own risk. Provided as operational examples — review, test, and adjust for your environment before production use.
