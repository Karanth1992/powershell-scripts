# Active Directory PowerShell Scripts

PowerShell tools and reference material for Active Directory administration, reporting, health checks, GPO inventory, domain-controller diagnostics, and LDAP security review.

These scripts are intended for AD administrators, infrastructure engineers, and service desk escalation teams who need practical, repeatable checks for domain-controller health and directory operations.

## Contents

| File | Purpose | Output |
| --- | --- | --- |
| [AD-PowerShell-Cheatsheet.md](AD-PowerShell-Cheatsheet.md) | Quick Active Directory PowerShell command reference for admins and service desk engineers. | Markdown reference guide |
| [Get-ADArchitectureAssessment.ps1](Get-ADArchitectureAssessment.ps1) | Builds a broad AD architecture inventory and issue report covering domains, forest, DCs, users, computers, groups, OUs, sites, replication, GPOs, ports, and services. | HTML, JSON, and CSV reports |
| [Get-ADForestHealth.ps1](Get-ADForestHealth.ps1) | Generates a forest-wide health report for domain controllers, including DCDiag tests, disk, CPU, memory, and uptime. | Color-coded HTML report |
| [Get-AccountLockoutReport.ps1](Get-AccountLockoutReport.ps1) | Reports currently locked AD accounts and attempts to identify source computers from Security Event ID 4740 on the PDC Emulator. | TXT, CSV, and HTML reports |
| [Get-GPOInventory.ps1](Get-GPOInventory.ps1) | Inventories GPOs, links, permissions, status, timestamps, and WMI filters for a domain. | Styled HTML report |
| [Get-GPOInventoryWithSettings-DC.ps1](Get-GPOInventoryWithSettings-DC.ps1) | Extended GPO inventory that also reads configured settings from `Get-GPOReport` XML. | Styled HTML report, optional raw GPO XML |
| [Get-InsecureLDAPBinds.ps1](Get-InsecureLDAPBinds.ps1) | Detects unsigned and simple LDAP binds by reading Directory Service Event ID 2889 across domain controllers. | Dated CSV report |
| [Test-DCPortHealth.ps1](Test-DCPortHealth.ps1) | Tests critical AD-related TCP ports across all domain controllers. | Console table, optional CSV |
| [Enable-DCPerformanceBaseline.ps1](Enable-DCPerformanceBaseline.ps1) | Creates and starts a domain-controller performance baseline Data Collector Set using `logman`. | Local binary performance logs on each DC |

## Requirements

- Windows PowerShell 5.1 unless a script states otherwise.
- Active Directory PowerShell module.
- Group Policy PowerShell module for GPO inventory scripts.
- Administrative privileges appropriate to the target domain controllers.
- Network access to domain controllers for LDAP, RPC, SMB, WMI/DCOM, or WinRM depending on the script.
- Read access to relevant event logs when collecting lockout or LDAP bind evidence.

Run PowerShell as Administrator before executing scripts that query domain controllers or remote event logs.

```powershell
Import-Module ActiveDirectory
Import-Module GroupPolicy
```

## Quick Start

Clone the repository and move into the Active Directory folder:

```powershell
git clone https://github.com/Karanth1992/powershell-scripts.git
cd .\powershell-scripts\active-directory
```

Run a read-only health or inventory script:

```powershell
.\Test-DCPortHealth.ps1 -TimeoutSeconds 5 -ExportPath "C:\temp\DCPortHealth.csv"

.\Get-GPOInventory.ps1 -DomainName "corp.contoso.com" -OutputPath "C:\temp\GPOInventory.html"

.\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com" -OutputFolder "C:\temp\ADAssessment"
```

## Script Examples

### Active Directory Architecture Assessment

```powershell
.\Get-ADArchitectureAssessment.ps1
.\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com"
.\Get-ADArchitectureAssessment.ps1 -DomainName "corp.contoso.com" -DomainController "DC01.corp.contoso.com"
.\Get-ADArchitectureAssessment.ps1 -OutputFolder "D:\Reports\ADAssessment" -StaleUserDays 120 -StaleComputerDays 120
```

Use `-SkipPortChecks` or `-SkipServiceChecks` when network or WMI/DCOM access is restricted.

### Forest Health Report

```powershell
.\Get-ADForestHealth.ps1
```

Review and update the output folder and optional email settings inside the script before using it in production.

### Account Lockout Report

```powershell
.\Get-AccountLockoutReport.ps1
.\Get-AccountLockoutReport.ps1 -TempPath "D:\temp" -SharedPath "\\fileserver\Reports\Lockouts" -LookbackMilliseconds 86400000
```

The script checks locked accounts and searches Event ID 4740 on the PDC Emulator to identify likely source computers.

### GPO Inventory

```powershell
.\Get-GPOInventory.ps1 -DomainName "corp.contoso.com"
.\Get-GPOInventory.ps1 -DomainName "corp.contoso.com" -OutputPath "D:\Reports\GPOInventory.html"
```

For a deeper inventory that includes configured settings:

```powershell
.\Get-GPOInventoryWithSettings-DC.ps1 -DomainName "corp.contoso.com"
.\Get-GPOInventoryWithSettings-DC.ps1 -DomainName "corp.contoso.com" -DomainController "DC01.corp.contoso.com"
.\Get-GPOInventoryWithSettings-DC.ps1 -DomainName "corp.contoso.com" -SaveGpoReportXmlFolder "C:\temp\GPOXml"
```

### Insecure LDAP Bind Review

```powershell
.\Get-InsecureLDAPBinds.ps1
.\Get-InsecureLDAPBinds.ps1 -Hours 72
```

This script reads Directory Service Event ID 2889 and is useful before enforcing LDAP signing policies.

### Domain Controller Port Health

```powershell
.\Test-DCPortHealth.ps1
.\Test-DCPortHealth.ps1 -TimeoutSeconds 5 -ExportPath "C:\temp\DCPortHealth.csv"
```

The default port list includes Kerberos, DNS, RPC, LDAP, SMB, LDAPS, Global Catalog, and RDP.

### Domain Controller Performance Baseline

```powershell
.\Enable-DCPerformanceBaseline.ps1
```

This script creates a `logman` Data Collector Set named `DC_Baseline_Monitoring` on each domain controller and stores logs under:

```text
C:\PerfLogs\DC_Baseline\
```

## Safety Notes

- Review each script before running it in production.
- Test in a lab or pilot domain before broad deployment.
- Confirm output paths, shared paths, and email settings before scheduled use.
- The inventory and reporting scripts are designed for read-only assessment unless noted otherwise.
- `Enable-DCPerformanceBaseline.ps1` creates and starts a Data Collector Set on domain controllers.
- Port checks are TCP reachability checks, not a full vulnerability scan.
- GPO setting inventory does not calculate Resultant Set of Policy for a specific user or computer.

## Troubleshooting

If a script fails, check the most common causes first:

- PowerShell was not started as Administrator.
- ActiveDirectory or GroupPolicy module is missing.
- The account does not have permission to query AD, GPOs, remote event logs, or WMI/DCOM.
- Firewall rules block RPC, SMB, LDAP, WinRM, or required AD ports.
- Output folders or network shares do not exist or are not writable.
- The selected domain controller is unavailable or cannot be resolved by DNS.

## Disclaimer

Use these scripts at your own risk. They are provided as operational examples and should be reviewed, tested, and adjusted for your environment before production use.
