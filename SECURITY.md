# Security Policy

This repository holds standalone (non-module) PowerShell scripts. If you're
looking for the **ADOpsKit** module's security policy, see
[Karanth1992/ADOpsKit](https://github.com/Karanth1992/ADOpsKit/blob/main/SECURITY.md)
instead.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately using either method:

- **GitHub Private Vulnerability Reporting**: use the "Report a vulnerability"
  button under this repository's Security tab.
- **Email**: skaranth.c@gmail.com — include the affected script, a description
  of the issue, and reproduction steps if possible.

You should get an acknowledgement within a few days.

## Scope Notes

This repository ships PowerShell automation for Active Directory and Entra
Connect administration. Relevant risk areas when reviewing or reporting:

- **Read-only vs. mutating scripts** — most scripts are read-only against
  Active Directory. `Enable-DCPerformanceBaseline.ps1` and
  `New-BulkADUser.ps1` make changes. Each script's `.NOTES` help section
  states which category it falls into.
- **No WinRM dependency** — remote collection uses WMI/DCOM and LDAP, not
  PowerShell remoting, by design. Flag anything that would change this.

Injection, privilege-escalation, and credential-exposure issues are all in
scope even if they require local administrative access to exploit.
