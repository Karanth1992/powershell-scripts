# Security Policy

## Supported Versions

Only the latest published version of the `ADOpsKit` module (see
[PowerShell Gallery](https://www.powershellgallery.com/packages/ADOpsKit)) is
supported. Security fixes are released as a new version, not backported to
older ones.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately using either method:

- **GitHub Private Vulnerability Reporting**: use the "Report a vulnerability"
  button under this repository's Security tab.
- **Email**: skaranth.c@gmail.com — include the affected function/script,
  version, a description of the issue, and reproduction steps if possible.

You should get an acknowledgement within a few days. Once a fix is confirmed,
a new version will be published to the PowerShell Gallery and the fix will be
noted in `CHANGELOG.md`. Please allow time to publish a fix before any public
disclosure.

## Scope Notes

This repository ships PowerShell automation for Active Directory and Entra
Connect administration. Relevant risk areas when reviewing or reporting:

- **Credential handling** — `Register-ADOpsKitScheduledTasks` and
  `Register-ADDCDiagHealthMonitor` validate service-account credentials and
  can embed SMTP credentials in generated task scripts. The generated
  `Scripts` folder ACL is restricted to SYSTEM, Administrators, and the
  service account; saved configuration files never contain passwords.
- **Read-only vs. mutating functions** — most functions are read-only against
  Active Directory. `Enable-DCPerformanceBaseline`,
  `Register-ADOpsKitScheduledTasks`, and `Register-ADDCDiagHealthMonitor` make
  changes; the latter two support `-WhatIf`/`-Confirm`. Each function's
  `.NOTES` help section states which category it falls into.
- **No WinRM dependency** — remote collection uses WMI/DCOM and LDAP, not
  PowerShell remoting, by design. Flag anything that would change this.

Injection, privilege-escalation, and credential-exposure issues are all in
scope even if they require local administrative access to exploit.
