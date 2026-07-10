---
name: Bug report
about: Report unexpected behavior in an ADOpsKit function or standalone script
title: "[Bug] "
labels: bug
assignees: ''
---

## Function / script

Which function or script? (e.g. `Get-ADForestHealth`, `standalone/active-directory/health/Test-DCPortHealth.ps1`)

## Module version

Output of `(Get-Module ADOpsKit -ListAvailable).Version` or the script version from `.NOTES`.

## Environment

- PowerShell version: `$PSVersionTable.PSVersion`
- OS: (e.g. Windows Server 2022)
- Single domain / multi-domain forest:
- Run as: (Domain Admin, delegated account, local Administrator, gMSA, etc.)

## What happened

A clear description of the actual behavior, including the full error message
and stack trace if there was one.

## What you expected

What should have happened instead.

## Steps to reproduce

```powershell
# Exact command(s) run, with any organization-specific values (domain names,
# server names, share paths) replaced with placeholders like corp.contoso.com
```

## Additional context

Anything else relevant — AD topology quirks, firewall restrictions, recent
changes to the environment, etc.
