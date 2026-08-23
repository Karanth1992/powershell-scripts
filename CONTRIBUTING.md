# Contributing to powershell-scripts

Thanks for considering a contribution. This repo is maintained solo, so keeping
changes small, tested, and consistent with the existing style makes review fast.

This repo holds standalone (non-module) scripts. If your change is about the
**ADOpsKit** module, it belongs in [Karanth1992/ADOpsKit](https://github.com/Karanth1992/ADOpsKit)
instead.

## Before you start

- For anything beyond a small fix, open an issue first describing the problem
  or feature so we can agree on approach before you write code.

## Coding standards

Every script in this repo follows the same baseline:

- `Set-StrictMode -Version Latest`, `[CmdletBinding()]`, typed `param()` blocks
  with validation attributes (`[ValidateRange()]`, `[ValidateSet()]`, etc.)
  where appropriate.
- No aliases — full cmdlet names (`Where-Object`, not `?` or `where`).
- No PowerShell remoting / WinRM dependency. Remote AD/DC collection uses
  `Get-WmiObject` (WMI/DCOM), LDAP, or the `ActiveDirectory`/`GroupPolicy`
  modules — not `Invoke-Command`.
- Comment-based help on every script: `.SYNOPSIS`, `.DESCRIPTION`, one
  `.PARAMETER` per parameter, at least one `.EXAMPLE`, and `.NOTES` stating
  whether the script is read-only or makes changes, required modules, and
  required permissions.
- Scripts that change systems support `-WhatIf` / `-Confirm`
  (`SupportsShouldProcess`).

Read an existing script (e.g. [`Get-ADForestHealth.ps1`](standalone/active-directory/health/Get-ADForestHealth.ps1))
as the canonical reference for structure before writing a new one.

## Linting

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path ./standalone -Recurse -Severity Warning,Error -Settings .pssa.psd1
```

CI runs PSScriptAnalyzer on every push and pull request to `main`. Must be
clean before merge.

## Pull requests

- Keep PRs scoped to one script or one fix — don't bundle unrelated changes.
- Remove any internal server names, domains, share paths, usernames, or
  organization-specific values from example code.

## Reporting bugs / security issues

Functional bugs: open a GitHub issue. Security vulnerabilities: see
[SECURITY.md](SECURITY.md) — please don't file those as public issues.
