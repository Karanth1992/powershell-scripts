# Contributing to ADOpsKit

Thanks for considering a contribution. This repo is maintained solo, so keeping
changes small, tested, and consistent with the existing style makes review fast.

## Before you start

- For anything beyond a small fix, open an issue first describing the problem
  or feature so we can agree on approach before you write code.
- Check [WORKFLOW.md](WORKFLOW.md) for how the module, scheduled tasks, and
  CI/CD pipeline fit together.

## Coding standards

Every script and function in this repo follows the same baseline:

- `Set-StrictMode -Version Latest`, `[CmdletBinding()]`, typed `param()` blocks
  with validation attributes (`[ValidateRange()]`, `[ValidateSet()]`, etc.)
  where appropriate.
- No aliases — full cmdlet names (`Where-Object`, not `?` or `where`).
- No PowerShell remoting / WinRM dependency. Remote AD/DC collection uses
  `Get-WmiObject` (WMI/DCOM), LDAP, or the `ActiveDirectory`/`GroupPolicy`
  modules — not `Invoke-Command`.
- Comment-based help on every function: `.SYNOPSIS`, `.DESCRIPTION`, one
  `.PARAMETER` per parameter, at least one `.EXAMPLE`, and `.NOTES` stating
  whether the function is read-only or makes changes, required modules, and
  required permissions.
- Functions that change systems support `-WhatIf` / `-Confirm`
  (`SupportsShouldProcess`).
- Report-generating functions default their output path under
  `C:\ADOpsKit\Reports\<FunctionName>` and accept an override parameter.
- New public functions go in `ADOpsKit/Public/`, shared helpers in
  `ADOpsKit/Private/Helpers.ps1`.

Read an existing function (e.g. [`Get-ADForestHealth.ps1`](ADOpsKit/Public/Get-ADForestHealth.ps1))
as the canonical reference for structure before writing a new one.

## Tests

- Every public function needs a corresponding file in `ADOpsKit/Tests/`.
- Parameter defaults and validation attributes (`ValidateRange`, `Mandatory`,
  etc.) are tested directly — these fail at parameter-binding time, before
  any AD/network call, so they're safe to run anywhere.
- Anything that requires real domain/Entra Connect/Task Scheduler
  connectivity goes in a `Context` tagged `-Tag 'Integration'`. CI excludes
  this tag; it's meant to be run manually against a real environment.
- Don't write a live-invocation test for a function that's interactive,
  requires elevation, or makes an irreversible/broad change (e.g.
  `Register-ADOpsKitScheduledTasks`, `Enable-DCPerformanceBaseline`) —
  stick to static/parameter-level checks for those.

Run the suite locally before opening a PR:

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Import-Module Pester -MinimumVersion 5.0
$config = New-PesterConfiguration
$config.Run.Path          = './ADOpsKit/Tests'
$config.Filter.ExcludeTag = 'Integration'
Invoke-Pester -Configuration $config
```

## Linting

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path ./ADOpsKit -Recurse -Severity Warning,Error -Settings .pssa.psd1
```

CI runs both PSScriptAnalyzer and Pester (`Integration` tag excluded) on every
push and pull request to `main`. Both must be clean before merge.

## Pull requests

- Keep PRs scoped to one function or one fix — don't bundle unrelated changes.
- Update `CHANGELOG.md` under the `## ADOpsKit Module` section if the change
  is user-visible.
- Don't bump `ModuleVersion` in your PR — that happens as a separate step
  right before a release (see [WORKFLOW.md §6](WORKFLOW.md#6--ci--cd-pipeline)).
- Remove any internal server names, domains, share paths, usernames, or
  organization-specific values from example code.

## Reporting bugs / security issues

Functional bugs: open a GitHub issue. Security vulnerabilities: see
[SECURITY.md](SECURITY.md) — please don't file those as public issues.
