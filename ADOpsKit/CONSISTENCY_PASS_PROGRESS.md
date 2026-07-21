# ADOpsKit Consistency Pass — Progress / Resume Doc

Not committed to git (untracked scratch doc for this work). Delete once the pass is
merged and the team doesn't need it anymore.

## Why this file exists

User asked for a full consistency pass across every script in the module, and asked
that progress be documented in case the session/API runs out mid-way so work can
resume cleanly. This file is the source of truth for what's done, what's left, and
exactly what each remaining item requires. If a new session picks this up: read this
file top to bottom, then run `TaskList` to cross-check status, then continue from the
first `[ ]` item below.

## Standard being converged on

The existing `C:\Github\CLAUDE.md` workspace baseline (already governs the rest of
this module) — nothing new invented:
- `Set-StrictMode -Version Latest` in every script.
- `-LiteralPath` (not `-Path`, not bare positional) for filesystem cmdlets operating
  on a concrete, non-wildcard path.
- `Write-Verbose`/`Write-Warning`/`Write-Error` for real operator feedback (including
  genuine error conditions); `Write-Host` reserved for narrow console-only status
  (banners, interactive wizard prompts/menus, colored progress lines) that isn't
  itself the only place a real failure is ever reported.
- No duplicated logic across scripts — shared helpers belong in `Private/Helpers.ps1`.

## Ground-truth audit (as of this pass, before edits)

### A. Missing `Set-StrictMode -Version Latest` (10 files)
- [x] `Private/Helpers.ps1` — added inside each of the 12 functions individually
      (file is dot-sourced into module scope, so a file-scope StrictMode statement
      would silently affect every Public function too - per-function is the
      lower-blast-radius, convention-matching choice)
- [x] `Public/Enable-DCPerformanceBaseline.ps1`
- [ ] `Public/Get-ADForestHealth.ps1`
- [x] `Public/Get-AccountLockoutReport.ps1`
- [x] `Public/Get-EntraConnectSyncStatus.ps1` — see full note below (item D block
      superseded - this became a real bug-fix pass, not just StrictMode/paths)
- [x] `Public/Get-GPOInventoryWithSettings.ps1` — StrictMode surfaced a REAL bug here
      (not just formality): `Get-XmlElementChildren` and other helpers do
      `return @($collection)`, but an EMPTY collection returned from a function
      collapses to `$null` across the call boundary (PowerShell pipeline-unrolling
      quirk - confirmed via isolated repro, independent of StrictMode). Callers
      that then did `.Count` on the result would previously silently misbehave
      (`$null.Count` == `$null`, falsy) and now threw under StrictMode. Fixed 3
      call sites to wrap with `@()` at the call site too (lines ~419, 256, 300),
      plus one related bug in the SAME function found while fixing this: `$a + $b`
      where both sides are $null gives $null, which `@()` then turns into a
      one-element array (count 1, not 0) - fixed by wrapping each side of the `+`
      individually before concatenating (~line 306). Verified against live lab,
      6/6 tests pass including full 2-GPO collection with settings flattening.
- [ ] `Public/Get-InsecureLDAPBinds.ps1`
- [x] `Public/Register-ADDCDiagHealthMonitor.ps1`
- [x] `Public/Register-ADOpsKitScheduledTasks.ps1` — parse-checked, unit tests pass
      (26/26 across its own + Enable-DCPerformanceBaseline + Register-ADDCDiagHealthMonitor).
      NOTE: this file's interactive wizard branches (credential prompts, menu
      choices) have no Integration-tagged live test coverage, so StrictMode
      exposure there is lower-confidence than the rest of this pass - if a
      StrictMode error surfaces in the wizard later, check here first.
- [x] `Public/Test-DCPortHealth.ps1` — also found+fixed the same null-collapse
      footgun: `$closed = $results | Where-Object {...}` would throw under
      StrictMode in the common case (zero closed ports) once StrictMode was
      added. Fixed with `@()` wrap. Verified live (7/7 tests, real closed ports
      137/138 exercised the non-empty branch too).

Already has it (no action): `Get-ADArchitectureAssessment.ps1`,
`Get-ADReplicationTopologyDiagram.ps1`, `Get-DCDecommissionReadiness.ps1`,
`Invoke-ADRealtimeHeartbeat.ps1`, `Test-ADDCDiagHealth.ps1`.

**Risk note**: adding StrictMode can surface latent uninitialized-variable bugs.
After adding it to each file, parse-check + run that file's Pester tests (including
its `Integration` tag against the live lab) before moving on, same as was done for
`Get-ADArchitectureAssessment.ps1` in the prior session.

### B. `-Path` / bare-positional path args that should be `-LiteralPath`
(filesystem cmdlets: Test-Path, Get-Content, Set-Content, Out-File, Remove-Item,
New-Item, Copy-Item, Export-Csv, Get-Item)

- [ ] `Public/Get-ADArchitectureAssessment.ps1` — 4 sites (`-Path`)
- [ ] `Public/Get-ADForestHealth.ps1` — 2 sites (1 `-Path`, 1 bare positional)
- [ ] `Public/Get-AccountLockoutReport.ps1` — 8 sites (3 `-Path`, 5 bare positional)
- [ ] `Public/Get-GPOInventoryWithSettings.ps1` — 2 sites (`-Path`)
- [ ] `Public/Get-InsecureLDAPBinds.ps1` — 1 site (`-Path`)
- [ ] `Public/Test-DCPortHealth.ps1` — 2 sites (1 `-Path`, 1 bare positional)
- [ ] `Public/Get-ADReplicationTopologyDiagram.ps1` — 1 site (bare positional)
- [ ] `Public/Get-DCDecommissionReadiness.ps1` — 3 sites (bare positional)
- [x] `Public/Get-EntraConnectSyncStatus.ps1` — 1 site (bare positional), fixed
- [ ] `Public/Invoke-ADRealtimeHeartbeat.ps1` — 1 `-Path` site, verify whether it's
      intentionally a wildcard cleanup pattern before changing (check context first)

Already clean (no action): `Enable-DCPerformanceBaseline.ps1`,
`Register-ADDCDiagHealthMonitor.ps1`, `Register-ADOpsKitScheduledTasks.ps1`,
`Test-ADDCDiagHealth.ps1`, `Private/Helpers.ps1`.

### C. Duplicated runspace timeout-wrapper (dedupe into `Private/Helpers.ps1`) - DONE
- [x] Moved canonical version into `Private/Helpers.ps1` as `Invoke-ADOKWithTimeout`
- [x] `Invoke-ADRealtimeHeartbeat.ps1` now calls the shared helper, local copy removed
- [x] `Get-ADArchitectureAssessment.ps1` now calls the shared helper, local copy removed
      (also fixed its 4 `-Path` sites -> `-LiteralPath` while in there, including the
      one that fans out to every `Export-CsvIfData` call site in the file)
- [x] Re-ran both scripts' Integration tests against the live lab - pass, and did an
      extra full live run of Get-ADArchitectureAssessment WITHOUT -SkipPortChecks/
      -SkipServiceChecks (the default test skips them) to actually exercise the
      shared timeout wrapper's WMI code path end to end - succeeded.

### D. Real error conditions reported only via colored `Write-Host` (not `Write-Warning`)
- [ ] `Public/Get-AccountLockoutReport.ps1` — `Write-ProgressInfo ... -Color Red` at
      6 call sites (lines ~89, 127, 149, 191, 221, 228) covers genuine failures
      (email send failure, per-user query error, HTML report error, copy failures).
      Keep the colored console line (it's this script's whole UX), but also emit
      `Write-Warning` at each so failures are capturable/redirectable and consistent
      with every other script in the module.
      Note: the line-127 "Locked out accounts found: N" one is NOT an error — it's
      colored red for visual emphasis on a count, not because it failed. Leave that
      one as Write-Host only.
- [x] `Public/Get-EntraConnectSyncStatus.ps1` — fixed, see the big note above:
      **StrictMode uncovered this function's error/status detection was
      completely non-functional before** (4 property accesses reading fields
      that never existed on the real ADSync objects, always silently $null).
      Verified against the live lab's real ADSync module via .NET reflection
      that the correct field/API is different in each case; fixed all four
      and added a fifth real signal (`Get-ADSyncRunProfileResult`) for last-
      sync-time, which the old code never actually had a working source for.
      After the fix, a live run correctly surfaced a REAL sync issue
      (`Last Sync Result: completed-export-errors`) that the broken version
      could never have reported. 4/4 tests pass. The "ATTENTION" banner is
      now driven by real pending-export counts (`ExportAdds/Updates/Deletes`)
      rather than the nonexistent `ExportErrors` field, with `Write-Warning`
      added alongside per the original plan.

Everything else using `Write-Host` in this module (interactive wizard prompts/menus
in `Register-ADOpsKitScheduledTasks.ps1`, section banners, progress narration) is a
correct use of the CLAUDE.md exception and is explicitly OUT OF SCOPE — do not touch.

## Execution order (mechanical, low risk to high)

1. `Private/Helpers.ps1` — add StrictMode + add shared `Invoke-ADOKWithTimeout`.
2. StrictMode-only files (no B/D work needed): `Enable-DCPerformanceBaseline.ps1`,
   `Register-ADDCDiagHealthMonitor.ps1`, `Register-ADOpsKitScheduledTasks.ps1`.
3. Files needing StrictMode + LiteralPath fixes: `Get-ADForestHealth.ps1`,
   `Get-GPOInventoryWithSettings.ps1`, `Get-InsecureLDAPBinds.ps1`,
   `Test-DCPortHealth.ps1`.
4. `Get-AccountLockoutReport.ps1` — StrictMode + LiteralPath + Write-Warning additions
   (most involved single file).
5. `Get-EntraConnectSyncStatus.ps1` — StrictMode + LiteralPath + Write-Warning.
6. LiteralPath-only fixes on files that already have StrictMode:
   `Get-ADReplicationTopologyDiagram.ps1`, `Get-DCDecommissionReadiness.ps1`.
7. Dedupe pass (item C): `Private/Helpers.ps1` shared function already added in step
   1 — now update `Invoke-ADRealtimeHeartbeat.ps1` and `Get-ADArchitectureAssessment.ps1`
   to use it, including the `Get-ADArchitectureAssessment.ps1` LiteralPath fixes (item B).
8. Full regression: `Import-Module` + `Invoke-ScriptAnalyzer` (0 Error severity) +
   full Pester suite (target: 150/150, same as before this pass — no test count
   change expected since this pass doesn't add/remove functionality).
9. Commit. Delete this file once committed (or leave it — harmless, untracked).

## Final status: ALL DONE, not yet committed

Full regression after every fix in this pass:
- `Import-Module .\ADOpsKit.psd1 -Force` - clean
- `Invoke-ScriptAnalyzer -Recurse -Severity Error` - 0 findings
- Full Pester suite (`.\Tests`) - **150/150 pass**, same count as before this pass
  (no functionality added/removed - StrictMode/LiteralPath/dedupe only, plus the
  incidental real-bug fixes documented above)

Unplanned but real findings this pass surfaced (StrictMode is not just a formality
here - it caught actual bugs that were silently wrong before):
1. `Get-GPOInventoryWithSettings.ps1` - a PowerShell "function returns empty
   collection -> $null across the call boundary" footgun caused `.Count` checks to
   misbehave (or now throw). Fixed 3 call sites + 1 related `$null + $null` bug.
2. `Test-DCPortHealth.ps1` - same footgun on `$closed = $results | Where-Object`.
3. `Get-EntraConnectSyncStatus.ps1` - the big one: **the function's sync-error
   detection was completely non-functional**, reading 4 properties that never
   existed on the real ADSync object types (verified via .NET reflection against
   this lab's actual installed ADSync module). After fixing to the real schema, a
   live run correctly surfaced a genuine issue (`completed-export-errors`) that the
   broken version could never have reported.

Next action: commit. Suggested commit message theme: "Add Set-StrictMode and
-LiteralPath consistently across all scripts; dedupe timeout wrapper; fix real bugs
StrictMode surfaced in Get-GPOInventoryWithSettings, Test-DCPortHealth, and
Get-EntraConnectSyncStatus (broken ADSync property mappings)."

After committing, this file can be deleted - it's an untracked scratch doc.

## How to resume if interrupted

1. Read this file.
2. Run `TaskList` — task IDs mirror the checklist above 1:1, titled
   "Consistency: <short description>".
3. Continue from the first non-`completed` task in execution order (step 1-9 above).
4. After each file edit: parse-check via
   `[System.Management.Automation.PSParser]::Tokenize(...)`, then run that file's
   specific Pester test file (`.\Tests\<Name>.Tests.ps1`) before moving to the next.
5. Do the full regression (step 8) only once, right before the final commit — no
   need to re-run the whole suite after every single file if time-constrained, but
   each touched file's own test file must pass before moving on.
