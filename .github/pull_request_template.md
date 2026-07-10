## What this changes

<!-- One or two sentences on what changed and why. -->

## Checklist

- [ ] `Invoke-ScriptAnalyzer -Path ./ADOpsKit -Recurse -Severity Warning,Error -Settings .pssa.psd1` is clean
- [ ] Pester tests added/updated for any new or changed public function, and pass with `-ExcludeTag Integration`
- [ ] Comment-based help updated (`.SYNOPSIS`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`) if parameters or behavior changed
- [ ] `CHANGELOG.md` entry added under `## ADOpsKit Module` if this is user-visible
- [ ] No internal server names, domains, share paths, usernames, or credentials in code or examples
- [ ] `ModuleVersion` in `ADOpsKit.psd1` left untouched (bumped separately at release time — see [WORKFLOW.md](../WORKFLOW.md))

## Testing performed

<!-- What you actually ran this against — lab domain, single DC, multi-domain forest, etc.
     Note anything you could NOT test (e.g. no Entra Connect server available). -->
