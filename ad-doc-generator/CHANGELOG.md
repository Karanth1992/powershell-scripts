# Changelog

All notable changes to **ad-doc-generator** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] – 2026-07-24

### Added
- `export/Get-ADTopologyExport.ps1` — read-only Stage 1 export of OU hierarchy, trusts, domain controllers, replication sites/site links, GPO links, and key privileged-group membership to a single timestamped JSON snapshot. No WinRM, no AD writes.
- `normalize/normalize.py` — Stage 2, flattens the raw export into a `{nodes, edges}` graph schema decoupled from AD's native shape.
- `analyze/analyze.py` — Stage 3, sends the normalized schema to the Claude API (`ANTHROPIC_API_KEY` required) and asks for a narrative, an anomaly list, and Mermaid diagram source. See README for the no-API-key alternative.
- `render/render.py` — Stage 4, combines narrative + anomalies + diagram into a single styled HTML report.
- `samples/sample-export.json` — synthetic fake-forest data so the pipeline can be demoed without a live domain or real org data.

### Fixed
- `Get-ADTopologyExport.ps1` — `Get-ADTrust`, `Get-ADDomainController`, `Get-ADOrganizationalUnit`, and `Get-ADReplicationSite`/`SiteLink` results were consumed unwrapped before being counted (`$trusts.Count`, etc.). Under `Set-StrictMode -Version Latest`, an empty result (e.g. a domain with zero trusts) returns `$null`, and referencing `.Count` on `$null` throws `"The property 'Count' cannot be found on this object"` — confirmed live against a single-domain lab with no trusts. All collection results are now wrapped in `@(...)` before being counted.
- `Get-ADTopologyExport.ps1` — the JSON snapshot was written with `Out-File -Encoding utf8`, which in Windows PowerShell 5.1 always prepends a UTF-8 BOM. Python's `json.load` rejects a BOM by default (`Unexpected UTF-8 BOM`), breaking Stage 2 on every real export. Switched to `[System.IO.File]::WriteAllText` with a BOM-less `UTF8Encoding`.

### Notes
- Verified end-to-end (export → normalize → render) against a real domain-joined lab (`Karanth.Lab`), not just synthetic sample data.
