# ad-doc-generator

Turns a snapshot of Active Directory structure into a written architecture
narrative, an anomaly list, and a Mermaid topology diagram — automatically,
from data that changes over time.

Complements [ADOpsKit](https://github.com/Karanth1992/ADOpsKit): ADOpsKit
handles operations and health checks; this handles documentation and drift
visibility.

## Pipeline

| Stage | Location | Language | Purpose |
|---|---|---|---|
| 1. Export | [`export/`](export) | PowerShell 5.1 | Read-only pull of OUs, trusts, DCs/sites, replication topology, GPO links, and key group membership into one JSON snapshot. |
| 2. Normalize | [`normalize/`](normalize) | Python 3.9+ | Flattens the raw export into a `{nodes, edges}` graph schema, decoupled from AD's native shape. |
| 3. Analyze | [`analyze/`](analyze) | Python + Claude API, or manual | Produces a narrative, an anomaly list, and Mermaid diagram source from the normalized schema. Two ways to do this — see below. |
| 4. Render | [`render/`](render) | Python 3.9+ | Combines narrative + anomalies + diagram into a single styled HTML report. |

Sanitized sample data lives in [`samples/`](samples) so the pipeline can be
demoed without any real org data or live AD connection.

See [WORKFLOW.md](WORKFLOW.md) for diagrams of the full pipeline, the
export script's internal collection flow, and the Stage 3 decision between
the scripted and manual analysis paths.

## Requirements

- Windows PowerShell 5.1, `ActiveDirectory` and `GroupPolicy` modules, on a
  domain-joined machine — for Stage 1 only.
- Python 3.9+ for Stages 2 and 4 (standard library only, no extra packages).
- Stage 3 only: `pip install -r requirements.txt` (installs the `anthropic`
  package) and an `ANTHROPIC_API_KEY` — **only if** you use the scripted
  path. See "Stage 3: two ways to run it" below for the alternative.

## Usage

```powershell
# Stage 1 - run on a domain-joined machine with the AD module.
# Defaults to C:\Temp\Reports\ADDocGenerator; override with -OutputFolder.
.\export\Get-ADTopologyExport.ps1 -Verbose
```

```bash
# Stage 2
python normalize/normalize.py C:/Temp/Reports/ADDocGenerator/ADTopologyExport_<timestamp>.json C:/Temp/Reports/ADDocGenerator/normalized.json
```

### Stage 3: two ways to run it

**Option A — scripted, via the Claude API.** Calls the Anthropic Messages API
directly from a standalone script. This is a *separate*, pay-as-you-go API
key from console.anthropic.com — it is not the same thing as, and does not
share quota with, a Claude.ai or Claude Code subscription. Useful for
unattended/scheduled runs where no one is present to do the analysis by hand.

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python analyze/analyze.py C:/Temp/Reports/ADDocGenerator/normalized.json C:/Temp/Reports/ADDocGenerator/analysis.json
```

**Option B — manual, via an assistant you already have open** (e.g. Claude
Code, or pasting `normalized.json` into claude.ai). No API key, no extra
billing. Give the assistant the normalized JSON and ask it to produce a JSON
object shaped like this (matching what `analyze.py`'s system prompt asks
for):

```json
{
  "narrative": "...",
  "anomalies": [{ "severity": "Critical|Warning|Info", "title": "...", "detail": "..." }],
  "documentationGaps": ["..."],
  "mermaidDiagram": "graph TD\n  ..."
}
```

Save that as `analysis.json` and continue to Stage 4.

```bash
# Stage 4 (either option above feeds this the same way)
python render/render.py C:/Temp/Reports/ADDocGenerator/analysis.json C:/Temp/Reports/ADDocGenerator/report.html --title "<Domain> AD Architecture Assessment Report v1.0"
```

### Try it on the bundled sample first

No live AD connection, no API key needed if you use the manual Stage 3 path:

```bash
python normalize/normalize.py samples/sample-export.json samples/sample-normalized.json
# Stage 3: either call analyze.py with an API key, or hand
# samples/sample-normalized.json to an assistant and save its
# reply as samples/sample-analysis.json (a worked example already
# exists there to compare against).
python render/render.py samples/sample-analysis.json samples/sample-report.html
```

## Notes

- Stage 1 is read-only: no AD objects, GPOs, or trusts are modified. No
  WinRM or PowerShell remoting is used — only the `ActiveDirectory` and
  `GroupPolicy` modules over LDAP/ADWS.
- GPO link discovery is scoped to organizational units. Policies linked
  directly at the domain root (e.g. Default Domain Policy) are not captured
  and won't appear in the narrative or anomalies — call this out explicitly
  if you rely on domain-root-linked policy.
- Output files are timestamped so successive snapshots can be diffed to
  show topology drift over time; this repo does not yet automate that
  comparison.
- No real organization data belongs in `samples/` — keep it synthetic.
- See [CHANGELOG.md](CHANGELOG.md) for fixes found while validating Stage 1
  against a real domain (a `Set-StrictMode`/`.Count`-on-`$null` crash when a
  collection comes back empty, and a UTF-8 BOM that broke Python's JSON
  parser).
