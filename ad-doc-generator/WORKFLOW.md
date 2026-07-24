# ad-doc-generator — Workflow

## 1 · End-to-End Pipeline

```mermaid
flowchart LR
    subgraph EXPORT["📤 Stage 1 — Export"]
        AD[("Active Directory\nread-only queries")]
        PS["Get-ADTopologyExport.ps1\nOUs · Trusts · DCs/Sites\nReplication · GPO links\nKey group membership"]
        JSON1["ADTopologyExport_&lt;timestamp&gt;.json\nUTF-8, no BOM"]
        AD --> PS --> JSON1
    end

    subgraph NORMALIZE["🔧 Stage 2 — Normalize"]
        NORM["normalize.py"]
        SCHEMA["normalized.json\n{ nodes, edges }"]
        JSON1 --> NORM --> SCHEMA
    end

    subgraph ANALYZE["🧠 Stage 3 — Analyze"]
        direction LR
        API["Option A: analyze.py\n+ Claude API key"]
        MANUAL["Option B: hand schema to\nan assistant you already have open"]
        ANALYSIS["analysis.json\nnarrative · anomalies\ndocumentationGaps · mermaidDiagram"]
        SCHEMA --> API --> ANALYSIS
        SCHEMA --> MANUAL --> ANALYSIS
    end

    subgraph RENDER["🖼️ Stage 4 — Render"]
        REND["render.py"]
        REPORT["report.html\nnarrative + diagram\n+ anomalies table"]
        ANALYSIS --> REND --> REPORT
    end

    style JSON1 fill:#eef1f4,stroke:#27425D,color:#1B1F23
    style SCHEMA fill:#eef1f4,stroke:#27425D,color:#1B1F23
    style ANALYSIS fill:#eef1f4,stroke:#27425D,color:#1B1F23
    style REPORT fill:#d1fae5,stroke:#10b981,color:#065f46
```

---

## 2 · Stage 1 Detail — Export Script Internals

Each collection area runs in its own `try`/`catch` so one failing area (e.g.
no `GroupPolicy` module access) doesn't blank out the rest of the snapshot.

```mermaid
flowchart TD
    START(["Get-ADTopologyExport.ps1 runs"]) --> OU
    OU["Get-OrganizationalUnitSnapshot\nOU hierarchy + depth + GPO-link flag"] --> TR
    TR["Get-TrustSnapshot\nGet-ADTrust -Filter *"] --> DC
    DC["Get-DomainControllerSnapshot\nHost · Site · FSMO roles · GC/RODC"] --> REPL
    REPL["Get-ReplicationTopologySnapshot\nSites + SiteLinks, isolated try/catch each"] --> GPO
    GPO["Get-GpoLinkSnapshot\nGet-GPInheritance per OU\n(domain-root links out of scope)"] --> GRP
    GRP["Get-KeyGroupMembershipSnapshot\nGet-ADGroupMember -Recursive\nDomain/Enterprise/Schema Admins by default"] --> MERGE

    MERGE["Merge into one [pscustomobject]\nSchemaVersion · ExportedAt · SourceDomain · Sections"] --> WRITE
    WRITE["[System.IO.File]::WriteAllText\nUTF-8, no BOM"] --> WARN

    WARN{"Any section\nstatus != Healthy?"}
    WARN -->|Yes| SUMMARY["Write-Warning per section\n(Status still written to JSON)"]
    WARN -->|No| DONE
    SUMMARY --> DONE(["Return OutputPath + per-section Status"])

    style DONE fill:#d1fae5,stroke:#10b981,color:#065f46
    style SUMMARY fill:#fef3cd,stroke:#8A6D00,color:#5c4a00
```

---

## 3 · Stage 3 Decision — Which Analysis Path

```mermaid
flowchart TD
    Q{"Is this a one-off run\nwith you at the keyboard?"}
    Q -->|Yes| B["Option B — Manual\nPaste normalized.json to an assistant\nyou already have open (e.g. Claude Code)"]
    Q -->|No, needs to run unattended\non a schedule| A["Option A — Scripted\nanalyze.py + ANTHROPIC_API_KEY"]

    B --> NOTE_B["No extra cost, no API key.\nAssistant returns the analysis JSON\nshaped per README.md"]
    A --> NOTE_A["Separate pay-as-you-go billing —\ndoes NOT share quota with a\nClaude.ai / Claude Code subscription"]

    NOTE_B --> SAVE["Save result as analysis.json"]
    NOTE_A --> SAVE
    SAVE --> R4(["Continue to Stage 4 — render.py"])

    style NOTE_A fill:#fef3cd,stroke:#8A6D00,color:#5c4a00
    style NOTE_B fill:#d1fae5,stroke:#10b981,color:#065f46
```

---

## 4 · Stages at a Glance

| Stage | Script | Input | Output |
|-------|--------|-------|--------|
| 1 · Export | `export/Get-ADTopologyExport.ps1` | Live AD (read-only) | `ADTopologyExport_<timestamp>.json` |
| 2 · Normalize | `normalize/normalize.py` | Stage 1 JSON | `normalized.json` — `{ nodes, edges }` |
| 3 · Analyze (Option A) | `analyze/analyze.py` | `normalized.json` + `ANTHROPIC_API_KEY` | `analysis.json` |
| 3 · Analyze (Option B) | *(manual — no script)* | `normalized.json` pasted to an assistant | `analysis.json` |
| 4 · Render | `render/render.py` | `analysis.json` | `report.html` |

---

## 5 · Output Folder Structure

Stage 1's default output folder, per this workspace's convention:

```
C:\Temp\Reports\ADDocGenerator\
├── ADTopologyExport_20260723_212457.json     ← Stage 1 raw export
├── normalized.json                            ← Stage 2 output
├── analysis.json                              ← Stage 3 output (either path)
└── report.html                                ← Stage 4 final report
```

Bundled demo artifacts (synthetic data, safe to keep in git):

```
samples/
├── sample-export.json        ← fake single-domain forest, fed to Stage 1's output shape
├── sample-normalized.json    ← Stage 2 output for the sample
├── sample-analysis.json      ← Stage 3 output for the sample (hand-written worked example)
└── sample-report.html        ← Stage 4 output for the sample
```

---

## 6 · Version History

| Version | Date | What changed |
|---------|------|---------------|
| **1.0.0** | 2026-07-24 | Initial pipeline: `Get-ADTopologyExport.ps1`, `normalize.py`, `analyze.py`, `render.py`, sample data. Verified end-to-end against a real domain-joined lab. Two bugs found and fixed during that verification: a `Set-StrictMode`/`.Count`-on-`$null` crash when an AD query returns no results, and a UTF-8 BOM from `Out-File` that broke Python's `json.load`. See [CHANGELOG.md](CHANGELOG.md#100--2026-07-24). |
