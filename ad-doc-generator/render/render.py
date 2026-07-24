#!/usr/bin/env python3
"""Builds a single HTML report combining the narrative, anomalies list, and
Mermaid diagram produced by the analyze stage.

Usage:
    python render.py <analysis.json> <output_report.html> [--title "Report Title"]
"""

import html
import json
import sys
from datetime import datetime, timezone

SEVERITY_COLORS = {
    "Critical": "#B3261E",
    "Warning": "#8A6D00",
    "Info": "#3A4A5A",
}

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #F4F6F8; color: #1B1F23; }}
  header {{ background: #27425D; color: #FFFFFF; padding: 24px 32px; }}
  header h1 {{ margin: 0 0 4px 0; font-size: 22px; }}
  header .meta {{ color: #C9D6E3; font-size: 13px; }}
  main {{ max-width: 960px; margin: 24px auto; padding: 0 16px 48px; }}
  section {{ background: #FFFFFF; border: 1px solid #DDE3E9; border-radius: 6px; padding: 20px 24px; margin-bottom: 20px; }}
  section h2 {{ margin-top: 0; font-size: 16px; color: #27425D; }}
  .narrative p {{ line-height: 1.55; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #E5E9ED; font-size: 13px; vertical-align: top; }}
  th {{ background: #EEF1F4; color: #3A4A5A; }}
  .severity-pill {{ display: inline-block; padding: 2px 8px; border-radius: 10px; color: #FFFFFF; font-size: 11px; }}
  .gap-list li {{ margin-bottom: 6px; font-size: 13px; }}
  .mermaid {{ text-align: center; }}
</style>
</head>
<body>
<header>
  <h1>{title}</h1>
  <div class="meta">Generated {generated_at}</div>
</header>
<main>
  <section class="narrative">
    <h2>Architecture Narrative</h2>
    {narrative_html}
  </section>

  <section>
    <h2>Topology Diagram</h2>
    <div class="mermaid">
{mermaid}
    </div>
  </section>

  <section>
    <h2>Anomalies</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Detail</th></tr></thead>
      <tbody>
{anomaly_rows}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Documentation Gaps</h2>
    <ul class="gap-list">
{gap_items}
    </ul>
  </section>
</main>
<script>mermaid.initialize({{ startOnLoad: true, theme: 'neutral' }});</script>
</body>
</html>
"""


def render_narrative(narrative: str) -> str:
    paragraphs = [p.strip() for p in narrative.split("\n") if p.strip()]
    return "\n    ".join(f"<p>{html.escape(p)}</p>" for p in paragraphs)


def render_anomaly_rows(anomalies: list[dict]) -> str:
    if not anomalies:
        return '        <tr><td colspan="3">No anomalies detected.</td></tr>'
    rows = []
    for anomaly in anomalies:
        severity = anomaly.get("severity", "Info")
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Info"])
        rows.append(
            "        <tr>"
            f'<td><span class="severity-pill" style="background:{color}">{html.escape(severity)}</span></td>'
            f"<td>{html.escape(anomaly.get('title', ''))}</td>"
            f"<td>{html.escape(anomaly.get('detail', ''))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_gap_items(gaps: list[str]) -> str:
    if not gaps:
        return "      <li>No documentation gaps flagged.</li>"
    return "\n".join(f"      <li>{html.escape(gap)}</li>" for gap in gaps)


def render(analysis: dict, title: str) -> str:
    return TEMPLATE.format(
        title=html.escape(title),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        narrative_html=render_narrative(analysis.get("narrative", "")),
        mermaid=analysis.get("mermaidDiagram", "graph TD\n  NoData[No diagram available]"),
        anomaly_rows=render_anomaly_rows(analysis.get("anomalies", [])),
        gap_items=render_gap_items(analysis.get("documentationGaps", [])),
    )


def main() -> None:
    args = sys.argv[1:]
    title = "AD Architecture Assessment Report"
    if "--title" in args:
        idx = args.index("--title")
        title = args[idx + 1]
        del args[idx:idx + 2]

    if len(args) != 2:
        print(f"Usage: python {sys.argv[0]} <analysis.json> <output_report.html> [--title \"Report Title\"]", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = args

    with open(input_path, "r", encoding="utf-8") as handle:
        analysis = json.load(handle)

    html_report = render(analysis, title)

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html_report)

    print(f"Wrote report to {output_path}")


if __name__ == "__main__":
    main()
