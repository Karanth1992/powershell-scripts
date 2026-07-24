#!/usr/bin/env python3
"""Feeds a normalized AD topology schema to Claude and asks for:
  - a plain-English architecture narrative
  - a list of anomalies/documentation gaps
  - a Mermaid diagram of the topology

Requires the ANTHROPIC_API_KEY environment variable and the `anthropic`
package (`pip install anthropic`).

Usage:
    python analyze.py <normalized_schema.json> <output_analysis.json>
"""

import json
import os
import sys

MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = """You are an Active Directory architecture reviewer. You are given a \
normalized JSON graph (nodes + edges) describing a customer's AD forest topology: \
organizational units, trust relationships, domain controllers, sites and site links, \
GPO links, and privileged group membership.

Respond with a single JSON object with exactly these keys:

- "narrative": a plain-English architecture summary (3-6 short paragraphs) describing \
  the domain/forest structure, trust relationships, site/replication topology, and \
  FSMO role placement.
- "anomalies": an array of objects, each with "severity" (one of "Critical", "Warning", \
  "Info"), "title", and "detail". Flag things such as undocumented or one-way trusts, \
  OUs with no GPO ever linked, domain controllers not assigned to any site, all FSMO \
  roles concentrated on a single DC, overly deep OU nesting (depth > 5), and privileged \
  groups with unexpectedly large or unusual membership.
- "documentationGaps": an array of short strings describing structures found in the data \
  that appear to lack a recorded business justification (e.g. "Trust to \
  partner.example.com exists but no description/justification is recorded").
- "mermaidDiagram": a string containing a valid Mermaid graph (use "graph TD" or \
  "flowchart TD") representing sites, domain controllers, and trust relationships. Keep \
  it readable - do not attempt to render every OU or group member, focus on topology.

Return only the JSON object, no surrounding prose or code fences.
"""


def build_user_prompt(schema: dict) -> str:
    return (
        "Here is the normalized AD topology graph:\n\n"
        f"{json.dumps(schema, indent=2)}"
    )


def analyze(schema: dict) -> dict:
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "The 'anthropic' package is required. Install it with: pip install anthropic"
        ) from exc

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("Set the ANTHROPIC_API_KEY environment variable before running this script.")

    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": build_user_prompt(schema)}],
    )

    raw_text = "".join(block.text for block in response.content if block.type == "text")
    return json.loads(raw_text)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <normalized_schema.json> <output_analysis.json>", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as handle:
        schema = json.load(handle)

    analysis = analyze(schema)

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2)

    print(f"Wrote analysis to {output_path}")


if __name__ == "__main__":
    main()
