#!/usr/bin/env python3
"""Flattens a Get-ADTopologyExport.ps1 JSON snapshot into a normalized
nodes/edges schema that the analyze and render stages consume.

Usage:
    python normalize.py <input_export.json> <output_schema.json>
"""

import json
import sys
from typing import Any, Iterable


SCHEMA_VERSION = "1.0"


def _section_data(sections: dict, name: str) -> Any:
    section = sections.get(name) or {}
    return section.get("Data")


def _node(node_id: str, node_type: str, label: str, **attributes: Any) -> dict:
    return {"id": node_id, "type": node_type, "label": label, "attributes": attributes}


def _edge(source: str, target: str, edge_type: str, **attributes: Any) -> dict:
    return {"source": source, "target": target, "type": edge_type, "attributes": attributes}


def build_ou_nodes_and_edges(ou_data: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    dn_set = {ou["DistinguishedName"] for ou in ou_data}
    for ou in ou_data:
        nodes.append(_node(
            ou["DistinguishedName"], "OU", ou["Name"],
            description=ou.get("Description"),
            hasGpoLink=ou.get("HasGpoLink", False),
            depth=ou.get("Depth", 0),
        ))
        parent_dn = ou.get("ParentDN")
        if parent_dn and parent_dn in dn_set:
            edges.append(_edge(parent_dn, ou["DistinguishedName"], "PARENT_OF"))
    return nodes, edges


def build_trust_edges(trust_data: Iterable[dict]) -> list[dict]:
    edges = []
    for trust in trust_data:
        edges.append(_edge(
            trust.get("Source", "unknown-source"),
            trust.get("Target", "unknown-target"),
            "TRUST",
            direction=trust.get("Direction"),
            trustType=trust.get("TrustType"),
            forestTransitive=trust.get("ForestTransitive"),
            sidFilteringQuarantined=trust.get("SIDFilteringQuarantined"),
        ))
    return edges


def build_dc_nodes(dc_data: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    for dc in dc_data:
        dc_id = f"dc:{dc['HostName']}"
        nodes.append(_node(
            dc_id, "DomainController", dc["HostName"],
            site=dc.get("Site"),
            domain=dc.get("Domain"),
            isGlobalCatalog=dc.get("IsGlobalCatalog", False),
            isReadOnly=dc.get("IsReadOnly", False),
            operatingSystem=dc.get("OperatingSystem"),
            fsmoRoles=dc.get("OperationMasterRoles", []),
        ))
        if dc.get("Site"):
            edges.append(_edge(dc_id, f"site:{dc['Site']}", "LOCATED_IN_SITE"))
    return nodes, edges


def build_site_nodes_and_edges(replication_data: dict) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    for site in (replication_data or {}).get("Sites", []):
        nodes.append(_node(f"site:{site['Name']}", "Site", site["Name"], description=site.get("Description")))

    for link in (replication_data or {}).get("SiteLinks", []):
        sites_included = link.get("SitesIncluded", [])
        link_id = f"sitelink:{link['Name']}"
        nodes.append(_node(
            link_id, "SiteLink", link["Name"],
            cost=link.get("Cost"),
            replicationFrequencyMinutes=link.get("ReplicationFrequencyInMinutes"),
        ))
        for site_dn in sites_included:
            site_name = site_dn.split(",")[0].replace("CN=", "")
            edges.append(_edge(link_id, f"site:{site_name}", "LINKS_SITE"))
    return nodes, edges


def build_gpo_edges(gpo_links: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    seen_gpos: set[str] = set()
    for link in gpo_links:
        gpo_id = f"gpo:{link['GpoName']}"
        if gpo_id not in seen_gpos:
            nodes.append(_node(gpo_id, "GPO", link["GpoName"]))
            seen_gpos.add(gpo_id)
        edges.append(_edge(
            gpo_id, link["OrganizationalUnit"], "LINKED_TO",
            enabled=link.get("Enabled"),
            enforced=link.get("Enforced"),
            order=link.get("Order"),
        ))
    return nodes, edges


def build_key_group_nodes_and_edges(key_group_data: dict) -> tuple[list[dict], list[dict]]:
    nodes, edges = [], []
    for group in (key_group_data or {}).get("Groups", []):
        group_id = f"group:{group['GroupName']}"
        nodes.append(_node(group_id, "Group", group["GroupName"], memberCount=group.get("MemberCount", 0)))
        for member in group.get("Members", []):
            member_id = f"principal:{member.get('SamAccountName') or member.get('Name')}"
            nodes.append(_node(member_id, "Principal", member.get("Name"), objectClass=member.get("ObjectClass")))
            edges.append(_edge(member_id, group_id, "MEMBER_OF"))
    return nodes, edges


def normalize(export: dict) -> dict:
    sections = export.get("Sections", {})

    nodes: list[dict] = []
    edges: list[dict] = []

    ou_nodes, ou_edges = build_ou_nodes_and_edges(_section_data(sections, "OrganizationalUnits") or [])
    nodes += ou_nodes
    edges += ou_edges

    edges += build_trust_edges(_section_data(sections, "Trusts") or [])

    dc_nodes, dc_edges = build_dc_nodes(_section_data(sections, "DomainControllers") or [])
    nodes += dc_nodes
    edges += dc_edges

    site_nodes, site_edges = build_site_nodes_and_edges(_section_data(sections, "ReplicationTopology") or {})
    nodes += site_nodes
    edges += site_edges

    gpo_nodes, gpo_edges = build_gpo_edges(_section_data(sections, "GpoLinks") or [])
    nodes += gpo_nodes
    edges += gpo_edges

    group_nodes, group_edges = build_key_group_nodes_and_edges(_section_data(sections, "KeyGroupMembership") or {})
    nodes += group_nodes
    edges += group_edges

    return {
        "schemaVersion": SCHEMA_VERSION,
        "sourceDomain": export.get("SourceDomain"),
        "exportedAt": export.get("ExportedAt"),
        "nodes": nodes,
        "edges": edges,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <input_export.json> <output_schema.json>", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as handle:
        export = json.load(handle)

    schema = normalize(export)

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(schema, handle, indent=2)

    print(f"Wrote {len(schema['nodes'])} node(s) and {len(schema['edges'])} edge(s) to {output_path}")


if __name__ == "__main__":
    main()
