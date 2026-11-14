"""Offline, read-only analysis of a deliberately scoped AD privilege graph.

Input is a local JSON export from Export-ADPrivilegeGraph.ps1. No AD connection,
credential access, exploit execution, LDAP mutation, or network connection.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from html import escape
import json
from pathlib import Path
import sys
from typing import Any

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_NODES = 20_000
MAX_EDGES = 100_000
MAX_SEARCH_STATES = 50_000
ALLOWED_RELATIONS = {"member_of", "can_modify_group"}


class GraphError(ValueError):
    pass


def _require_string(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise GraphError(f"Invalid {key}")
    return value


def validate_graph(graph: Any) -> dict:
    if not isinstance(graph, dict) or graph.get("schema_version") != "1.0":
        raise GraphError("Expected schema_version 1.0 JSON object")
    start = _require_string(graph.get("start_sid"), "start_sid")
    target = _require_string(graph.get("target_sid"), "target_sid")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    indicators = graph.get("indicators", [])
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise GraphError("Invalid node list or node count")
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise GraphError("Invalid edge list or edge count")
    if not isinstance(indicators, list):
        raise GraphError("Invalid indicators list")
    ids = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise GraphError("Invalid node entry")
        node_id = _require_string(node.get("id"), "node.id")
        if node_id in ids:
            raise GraphError("Duplicate graph node")
        ids.add(node_id)
    if not {start, target}.issubset(ids):
        raise GraphError("Start and target identities must be in the node collection")
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("relation") not in ALLOWED_RELATIONS:
            raise GraphError("Invalid graph edge")
        if edge.get("from") not in ids or edge.get("to") not in ids:
            raise GraphError("Graph edge references an unknown identity")
        if edge["from"] == edge["to"]:
            raise GraphError("Graph contains a self-edge")
    for item in indicators:
        if not isinstance(item, dict) or item.get("principal_sid") not in ids:
            raise GraphError("Indicator references an unknown principal")
    if not isinstance(graph.get("complete"), bool):
        raise GraphError("Explicit true/false scan completeness is mandatory")
    if not isinstance(graph.get("warnings", []), list):
        raise GraphError("Invalid warnings list")
    return graph


def _shortest(start: str, target: str, edges: list[dict], max_depth: int,
              allow_candidates: bool) -> list[dict] | None:
    by_source = defaultdict(list)
    for edge in edges:
        if edge["relation"] == "member_of" or allow_candidates:
            by_source[edge["from"]].append(edge)
    queue = deque([(start, ())])
    visited = {start}
    states = 0
    while queue:
        current, path = queue.popleft()
        states += 1
        if states > MAX_SEARCH_STATES:
            raise GraphError("Path search exceeded safety limit")
        if current == target:
            return list(path)
        if len(path) >= max_depth:
            continue
        for edge in by_source[current]:
            if edge["to"] not in visited:
                visited.add(edge["to"])
                queue.append((edge["to"], (*path, edge)))
    return None


def assess(graph: dict, *, max_depth: int = 10) -> dict:
    validate_graph(graph)
    if not isinstance(max_depth, int) or max_depth < 1 or max_depth > 25:
        raise GraphError("max_depth must be 1–25")
    labels = {node["id"]: str(node.get("label") or node["id"]) for node in graph["nodes"]}
    start = graph["start_sid"]
    target = graph["target_sid"]
    member_path = _shortest(start, target, graph["edges"], max_depth, False)
    candidate_path = None if member_path is not None else _shortest(
        start, target, graph["edges"], max_depth, True
    )
    if member_path is not None:
        status = "membership_path_found"
        chosen = member_path
    elif candidate_path is not None:
        status = "potential_acl_path"
        chosen = candidate_path
    else:
        status = "no_path_in_collected_scope"
        chosen = []
    def describe(path: list[dict]) -> list[dict]:
        return [
            {"from": labels[e["from"]], "to": labels[e["to"]],
             "relation": e["relation"],
             "evidence": str(e.get("evidence", ""))[:400],
             "confidence": ("directory_membership" if e["relation"] == "member_of"
                            else "acl_candidate_not_exploit_proof")}
            for e in path
        ]

    # An exposure based on legitimate current group membership can be reported
    # separately without treating DCSync or GPO write as Domain Admin membership.
    reachable = {start: []}
    adjacency = defaultdict(list)
    for edge in graph["edges"]:
        if edge["relation"] == "member_of":
            adjacency[edge["from"]].append(edge)
    queue = deque([start])
    while queue:
        node = queue.popleft()
        if len(reachable[node]) >= max_depth:
            continue
        for edge in adjacency[node]:
            if edge["to"] not in reachable:
                reachable[edge["to"]] = [*reachable[node], edge]
                queue.append(edge["to"])
    high_impact = []
    for item in graph.get("indicators", []):
        sid = item["principal_sid"]
        if sid not in reachable:
            continue
        high_impact.append({
            "principal": labels[sid],
            "kind": str(item.get("kind", "unclassified"))[:100],
            "object": str(item.get("object", ""))[:250],
            "evidence": str(item.get("evidence", ""))[:500],
            "membership_steps": describe(reachable[sid]),
            "assessment": "needs_effective_permission_and_scope_validation",
            "is_domain_admin_membership": False,
        })
    return {
        "schema_version": "1.0",
        "start": labels[start],
        "target": labels[target],
        "status": status,
        "steps": describe(chosen),
        "contains_acl_candidate": bool(candidate_path is not None),
        "confirmed_exploit": False,
        "graph_complete": graph["complete"],
        "coverage": graph.get("coverage", {}),
        "warnings": graph.get("warnings", []),
        "high_impact_exposures": high_impact,
        "interpretation": (
            "Directory membership is reported separately from ACL-derived potential "
            "access changes. DCSync is not equivalent to Domain Admin group membership. "
            "Access-deny ACEs, object-specific inheritance, group tokens, trust scope, "
            "AdminSDHolder/SDProp and policy effects require live validation. "
            "No observed path is not proof of absence, especially when incomplete."
        ),
    }


def load_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise GraphError("Graph JSON is missing or exceeds maximum file size")
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GraphError("Cannot read graph JSON") from exc


def html_report(report: dict) -> str:
    rows = "".join(
        "<tr><td>" + escape(str(e["from"])) + "</td><td>" +
        escape(str(e["relation"])) + "</td><td>" + escape(str(e["to"])) +
        "</td><td>" + escape(str(e["evidence"])) + "</td></tr>"
        for e in report["steps"]
    )
    extra = "".join(
        "<li>" + escape(str(x["principal"])) + ": " +
        escape(str(x["kind"])) + " — " + escape(str(x["evidence"])) + "</li>"
        for x in report["high_impact_exposures"]
    )
    warning_rows = "".join("<li>" + escape(str(x)) + "</li>" for x in report["warnings"])
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<title>AD privilege relationship audit</title>'
        '<style>body{font:16px system-ui;margin:3em auto;max-width:1100px;padding:1em}'
        'table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.6em}'
        'th{background:#eee}</style><body>'
        '<h1>Read-only AD privilege relationship assessment</h1>'
        '<p>Start: ' + escape(report["start"]) + '</p>'
        '<p>Target: ' + escape(report["target"]) + '</p>'
        '<p>Result: <strong>' + escape(report["status"]) + '</strong></p>'
        '<p>Collection complete: ' + str(report["graph_complete"]) + '</p>'
        '<p>Not a verified exploit or effective-access proof.</p>'
        '<table><tr><th>From</th><th>Relationship</th><th>To</th>'
        '<th>Collected evidence</th></tr>' + rows + '</table>'
        '<h2>Additional high-impact indicators, not Domain Admin membership</h2>'
        '<ul>' + extra + '</ul><h2>Warnings</h2><ul>' + warning_rows + '</ul>'
        '<p>' + escape(report["interpretation"]) + '</p></body></html>'
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only offline AD permission graph review")
    parser.add_argument("graph", type=Path, help="JSON exported by Export-ADPrivilegeGraph.ps1")
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--output", type=Path, help="Local file; refuses overwriting")
    parser.add_argument("--max-depth", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        result = assess(load_json(args.graph), max_depth=args.max_depth)
        data = (json.dumps(result, ensure_ascii=False, indent=2)
                if args.format == "json" else html_report(result))
        if args.output:
            # Mode x prevents replacing an existing report or following symlinks.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(data + "\n")
            print(f"Saved report: {args.output}")
        else:
            print(data)
        if not result["graph_complete"]:
            print("WARNING: Graph collection incomplete; no-path result is NOT reliable.", file=sys.stderr)
        return 0 if result["graph_complete"] else 3
    except (GraphError, OSError) as exc:
        print(f"AD privilege graph error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
