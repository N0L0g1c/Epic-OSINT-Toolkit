"""Export correlation / scan results as investigation graphs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from xml.sax.saxutils import escape


class GraphExport:
    """Build entity graphs and write JSON / GraphML."""

    def from_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        nodes: Dict[str, Dict[str, str]] = {}
        edges: List[Dict[str, str]] = []

        def add_node(nid: str, ntype: str, label: str = "") -> None:
            if nid not in nodes:
                nodes[nid] = {"id": nid, "type": ntype, "label": label or nid}

        def add_edge(src: str, dst: str, rel: str = "related") -> None:
            edges.append({"from": src, "to": dst, "rel": rel})

        target = str(results.get("target") or "unknown")
        ttype = str(results.get("scan_type") or "target")
        root = f"{ttype}:{target}"
        add_node(root, ttype, target)

        corr = results.get("correlation") or {}
        for etype, values in (corr.get("entities") or {}).items():
            for v in values or []:
                nid = f"{etype}:{v}"
                add_node(nid, etype.rstrip("s") if etype.endswith("s") else etype, str(v))
                add_edge(root, nid, "found")

        for link in corr.get("links") or []:
            frm, to = link.get("from"), link.get("to")
            if frm and to:
                add_node(frm, frm.split(":", 1)[0], frm.split(":", 1)[-1])
                add_node(to, to.split(":", 1)[0], to.split(":", 1)[-1])
                add_edge(frm, to, "link")

        return {
            "target": target,
            "nodes": list(nodes.values()),
            "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges)},
        }

    def write_json(self, graph: Dict[str, Any], path: str) -> str:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(graph, indent=2), encoding="utf-8")
        return str(p)

    def write_graphml(self, graph: Dict[str, Any], path: str) -> str:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="rel" for="edge" attr.name="rel" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">',
        ]
        for n in graph.get("nodes") or []:
            nid = escape(str(n["id"]))
            lines.append(f'    <node id="{nid}">')
            lines.append(f'      <data key="type">{escape(str(n.get("type", "")))}</data>')
            lines.append(f'      <data key="label">{escape(str(n.get("label", "")))}</data>')
            lines.append("    </node>")
        for i, e in enumerate(graph.get("edges") or []):
            lines.append(
                f'    <edge id="e{i}" source="{escape(str(e["from"]))}" target="{escape(str(e["to"]))}">'
            )
            lines.append(f'      <data key="rel">{escape(str(e.get("rel", "")))}</data>')
            lines.append("    </edge>")
        lines.append("  </graph>")
        lines.append("</graphml>")
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)
