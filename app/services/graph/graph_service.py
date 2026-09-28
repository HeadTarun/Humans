"""
services/graph/graph_service.py

Server-side graph construction from investigation evidence and indicators.

Builds a forensic entity-relationship graph:
  Nodes = unique entities (IP, Domain, URL, Email, Sender, Attachment, Verdict)
  Edges = relationships between entities derived from evidence

The GraphService is kept behind the API so it can be optimized later
(e.g. pre-computed graph, Neo4j, NetworkX) without frontend changes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional, Set, Tuple

from app.models.schema import EvidenceModel, IndicatorModel


ENTITY_TYPE_MAP = {
    "ip": "IP",
    "domain": "DOMAIN",
    "url": "URL",
    "email": "EMAIL",
    "sender": "EMAIL",
    "recipient": "EMAIL",
    "attachment": "ATTACHMENT",
    "file": "ATTACHMENT",
    "hash": "HASH",
    "threat_actor": "THREAT_ACTOR",
    "campaign": "CAMPAIGN",
}


def _stable_id(entity_type: str, value: str) -> str:
    """Generate a stable, reproducible node ID from type + value."""
    return hashlib.sha256(f"{entity_type}:{value.lower()}".encode()).hexdigest()[:24]


def _detect_entity_type(key: str, value: str) -> str:
    """Heuristic entity type detection from evidence key + value."""
    key_lower = key.lower()
    for k, t in ENTITY_TYPE_MAP.items():
        if k in key_lower:
            return t
    # Value-based heuristics
    if value.startswith("http://") or value.startswith("https://"):
        return "URL"
    if "@" in value:
        return "EMAIL"
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "IP"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value) and "." in value:
        return "DOMAIN"
    return "INDICATOR"


def build_graph(
    case_id: str,
    evidence_items: List[EvidenceModel],
    indicators: List[IndicatorModel],
    max_depth: int = 2,
    center_node_id: Optional[str] = None,
) -> Tuple[List[dict], List[dict]]:
    """
    Build a forensic entity-relationship graph from evidence and indicators.

    Returns:
        (nodes, edges) — both as plain dicts ready for JSON serialization.
    """
    nodes: Dict[str, dict] = {}
    edges: List[dict] = []
    edge_ids: Set[str] = set()

    # Root: the case itself
    case_node_id = _stable_id("CASE", case_id)
    nodes[case_node_id] = {
        "id": case_node_id,
        "type": "CASE",
        "label": f"Case {case_id[:12]}",
        "value": case_id,
        "risk_score": None,
        "depth": 0,
    }

    def _add_edge(source: str, target: str, label: str, edge_type: str) -> None:
        edge_id = _stable_id(edge_type, f"{source}-{target}")
        if edge_id not in edge_ids:
            edge_ids.add(edge_id)
            edges.append({"id": edge_id, "source": source, "target": target, "label": label, "type": edge_type})

    def _add_node(entity_type: str, value: str, depth: int, extra: Optional[dict] = None) -> str:
        node_id = _stable_id(entity_type, value)
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": entity_type,
                "label": value[:64] if len(value) > 64 else value,
                "value": value,
                "risk_score": None,
                "depth": depth,
                **(extra or {}),
            }
        return node_id

    # Build from evidence items
    for ev in evidence_items:
        raw = ev.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {}

        key = ev.key or raw.get("key", "")
        value_data = raw.get("value", {})

        # Extract entity nodes from the evidence value dict
        if isinstance(value_data, dict):
            for field, val in value_data.items():
                if not val or not isinstance(val, str) or len(val) < 2:
                    continue
                etype = _detect_entity_type(field, val)
                if etype == "INDICATOR":  # skip generic indicators
                    continue
                node_id = _add_node(etype, val, depth=1)
                _add_edge(case_node_id, node_id, key, "CASE_TO_ENTITY")

        elif isinstance(value_data, str) and value_data:
            etype = _detect_entity_type(key, value_data)
            node_id = _add_node(etype, value_data, depth=1)
            _add_edge(case_node_id, node_id, key, "CASE_TO_ENTITY")

        # If there's a related_entity, add it and link
        related_entity = raw.get("related_entity")
        if related_entity and isinstance(related_entity, str):
            etype = _detect_entity_type(key, related_entity)
            rel_node_id = _add_node(etype, related_entity, depth=2)
            if isinstance(value_data, dict):
                for field, val in value_data.items():
                    if val and isinstance(val, str):
                        src_id = _stable_id(_detect_entity_type(field, val), val)
                        if src_id in nodes:
                            _add_edge(src_id, rel_node_id, "RELATED_TO", "ENTITY_RELATION")

    # Build from indicators (cross-node linking)
    for ind in indicators:
        etype = _detect_entity_type(ind.indicator_type, ind.indicator_value)
        ind_node_id = _add_node(etype, ind.indicator_value, depth=1, extra={"indicator_type": ind.indicator_type})
        _add_edge(case_node_id, ind_node_id, ind.indicator_type, "INDICATOR")

    return list(nodes.values()), edges


def expand_node(
    node_id: str,
    case_id: str,
    evidence_items: List[EvidenceModel],
    indicators: List[IndicatorModel],
) -> Tuple[List[dict], List[dict]]:
    """
    Expand a single graph node — return only nodes/edges adjacent to node_id
    that are not already in the caller's graph.
    """
    all_nodes, all_edges = build_graph(case_id, evidence_items, indicators, max_depth=3)

    # Find direct neighbours of node_id
    adjacent_edge_ids = {
        e["id"] for e in all_edges
        if e["source"] == node_id or e["target"] == node_id
    }
    adjacent_node_ids = set()
    adjacent_edges = []
    for e in all_edges:
        if e["id"] in adjacent_edge_ids:
            adjacent_edges.append(e)
            adjacent_node_ids.add(e["source"])
            adjacent_node_ids.add(e["target"])

    # Return only the adjacent nodes (caller merges with existing)
    adjacent_nodes = [n for n in all_nodes if n["id"] in adjacent_node_ids]
    return adjacent_nodes, adjacent_edges
