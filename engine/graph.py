"""Engagement Graph — typed directed property graph for pentest state.

The graph unifies assets, services, endpoints, identities, trust boundaries,
findings, hypotheses, test executions, evidence and capabilities into a single
queryable structure.  Existing modules (Brain, Coverage, Findings, ChainEngine)
will read from and write to this graph in Phase 2; Phase 1 is standalone.

Storage: JSONL append-only files (nodes.jsonl, edges.jsonl) with an in-memory
index rebuilt on load.  Each mutation optionally logs to the custody chain.
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path as FilePath
from typing import Any

try:
    from .storage import append_jsonl, atomic_write_json, engagement_lock, read_json
except ImportError:
    from storage import append_jsonl, atomic_write_json, engagement_lock, read_json


# -- Schema constants -------------------------------------------------------

NODE_TYPES = frozenset({
    "asset", "service", "endpoint", "identity", "trust_boundary",
    "finding", "hypothesis", "test_execution", "evidence", "capability",
    "chain",
})

EDGE_TYPES = frozenset({
    "hosts", "exposes", "authenticates_to", "crosses", "tested_by",
    "produced", "supports", "grants", "enables", "chains_to", "calls",
    "trusts", "protects", "refutes", "scoped_to", "weakens", "involves",
    "derived_from",
})

CONFIDENCE_LEVELS = ("hypothesized", "inferred", "observed", "demonstrated", "disproved")
_CONF_ORDER = {c: i for i, c in enumerate(CONFIDENCE_LEVELS)}

CONFIDENCE_TERMINAL = frozenset({"demonstrated", "disproved"})


# -- Data classes -----------------------------------------------------------

@dataclass
class Node:
    id: str
    type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    source: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class Edge:
    id: str
    type: str
    source_id: str
    target_id: str
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: str = "observed"
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    source: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class GraphPath:
    nodes: list[str]
    edges: list[Edge]
    min_confidence: str = "demonstrated"

    def __post_init__(self):
        if self.edges:
            worst = min(self.edges, key=lambda e: _CONF_ORDER.get(e.confidence, 0))
            self.min_confidence = worst.confidence


@dataclass
class Subgraph:
    nodes: dict[str, Node]
    edges: list[Edge]

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


# -- Main class -------------------------------------------------------------

class EngagementGraph:
    """Typed directed property graph backed by JSONL files."""

    def __init__(self, audit_dir: str, custody_log=None):
        self.audit_dir = FilePath(audit_dir)
        self.state_dir = self.audit_dir / ".pentest-state"
        self.graph_dir = self.state_dir / "graph"
        self.nodes_file = self.graph_dir / "nodes.jsonl"
        self.edges_file = self.graph_dir / "edges.jsonl"
        self.index_file = self.graph_dir / "index.json"
        self._custody = custody_log

        self._nodes: dict[str, Node] = {}
        self._edges: dict[str, Edge] = {}
        self._adj_out: dict[str, list[str]] = defaultdict(list)
        self._adj_in: dict[str, list[str]] = defaultdict(list)
        self._type_index_nodes: dict[str, set[str]] = defaultdict(set)
        self._type_index_edges: dict[str, set[str]] = defaultdict(set)

        self._load()

    # -- Persistence ---------------------------------------------------------

    def _load(self):
        self._nodes.clear()
        self._edges.clear()
        self._adj_out.clear()
        self._adj_in.clear()
        self._type_index_nodes.clear()
        self._type_index_edges.clear()

        if self.nodes_file.exists():
            for line in self.nodes_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                node = Node(**raw)
                self._nodes[node.id] = node
                self._type_index_nodes[node.type].add(node.id)

        if self.edges_file.exists():
            for line in self.edges_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                edge = Edge(**raw)
                self._edges[edge.id] = edge
                self._index_edge(edge)

    def _index_edge(self, edge: Edge):
        self._adj_out[edge.source_id].append(edge.id)
        self._adj_in[edge.target_id].append(edge.id)
        self._type_index_edges[edge.type].add(edge.id)

    def _append_node(self, node: Node):
        self.graph_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(self.nodes_file, asdict(node))

    def _append_edge(self, edge: Edge):
        self.graph_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(self.edges_file, asdict(edge))

    def _custody_log(self, event: str, detail: dict):
        if self._custody:
            self._custody.append(event, detail, actor="engine")

    def save_index(self):
        self.graph_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.index_file, {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "node_types": {t: len(ids) for t, ids in self._type_index_nodes.items()},
            "edge_types": {t: len(ids) for t, ids in self._type_index_edges.items()},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    # -- Mutations -----------------------------------------------------------

    def add_node(self, type: str, label: str, properties: dict | None = None,
                 source: str = "", node_id: str | None = None) -> str:
        if type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {type!r}. Valid: {sorted(NODE_TYPES)}")
        nid = node_id or f"N-{uuid.uuid4().hex[:10]}"
        node = Node(id=nid, type=type, label=label,
                    properties=properties or {}, source=source)
        self._nodes[nid] = node
        self._type_index_nodes[type].add(nid)
        self._append_node(node)
        self._custody_log("graph_node_added", {"node_id": nid, "type": type, "label": label})
        return nid

    def add_edge(self, type: str, source_id: str, target_id: str,
                 confidence: str = "observed", evidence_refs: list[str] | None = None,
                 properties: dict | None = None, source: str = "",
                 edge_id: str | None = None) -> str:
        if type not in EDGE_TYPES:
            raise ValueError(f"Unknown edge type: {type!r}. Valid: {sorted(EDGE_TYPES)}")
        if confidence not in _CONF_ORDER:
            raise ValueError(f"Unknown confidence: {confidence!r}. Valid: {CONFIDENCE_LEVELS}")
        if source_id not in self._nodes:
            raise KeyError(f"Source node {source_id!r} not in graph")
        if target_id not in self._nodes:
            raise KeyError(f"Target node {target_id!r} not in graph")

        eid = edge_id or f"E-{uuid.uuid4().hex[:10]}"
        edge = Edge(id=eid, type=type, source_id=source_id, target_id=target_id,
                    confidence=confidence, evidence_refs=evidence_refs or [],
                    properties=properties or {}, source=source)
        self._edges[eid] = edge
        self._index_edge(edge)
        self._append_edge(edge)
        self._custody_log("graph_edge_added", {
            "edge_id": eid, "type": type,
            "source": source_id, "target": target_id,
            "confidence": confidence,
        })
        return eid

    def update_confidence(self, edge_id: str, new_confidence: str,
                          evidence_refs: list[str] | None = None,
                          reason: str = "") -> None:
        if edge_id not in self._edges:
            raise KeyError(f"Edge {edge_id!r} not in graph")
        if new_confidence not in _CONF_ORDER:
            raise ValueError(f"Unknown confidence: {new_confidence!r}")

        edge = self._edges[edge_id]
        old = edge.confidence
        edge.confidence = new_confidence
        edge.updated_at = datetime.now(timezone.utc).isoformat()
        if evidence_refs:
            edge.evidence_refs.extend(evidence_refs)
        self._append_edge(edge)
        self._custody_log("graph_confidence_updated", {
            "edge_id": edge_id, "old": old, "new": new_confidence, "reason": reason,
        })

    def update_node(self, node_id: str, properties: dict) -> None:
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id!r} not in graph")
        node = self._nodes[node_id]
        node.properties.update(properties)
        node.updated_at = datetime.now(timezone.utc).isoformat()
        self._append_node(node)
        self._custody_log("graph_node_updated", {
            "node_id": node_id, "updated_keys": list(properties.keys()),
        })

    # -- Queries -------------------------------------------------------------

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Edge | None:
        return self._edges.get(edge_id)

    def get_edges(self, node_id: str, direction: str = "both",
                  edge_type: str | None = None) -> list[Edge]:
        eids: set[str] = set()
        if direction in ("out", "both"):
            eids.update(self._adj_out.get(node_id, []))
        if direction in ("in", "both"):
            eids.update(self._adj_in.get(node_id, []))
        edges = [self._edges[eid] for eid in eids if eid in self._edges]
        if edge_type:
            edges = [e for e in edges if e.type == edge_type]
        return edges

    def nodes_by_type(self, node_type: str) -> list[Node]:
        return [self._nodes[nid] for nid in self._type_index_nodes.get(node_type, set())
                if nid in self._nodes]

    def edges_by_type(self, edge_type: str) -> list[Edge]:
        return [self._edges[eid] for eid in self._type_index_edges.get(edge_type, set())
                if eid in self._edges]

    def query(self, node_types: list[str] | None = None,
              edge_types: list[str] | None = None,
              min_confidence: str = "hypothesized") -> Subgraph:
        min_idx = _CONF_ORDER.get(min_confidence, 0)

        if node_types:
            node_ids: set[str] = set()
            for nt in node_types:
                node_ids.update(self._type_index_nodes.get(nt, set()))
        else:
            node_ids = set(self._nodes.keys())

        edges: list[Edge] = []
        for edge in self._edges.values():
            if edge_types and edge.type not in edge_types:
                continue
            if _CONF_ORDER.get(edge.confidence, 0) < min_idx:
                continue
            if edge.source_id in node_ids or edge.target_id in node_ids:
                edges.append(edge)
                node_ids.add(edge.source_id)
                node_ids.add(edge.target_id)

        nodes = {nid: self._nodes[nid] for nid in node_ids if nid in self._nodes}
        return Subgraph(nodes=nodes, edges=edges)

    def find_paths(self, start_id: str, goal_types: list[str],
                   max_depth: int = 6,
                   min_confidence: str = "inferred") -> list[GraphPath]:
        if start_id not in self._nodes:
            return []

        min_idx = _CONF_ORDER.get(min_confidence, 0)
        goal_type_set = set(goal_types)
        results: list[GraphPath] = []
        queue: list[tuple[str, list[str], list[Edge]]] = [(start_id, [start_id], [])]

        while queue and len(results) < 50:
            current, visited, path_edges = queue.pop(0)

            if len(path_edges) > 0:
                node = self._nodes.get(current)
                if node and node.type in goal_type_set:
                    results.append(GraphPath(nodes=list(visited), edges=list(path_edges)))
                    continue

            if len(visited) > max_depth:
                continue

            for eid in self._adj_out.get(current, []):
                edge = self._edges.get(eid)
                if not edge:
                    continue
                if _CONF_ORDER.get(edge.confidence, 0) < min_idx:
                    continue
                if edge.target_id in visited:
                    continue
                queue.append((
                    edge.target_id,
                    visited + [edge.target_id],
                    path_edges + [edge],
                ))

        return results

    def unconnected(self, node_type: str, edge_type: str,
                    direction: str = "in") -> list[Node]:
        connected: set[str] = set()
        for edge in self._edges.values():
            if edge.type == edge_type:
                if direction == "in":
                    connected.add(edge.target_id)
                elif direction == "out":
                    connected.add(edge.source_id)
                else:
                    connected.add(edge.source_id)
                    connected.add(edge.target_id)

        return [self._nodes[nid] for nid in self._type_index_nodes.get(node_type, set())
                if nid not in connected and nid in self._nodes]

    def neighbors(self, node_id: str, edge_types: list[str] | None = None,
                  direction: str = "both") -> list[Node]:
        neighbor_ids: set[str] = set()
        edges = self.get_edges(node_id, direction=direction)
        for e in edges:
            if edge_types and e.type not in edge_types:
                continue
            other = e.target_id if e.source_id == node_id else e.source_id
            neighbor_ids.add(other)
        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    # -- Stats ---------------------------------------------------------------

    def summary(self) -> dict:
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "node_types": {t: len(ids) for t, ids in self._type_index_nodes.items()},
            "edge_types": {t: len(ids) for t, ids in self._type_index_edges.items()},
            "confidence_distribution": self._confidence_dist(),
        }

    def _confidence_dist(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for edge in self._edges.values():
            dist[edge.confidence] = dist.get(edge.confidence, 0) + 1
        return dist

    # -- Serialization helpers -----------------------------------------------

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges.values()],
            "summary": self.summary(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def to_json(self, path: str | None = None) -> str:
        data = self.to_dict()
        text = json.dumps(data, indent=2, ensure_ascii=False)
        if path:
            FilePath(path).write_text(text)
        return text
