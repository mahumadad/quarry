"""Graph-driven hunting — use the engagement graph to brief agents and find gaps.

Phase 5 of the Engagement Graph: instead of flat briefings from brain.json,
agents receive a relevant subgraph around their target. Gap analysis is concrete:
"endpoint X has no test_execution with identity Y".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph import EngagementGraph, Node, Edge, Subgraph


@dataclass
class CoverageGap:
    endpoint_id: str
    endpoint_label: str
    missing: str
    detail: str
    priority: str = "medium"


@dataclass
class HuntSuggestion:
    target_id: str
    target_label: str
    target_type: str
    reason: str
    priority: str = "medium"
    related_nodes: list[str] = field(default_factory=list)


@dataclass
class AgentBriefing:
    target_id: str
    target_label: str
    subgraph_nodes: int
    subgraph_edges: int
    capabilities: list[dict]
    active_hypotheses: list[dict]
    related_findings: list[dict]
    coverage_gaps: list[dict]
    attack_paths: list[dict]
    context_summary: str


def generate_briefing(graph: EngagementGraph, target_id: str,
                      depth: int = 3) -> AgentBriefing:
    target = graph.get_node(target_id)
    if not target:
        return AgentBriefing(
            target_id=target_id, target_label="(not found)",
            subgraph_nodes=0, subgraph_edges=0,
            capabilities=[], active_hypotheses=[],
            related_findings=[], coverage_gaps=[],
            attack_paths=[], context_summary="Target not in graph.",
        )

    context_nodes, context_edges = _collect_neighborhood(graph, target_id, depth)

    capabilities = []
    active_hypotheses = []
    related_findings = []

    for nid in context_nodes:
        node = graph.get_node(nid)
        if not node:
            continue
        if node.type == "capability":
            capabilities.append({
                "id": node.id, "label": node.label,
                "confidence": _best_edge_confidence(graph, node.id),
            })
        elif node.type == "hypothesis":
            status = node.properties.get("status", "")
            if status in ("active", "testing"):
                active_hypotheses.append({
                    "id": node.id, "label": node.label,
                    "status": status,
                    "priority": node.properties.get("priority", "medium"),
                })
        elif node.type == "finding":
            related_findings.append({
                "id": node.id, "label": node.label,
                "severity": node.properties.get("severity", ""),
                "vuln_class": node.properties.get("vuln_class", ""),
                "status": node.properties.get("status", ""),
            })

    gaps = coverage_gaps(graph, target_id)
    gap_dicts = [{"endpoint": g.endpoint_id, "label": g.endpoint_label,
                  "missing": g.missing, "detail": g.detail,
                  "priority": g.priority} for g in gaps]

    paths = _attack_paths_from_target(graph, target_id)

    summary_parts = [f"Target: {target.label} ({target.type})"]
    if capabilities:
        summary_parts.append(f"{len(capabilities)} capabilities reachable")
    if active_hypotheses:
        summary_parts.append(f"{len(active_hypotheses)} active hypotheses")
    if related_findings:
        summary_parts.append(f"{len(related_findings)} related findings")
    if gaps:
        summary_parts.append(f"{len(gaps)} coverage gaps")

    return AgentBriefing(
        target_id=target_id,
        target_label=target.label,
        subgraph_nodes=len(context_nodes),
        subgraph_edges=len(context_edges),
        capabilities=capabilities,
        active_hypotheses=active_hypotheses,
        related_findings=related_findings,
        coverage_gaps=gap_dicts,
        attack_paths=paths,
        context_summary=". ".join(summary_parts) + ".",
    )


def coverage_gaps(graph: EngagementGraph,
                  scope_node_id: str | None = None) -> list[CoverageGap]:
    gaps: list[CoverageGap] = []

    if scope_node_id:
        endpoints = _endpoints_under(graph, scope_node_id)
    else:
        endpoints = graph.nodes_by_type("endpoint")

    identities = graph.nodes_by_type("identity")
    identity_ids = {n.id for n in identities}

    for ep in endpoints:
        tested_by_edges = graph.get_edges(ep.id, direction="out", edge_type="tested_by")

        if not tested_by_edges:
            gaps.append(CoverageGap(
                endpoint_id=ep.id, endpoint_label=ep.label,
                missing="no_tests",
                detail="No test executions recorded",
                priority="high",
            ))
            continue

        tested_identities: set[str] = set()
        has_conclusive = False
        for edge in tested_by_edges:
            te = graph.get_node(edge.target_id)
            if not te:
                continue
            ident = te.properties.get("identity_used", "")
            if ident:
                tested_identities.add(ident)
            status = te.properties.get("status", "")
            if status in ("pass", "fail", "finding_detected"):
                has_conclusive = True

        if not has_conclusive:
            gaps.append(CoverageGap(
                endpoint_id=ep.id, endpoint_label=ep.label,
                missing="no_conclusive_test",
                detail=f"{len(tested_by_edges)} tests recorded but none conclusive",
                priority="high",
            ))

        if identity_ids:
            missing_identities = identity_ids - tested_identities
            if missing_identities and len(missing_identities) < len(identity_ids):
                missing_labels = []
                for mid in list(missing_identities)[:5]:
                    mn = graph.get_node(mid)
                    missing_labels.append(mn.label if mn else mid)
                gaps.append(CoverageGap(
                    endpoint_id=ep.id, endpoint_label=ep.label,
                    missing="identity_gap",
                    detail=f"Not tested with identities: {', '.join(missing_labels)}",
                    priority="medium",
                ))

    return gaps


def suggest_next_targets(graph: EngagementGraph,
                         max_results: int = 10) -> list[HuntSuggestion]:
    suggestions: list[HuntSuggestion] = []

    untested = graph.unconnected("endpoint", "tested_by", direction="out")
    for ep in untested[:max_results]:
        parent_edges = graph.get_edges(ep.id, direction="in")
        related = [e.source_id for e in parent_edges]
        suggestions.append(HuntSuggestion(
            target_id=ep.id, target_label=ep.label,
            target_type="endpoint", reason="Untested endpoint",
            priority="high", related_nodes=related,
        ))

    if len(suggestions) < max_results:
        for h in graph.nodes_by_type("hypothesis"):
            if len(suggestions) >= max_results:
                break
            status = h.properties.get("status", "")
            if status != "active":
                continue
            involved = [e.target_id for e in graph.get_edges(h.id, direction="out")
                        if e.type == "involves"]
            suggestions.append(HuntSuggestion(
                target_id=h.id, target_label=h.label,
                target_type="hypothesis",
                reason=f"Active hypothesis: {h.properties.get('basis', '')}",
                priority=h.properties.get("priority", "medium"),
                related_nodes=involved,
            ))

    if len(suggestions) < max_results:
        for cap in graph.nodes_by_type("capability"):
            if len(suggestions) >= max_results:
                break
            enables = graph.get_edges(cap.id, direction="out", edge_type="enables")
            if not enables:
                continue
            for edge in enables:
                if len(suggestions) >= max_results:
                    break
                target_node = graph.get_node(edge.target_id)
                if not target_node:
                    continue
                tested = graph.get_edges(edge.target_id, direction="out",
                                         edge_type="tested_by")
                if tested:
                    continue
                suggestions.append(HuntSuggestion(
                    target_id=edge.target_id,
                    target_label=target_node.label,
                    target_type=target_node.type,
                    reason=f"Enabled by capability '{cap.label}' but untested",
                    priority="high",
                    related_nodes=[cap.id],
                ))

    return suggestions[:max_results]


def chain_suggestions(graph: EngagementGraph,
                      max_depth: int = 4) -> list[dict]:
    findings = graph.nodes_by_type("finding")
    chains: list[dict] = []

    for f in findings:
        paths = graph.find_paths(f.id, ["capability"], max_depth=max_depth,
                                  min_confidence="inferred")
        for path in paths:
            cap_id = path.nodes[-1]
            cap = graph.get_node(cap_id)
            if not cap:
                continue
            enables = graph.get_edges(cap_id, direction="out", edge_type="enables")
            for e_edge in enables:
                target = graph.get_node(e_edge.target_id)
                if not target:
                    continue
                chains.append({
                    "finding_id": f.id,
                    "finding_label": f.label,
                    "capability": cap.label,
                    "enables_target_id": target.id,
                    "enables_target_label": target.label,
                    "path_length": len(path.nodes),
                    "min_confidence": path.min_confidence,
                })

    chains.sort(key=lambda c: c["path_length"])
    return chains


def subgraph_for_agent(graph: EngagementGraph, target_id: str,
                       depth: int = 2,
                       include_types: list[str] | None = None) -> dict:
    context_nodes, context_edges = _collect_neighborhood(graph, target_id, depth)

    if include_types:
        type_set = set(include_types)
        context_nodes = {nid for nid in context_nodes
                         if graph.get_node(nid) and graph.get_node(nid).type in type_set}
        context_nodes.add(target_id)

    nodes = []
    for nid in context_nodes:
        n = graph.get_node(nid)
        if not n:
            continue
        nodes.append({
            "id": n.id, "type": n.type, "label": n.label,
            "properties": dict(n.properties),
        })

    edges = []
    for eid in context_edges:
        e = graph.get_edge(eid)
        if not e:
            continue
        if e.source_id in context_nodes and e.target_id in context_nodes:
            edges.append({
                "id": e.id, "type": e.type,
                "source": e.source_id, "target": e.target_id,
                "confidence": e.confidence,
            })

    return {"target": target_id, "nodes": nodes, "edges": edges}


# -- Helpers -----------------------------------------------------------------

def _collect_neighborhood(graph: EngagementGraph, center_id: str,
                          depth: int) -> tuple[set[str], set[str]]:
    visited_nodes: set[str] = {center_id}
    visited_edges: set[str] = set()
    frontier = {center_id}

    for _ in range(depth):
        next_frontier: set[str] = set()
        for nid in frontier:
            for edge in graph.get_edges(nid, direction="both"):
                visited_edges.add(edge.id)
                other = edge.target_id if edge.source_id == nid else edge.source_id
                if other not in visited_nodes:
                    visited_nodes.add(other)
                    next_frontier.add(other)
        frontier = next_frontier

    return visited_nodes, visited_edges


def _best_edge_confidence(graph: EngagementGraph, node_id: str) -> str:
    from .graph import _CONF_ORDER
    best = "hypothesized"
    best_idx = 0
    for edge in graph.get_edges(node_id, direction="both"):
        idx = _CONF_ORDER.get(edge.confidence, 0)
        if idx > best_idx:
            best_idx = idx
            best = edge.confidence
    return best


def _endpoints_under(graph: EngagementGraph, scope_id: str) -> list:
    node = graph.get_node(scope_id)
    if not node:
        return []
    if node.type == "endpoint":
        return [node]

    endpoints = []
    visited: set[str] = set()
    queue = [scope_id]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        n = graph.get_node(current)
        if n and n.type == "endpoint":
            endpoints.append(n)
        for edge in graph.get_edges(current, direction="out"):
            if edge.target_id not in visited:
                queue.append(edge.target_id)

    return endpoints


def _attack_paths_from_target(graph: EngagementGraph,
                              target_id: str) -> list[dict]:
    paths = graph.find_paths(target_id, ["finding", "capability"],
                              max_depth=5, min_confidence="inferred")
    result = []
    for p in paths[:20]:
        goal = graph.get_node(p.nodes[-1])
        result.append({
            "path": p.nodes,
            "length": len(p.nodes),
            "goal_id": p.nodes[-1],
            "goal_type": goal.type if goal else "",
            "goal_label": goal.label if goal else "",
            "min_confidence": p.min_confidence,
        })
    return result
