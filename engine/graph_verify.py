"""Independent verification — isolated finding reproduction via the graph.

Phase 6 of the Engagement Graph: a finding-checker receives only the evidence
subgraph (no operator conclusions), attempts to reproduce, and writes its own
test_execution node with the result. This prevents confirmation bias — the
verifier sees evidence, not verdicts.

Usage:
  vr = prepare_verification(graph, "F-001")
  # vr.evidence_subgraph has only evidence + test_execution nodes, no findings
  # Agent attempts reproduction using vr.steps_to_reproduce ...
  result = record_verification(graph, tracker, "F-001",
      status="confirmed", technique="manual-replay", tool="curl",
      notes="Reproduced: GET /api/users/2 returns foreign data")
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph import EngagementGraph, Node, Edge
    from .test_tracker import TestExecutionTracker


VERIFICATION_STATUSES = frozenset({
    "confirmed", "not_reproduced", "partial", "blocked", "inconclusive",
})


@dataclass
class VerificationRequest:
    finding_id: str
    finding_label: str
    target_asset: str
    vuln_class: str
    severity: str
    evidence_subgraph: dict
    steps_to_reproduce: list[str]
    evidence_artifacts: list[dict]
    test_executions: list[dict]
    context: dict


@dataclass
class VerificationResult:
    finding_id: str
    status: str
    test_execution_id: str
    technique: str
    tool: str
    notes: str
    verified_at: str = ""
    duration_ms: int | None = None

    def __post_init__(self):
        if not self.verified_at:
            self.verified_at = datetime.now(timezone.utc).isoformat()


def prepare_verification(graph: EngagementGraph,
                         finding_id: str) -> VerificationRequest:
    finding_node = graph.get_node(finding_id)
    if not finding_node:
        return VerificationRequest(
            finding_id=finding_id, finding_label="(not found)",
            target_asset="", vuln_class="", severity="",
            evidence_subgraph={"nodes": [], "edges": []},
            steps_to_reproduce=[], evidence_artifacts=[],
            test_executions=[], context={},
        )

    props = finding_node.properties

    evidence_nodes = []
    test_exec_nodes = []
    subgraph_nodes: list[dict] = []
    subgraph_edges: list[dict] = []
    visited_nodes: set[str] = set()

    for edge in graph.get_edges(finding_id, direction="in"):
        src = graph.get_node(edge.source_id)
        if not src:
            continue

        if src.type == "evidence" and edge.type == "supports":
            evidence_nodes.append(src)
            _add_to_subgraph(src, edge, subgraph_nodes, subgraph_edges, visited_nodes)

        if src.type == "test_execution":
            test_exec_nodes.append(src)
            _add_to_subgraph(src, edge, subgraph_nodes, subgraph_edges, visited_nodes)

    for edge in graph.get_edges(finding_id, direction="in"):
        src = graph.get_node(edge.source_id)
        if src and src.type == "test_execution" and edge.type == "tested_by":
            if src.id not in visited_nodes:
                test_exec_nodes.append(src)
                _add_to_subgraph(src, edge, subgraph_nodes, subgraph_edges, visited_nodes)

    for te in test_exec_nodes:
        for te_edge in graph.get_edges(te.id, direction="in"):
            target_node = graph.get_node(te_edge.source_id)
            if target_node and target_node.type in ("endpoint", "asset", "service"):
                if target_node.id not in visited_nodes:
                    visited_nodes.add(target_node.id)
                    subgraph_nodes.append({
                        "id": target_node.id, "type": target_node.type,
                        "label": target_node.label,
                    })
                subgraph_edges.append({
                    "id": te_edge.id, "type": te_edge.type,
                    "source": te_edge.source_id, "target": te_edge.target_id,
                    "confidence": te_edge.confidence,
                })

    for te in test_exec_nodes:
        for te_edge in graph.get_edges(te.id, direction="out"):
            target_node = graph.get_node(te_edge.target_id)
            if target_node and target_node.type in ("endpoint", "asset", "service"):
                if target_node.id not in visited_nodes:
                    visited_nodes.add(target_node.id)
                    subgraph_nodes.append({
                        "id": target_node.id, "type": target_node.type,
                        "label": target_node.label,
                    })
                subgraph_edges.append({
                    "id": te_edge.id, "type": te_edge.type,
                    "source": te_edge.source_id, "target": te_edge.target_id,
                    "confidence": te_edge.confidence,
                })

    evidence_artifacts = []
    for ev in evidence_nodes:
        evidence_artifacts.append({
            "id": ev.id, "label": ev.label,
            "type": ev.properties.get("type", ""),
            "content": ev.properties.get("content", ""),
            "tool": ev.properties.get("tool", ""),
            "tag": ev.properties.get("tag", ""),
        })

    test_execution_dicts = []
    for te in test_exec_nodes:
        test_execution_dicts.append({
            "id": te.id, "label": te.label,
            "technique": te.properties.get("technique", ""),
            "tool": te.properties.get("tool", ""),
            "status": te.properties.get("status", ""),
            "identity_used": te.properties.get("identity_used", ""),
            "notes": te.properties.get("notes", ""),
        })

    steps: list[str] = []
    for te in test_exec_nodes:
        technique = te.properties.get("technique", "")
        tool = te.properties.get("tool", "")
        notes = te.properties.get("notes", "")
        if technique or tool:
            step = f"Run {technique}" if technique else ""
            if tool:
                step += f" using {tool}" if step else f"Use {tool}"
            if notes:
                step += f" — {notes}"
            steps.append(step.strip())

    for ev in evidence_nodes:
        content = ev.properties.get("content", "")
        if content:
            steps.append(f"Verify: {content[:200]}")

    context = {
        "target_asset": props.get("target_asset", ""),
        "vuln_class": props.get("vuln_class", ""),
        "cvss_score": props.get("cvss_score", ""),
    }

    return VerificationRequest(
        finding_id=finding_id,
        finding_label=finding_node.label,
        target_asset=props.get("target_asset", ""),
        vuln_class=props.get("vuln_class", ""),
        severity=props.get("severity", ""),
        evidence_subgraph={"nodes": subgraph_nodes, "edges": subgraph_edges},
        steps_to_reproduce=steps,
        evidence_artifacts=evidence_artifacts,
        test_executions=test_execution_dicts,
        context=context,
    )


def record_verification(graph: EngagementGraph,
                        tracker: TestExecutionTracker,
                        finding_id: str,
                        status: str,
                        technique: str = "manual-verification",
                        tool: str = "",
                        notes: str = "",
                        identity_used: str = "",
                        duration_ms: int | None = None,
                        evidence_refs: list[str] | None = None,
                        source: str = "verifier") -> VerificationResult:
    if status not in VERIFICATION_STATUSES:
        raise ValueError(
            f"Invalid verification status: {status!r}. "
            f"Valid: {sorted(VERIFICATION_STATUSES)}")

    status_map = {
        "confirmed": "finding_detected",
        "not_reproduced": "pass",
        "partial": "inconclusive",
        "blocked": "blocked",
        "inconclusive": "inconclusive",
    }
    te_status = status_map[status]

    finding_node = graph.get_node(finding_id)
    target_node_id = ""
    if finding_node:
        target_asset = finding_node.properties.get("target_asset", "")
        if target_asset:
            for edge in graph.get_edges(finding_id, direction="both"):
                other_id = (edge.target_id if edge.source_id == finding_id
                            else edge.source_id)
                other = graph.get_node(other_id)
                if other and other.type in ("endpoint", "asset", "service"):
                    target_node_id = other_id
                    break

    te = tracker.record(
        label=f"Verification: {finding_id}",
        technique=technique,
        tool=tool,
        target_node_id=target_node_id,
        identity_used=identity_used,
        vuln_class=finding_node.properties.get("vuln_class", "") if finding_node else "",
        status=te_status,
        duration_ms=duration_ms,
        notes=f"[verification:{status}] {notes}",
        evidence_refs=evidence_refs or [],
        finding_id=finding_id,
        source=source,
    )

    if finding_node and graph.get_node(te.id):
        if status == "confirmed":
            graph.add_edge("supports", te.id, finding_id,
                           confidence="demonstrated",
                           properties={"verification": True},
                           source=source)
        elif status == "not_reproduced":
            graph.add_edge("refutes", te.id, finding_id,
                           confidence="demonstrated",
                           properties={"verification": True},
                           source=source)

    return VerificationResult(
        finding_id=finding_id,
        status=status,
        test_execution_id=te.id,
        technique=technique,
        tool=tool,
        notes=notes,
        duration_ms=duration_ms,
    )


def verification_summary(graph: EngagementGraph) -> dict:
    findings = graph.nodes_by_type("finding")
    total = len(findings)
    verified = 0
    refuted = 0
    unverified = 0

    for f in findings:
        in_edges = graph.get_edges(f.id, direction="in")
        has_verification_support = False
        has_verification_refute = False
        for e in in_edges:
            if e.properties.get("verification"):
                if e.type == "supports":
                    has_verification_support = True
                elif e.type == "refutes":
                    has_verification_refute = True

        if has_verification_support:
            verified += 1
        elif has_verification_refute:
            refuted += 1
        else:
            unverified += 1

    return {
        "total_findings": total,
        "verified": verified,
        "refuted": refuted,
        "unverified": unverified,
        "verification_rate": (verified / total * 100) if total else 0,
    }


def findings_needing_verification(graph: EngagementGraph) -> list[dict]:
    findings = graph.nodes_by_type("finding")
    needs: list[dict] = []

    for f in findings:
        in_edges = graph.get_edges(f.id, direction="in")
        has_verification = any(
            e.properties.get("verification") for e in in_edges
        )
        if not has_verification:
            needs.append({
                "id": f.id,
                "label": f.label,
                "severity": f.properties.get("severity", ""),
                "vuln_class": f.properties.get("vuln_class", ""),
                "status": f.properties.get("status", ""),
            })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    needs.sort(key=lambda f: severity_order.get(f["severity"], 99))
    return needs


# -- Helpers -----------------------------------------------------------------

def _add_to_subgraph(node, edge, nodes: list, edges: list,
                     visited: set) -> None:
    if node.id not in visited:
        visited.add(node.id)
        nodes.append({
            "id": node.id, "type": node.type, "label": node.label,
            "properties": dict(node.properties),
        })
    edges.append({
        "id": edge.id, "type": edge.type,
        "source": edge.source_id, "target": edge.target_id,
        "confidence": edge.confidence,
    })
