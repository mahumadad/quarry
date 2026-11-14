"""Tests for engine.graph — Engagement Graph Phase 1."""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from engine.graph import (
    CONFIDENCE_LEVELS,
    EDGE_TYPES,
    NODE_TYPES,
    Edge,
    EngagementGraph,
    Node,
)


@pytest.fixture
def audit_dir(tmp_path):
    return str(tmp_path / "test-engagement")


@pytest.fixture
def graph(audit_dir):
    return EngagementGraph(audit_dir)


@pytest.fixture
def populated_graph(graph):
    """Graph with a small Fintual-like topology for path/query tests."""
    a1 = graph.add_node("asset", "fintual.cl", source="recon")
    s1 = graph.add_node("service", "GraphQL /gql/", {"port": 443}, source="recon")
    s2 = graph.add_node("service", "REST v1 /api/*", {"port": 443}, source="recon")
    e1 = graph.add_node("endpoint", "GET /api/goals/:id", {"method": "GET", "auth_required": True})
    e2 = graph.add_node("endpoint", "POST /gql/ (clGoal)", {"method": "POST"})
    i1 = graph.add_node("identity", "Account A", {"account_id": "1201884"})
    tb1 = graph.add_node("trust_boundary", "public→auth", {"mechanism": "cookie-session"})
    f1 = graph.add_node("finding", "F-CORS", {"vuln_class": "cors", "severity": "high"})
    cap1 = graph.add_node("capability", "steal_token", {"scope": "rest-api-v1"})
    h1 = graph.add_node("hypothesis", "CORS round-trip", {"status": "active"})
    te1 = graph.add_node("test_execution", "IDOR test round 2",
                         {"technique": "sequential-id", "status": "pass"})
    ev1 = graph.add_node("evidence", "HTTP 404 response", {"kind": "response"})

    graph.add_edge("hosts", a1, s1, confidence="demonstrated")
    graph.add_edge("hosts", a1, s2, confidence="demonstrated")
    graph.add_edge("exposes", s2, e1, confidence="demonstrated")
    graph.add_edge("exposes", s1, e2, confidence="demonstrated")
    graph.add_edge("authenticates_to", i1, s1, confidence="demonstrated")
    graph.add_edge("authenticates_to", i1, s2, confidence="demonstrated")
    graph.add_edge("crosses", e1, tb1, confidence="observed")
    graph.add_edge("tested_by", e1, te1, confidence="demonstrated")
    graph.add_edge("produced", te1, ev1, confidence="demonstrated")
    graph.add_edge("grants", f1, cap1, confidence="demonstrated")
    graph.add_edge("enables", cap1, h1, confidence="inferred")
    graph.add_edge("weakens", f1, tb1, confidence="inferred")

    return graph, {
        "asset": a1, "gql": s1, "rest": s2, "endpoint_goals": e1,
        "endpoint_gql": e2, "identity": i1, "boundary": tb1,
        "finding": f1, "capability": cap1, "hypothesis": h1,
        "test_exec": te1, "evidence": ev1,
    }


# -- Node operations --------------------------------------------------------

class TestNodeOperations:
    def test_add_node_returns_id(self, graph):
        nid = graph.add_node("asset", "example.com")
        assert nid.startswith("N-")
        assert len(nid) == 12

    def test_add_node_custom_id(self, graph):
        nid = graph.add_node("asset", "example.com", node_id="N-custom123")
        assert nid == "N-custom123"

    def test_add_node_invalid_type(self, graph):
        with pytest.raises(ValueError, match="Unknown node type"):
            graph.add_node("bogus", "test")

    def test_get_node(self, graph):
        nid = graph.add_node("service", "API", {"port": 443})
        node = graph.get_node(nid)
        assert node is not None
        assert node.type == "service"
        assert node.label == "API"
        assert node.properties["port"] == 443

    def test_get_node_missing(self, graph):
        assert graph.get_node("N-nonexistent") is None

    def test_update_node(self, graph):
        nid = graph.add_node("asset", "example.com", {"kind": "domain"})
        graph.update_node(nid, {"in_scope": True})
        node = graph.get_node(nid)
        assert node.properties["kind"] == "domain"
        assert node.properties["in_scope"] is True

    def test_update_node_missing(self, graph):
        with pytest.raises(KeyError):
            graph.update_node("N-nope", {"x": 1})

    def test_nodes_by_type(self, graph):
        graph.add_node("asset", "a.com")
        graph.add_node("asset", "b.com")
        graph.add_node("service", "API")
        assets = graph.nodes_by_type("asset")
        assert len(assets) == 2
        assert all(n.type == "asset" for n in assets)

    def test_all_node_types_valid(self):
        assert len(NODE_TYPES) == 11


# -- Edge operations --------------------------------------------------------

class TestEdgeOperations:
    def test_add_edge_returns_id(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        eid = graph.add_edge("hosts", n1, n2)
        assert eid.startswith("E-")

    def test_add_edge_invalid_type(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        with pytest.raises(ValueError, match="Unknown edge type"):
            graph.add_edge("bogus_edge", n1, n2)

    def test_add_edge_invalid_confidence(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        with pytest.raises(ValueError, match="Unknown confidence"):
            graph.add_edge("hosts", n1, n2, confidence="maybe")

    def test_add_edge_missing_source(self, graph):
        n2 = graph.add_node("service", "API")
        with pytest.raises(KeyError, match="Source node"):
            graph.add_edge("hosts", "N-ghost", n2)

    def test_add_edge_missing_target(self, graph):
        n1 = graph.add_node("asset", "a.com")
        with pytest.raises(KeyError, match="Target node"):
            graph.add_edge("hosts", n1, "N-ghost")

    def test_get_edges_out(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        graph.add_edge("hosts", n1, n2)
        edges = graph.get_edges(n1, direction="out")
        assert len(edges) == 1
        assert edges[0].type == "hosts"

    def test_get_edges_in(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        graph.add_edge("hosts", n1, n2)
        edges = graph.get_edges(n2, direction="in")
        assert len(edges) == 1

    def test_get_edges_filtered(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        n3 = graph.add_node("service", "DB")
        graph.add_edge("hosts", n1, n2)
        graph.add_edge("calls", n2, n3)
        edges = graph.get_edges(n2, direction="both", edge_type="hosts")
        assert len(edges) == 1
        assert edges[0].type == "hosts"

    def test_update_confidence(self, graph):
        n1 = graph.add_node("finding", "F-001")
        n2 = graph.add_node("capability", "read_data")
        eid = graph.add_edge("grants", n1, n2, confidence="inferred")
        graph.update_confidence(eid, "demonstrated", evidence_refs=["EV-01"])
        edge = graph.get_edge(eid)
        assert edge.confidence == "demonstrated"
        assert "EV-01" in edge.evidence_refs

    def test_update_confidence_missing(self, graph):
        with pytest.raises(KeyError):
            graph.update_confidence("E-nope", "demonstrated")

    def test_edges_by_type(self, graph):
        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        n3 = graph.add_node("service", "DB")
        graph.add_edge("hosts", n1, n2)
        graph.add_edge("calls", n2, n3)
        hosts = graph.edges_by_type("hosts")
        assert len(hosts) == 1
        calls = graph.edges_by_type("calls")
        assert len(calls) == 1


# -- Persistence ------------------------------------------------------------

class TestPersistence:
    def test_round_trip(self, audit_dir):
        g1 = EngagementGraph(audit_dir)
        n1 = g1.add_node("asset", "a.com", {"kind": "domain"})
        n2 = g1.add_node("service", "API", {"port": 443})
        e1 = g1.add_edge("hosts", n1, n2, confidence="demonstrated")

        g2 = EngagementGraph(audit_dir)
        assert g2.get_node(n1) is not None
        assert g2.get_node(n1).label == "a.com"
        assert g2.get_node(n2).properties["port"] == 443
        edge = g2.get_edge(e1)
        assert edge is not None
        assert edge.confidence == "demonstrated"

    def test_update_survives_reload(self, audit_dir):
        g1 = EngagementGraph(audit_dir)
        nid = g1.add_node("asset", "a.com", {"kind": "domain"})
        g1.update_node(nid, {"in_scope": True})

        g2 = EngagementGraph(audit_dir)
        node = g2.get_node(nid)
        assert node.properties["in_scope"] is True

    def test_confidence_update_survives_reload(self, audit_dir):
        g1 = EngagementGraph(audit_dir)
        n1 = g1.add_node("finding", "F-001")
        n2 = g1.add_node("capability", "read_data")
        eid = g1.add_edge("grants", n1, n2, confidence="inferred")
        g1.update_confidence(eid, "demonstrated", evidence_refs=["EV-01"])

        g2 = EngagementGraph(audit_dir)
        edge = g2.get_edge(eid)
        assert edge.confidence == "demonstrated"

    def test_jsonl_append_only(self, audit_dir):
        g = EngagementGraph(audit_dir)
        g.add_node("asset", "a.com")
        g.add_node("asset", "b.com")
        lines = g.nodes_file.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_save_index(self, audit_dir):
        g = EngagementGraph(audit_dir)
        g.add_node("asset", "a.com")
        g.add_node("service", "API")
        n1 = list(g._nodes.keys())[0]
        n2 = list(g._nodes.keys())[1]
        g.add_edge("hosts", n1, n2)
        g.save_index()
        idx = json.loads(g.index_file.read_text())
        assert idx["node_count"] == 2
        assert idx["edge_count"] == 1

    def test_empty_graph_loads(self, audit_dir):
        g = EngagementGraph(audit_dir)
        assert g.summary()["node_count"] == 0
        assert g.summary()["edge_count"] == 0


# -- Query operations -------------------------------------------------------

class TestQueries:
    def test_query_by_node_type(self, populated_graph):
        graph, ids = populated_graph
        sub = graph.query(node_types=["finding", "capability"])
        assert ids["finding"] in sub.nodes
        assert ids["capability"] in sub.nodes

    def test_query_by_edge_type(self, populated_graph):
        graph, ids = populated_graph
        sub = graph.query(edge_types=["grants"])
        assert any(e.type == "grants" for e in sub.edges)
        assert ids["finding"] in sub.nodes
        assert ids["capability"] in sub.nodes

    def test_query_min_confidence(self, populated_graph):
        graph, ids = populated_graph
        sub = graph.query(min_confidence="demonstrated")
        for edge in sub.edges:
            assert edge.confidence == "demonstrated"

    def test_query_all(self, populated_graph):
        graph, ids = populated_graph
        sub = graph.query()
        assert sub.node_count == 12
        assert sub.edge_count == 12

    def test_unconnected_endpoints(self, populated_graph):
        graph, ids = populated_graph
        untested = graph.unconnected("endpoint", "tested_by", direction="out")
        assert len(untested) == 1
        assert untested[0].id == ids["endpoint_gql"]

    def test_neighbors(self, populated_graph):
        graph, ids = populated_graph
        nbrs = graph.neighbors(ids["asset"])
        labels = {n.label for n in nbrs}
        assert "GraphQL /gql/" in labels
        assert "REST v1 /api/*" in labels

    def test_neighbors_filtered(self, populated_graph):
        graph, ids = populated_graph
        nbrs = graph.neighbors(ids["rest"], edge_types=["exposes"])
        assert len(nbrs) == 1
        assert nbrs[0].id == ids["endpoint_goals"]


# -- Path finding -----------------------------------------------------------

class TestPathFinding:
    def test_find_path_to_capability(self, populated_graph):
        graph, ids = populated_graph
        paths = graph.find_paths(ids["finding"], goal_types=["hypothesis"])
        assert len(paths) >= 1
        assert paths[0].nodes[-1] == ids["hypothesis"]

    def test_find_path_respects_confidence(self, populated_graph):
        graph, ids = populated_graph
        paths = graph.find_paths(ids["finding"], goal_types=["hypothesis"],
                                 min_confidence="demonstrated")
        assert len(paths) == 0

    def test_find_path_respects_depth(self, populated_graph):
        graph, ids = populated_graph
        paths = graph.find_paths(ids["asset"], goal_types=["evidence"], max_depth=2)
        assert len(paths) == 0
        paths = graph.find_paths(ids["asset"], goal_types=["evidence"], max_depth=5)
        assert len(paths) >= 1

    def test_find_path_no_cycles(self, graph):
        n1 = graph.add_node("service", "A")
        n2 = graph.add_node("service", "B")
        n3 = graph.add_node("capability", "cap")
        graph.add_edge("calls", n1, n2)
        graph.add_edge("calls", n2, n1)
        graph.add_edge("grants", n2, n3)
        paths = graph.find_paths(n1, goal_types=["capability"], max_depth=10)
        assert len(paths) >= 1
        for p in paths:
            assert len(p.nodes) == len(set(p.nodes))

    def test_find_path_empty_graph(self, graph):
        paths = graph.find_paths("N-nothing", goal_types=["capability"])
        assert paths == []

    def test_max_50_paths(self, graph):
        root = graph.add_node("asset", "root")
        goals = [graph.add_node("capability", f"cap-{i}") for i in range(60)]
        for g in goals:
            graph.add_edge("grants", root, g)
        paths = graph.find_paths(root, goal_types=["capability"])
        assert len(paths) <= 50


# -- Serialization -----------------------------------------------------------

class TestSerialization:
    def test_to_dict(self, populated_graph):
        graph, ids = populated_graph
        d = graph.to_dict()
        assert len(d["nodes"]) == 12
        assert len(d["edges"]) == 12
        assert "summary" in d

    def test_to_json_file(self, populated_graph, tmp_path):
        graph, ids = populated_graph
        out = str(tmp_path / "export.json")
        graph.to_json(out)
        data = json.loads(Path(out).read_text())
        assert data["summary"]["node_count"] == 12

    def test_summary(self, populated_graph):
        graph, ids = populated_graph
        s = graph.summary()
        assert s["node_count"] == 12
        assert s["edge_count"] == 12
        assert "asset" in s["node_types"]
        assert "hosts" in s["edge_types"]
        assert "demonstrated" in s["confidence_distribution"]


# -- Custody integration ----------------------------------------------------

class TestCustodyIntegration:
    def test_mutations_log_to_custody(self, audit_dir):
        from engine.custody import CustodyLog
        custody = CustodyLog(audit_dir)
        graph = EngagementGraph(audit_dir, custody_log=custody)

        n1 = graph.add_node("asset", "a.com")
        n2 = graph.add_node("service", "API")
        eid = graph.add_edge("hosts", n1, n2)
        graph.update_confidence(eid, "demonstrated", reason="test")
        graph.update_node(n1, {"in_scope": True})

        report = custody.verify()
        assert report["entries"] == 5
        assert report["intact"] is True

    def test_no_custody_ok(self, audit_dir):
        graph = EngagementGraph(audit_dir, custody_log=None)
        n1 = graph.add_node("asset", "a.com")
        assert graph.get_node(n1) is not None
