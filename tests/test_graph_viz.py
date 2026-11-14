"""Phase 4 tests — Cytoscape.js graph visualization export."""

import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.graph import EngagementGraph
from engine.graph_viz import (
    to_cytoscape_elements, to_cytoscape_json, generate_html,
    NODE_COLORS, NODE_SHAPES, CONFIDENCE_STYLES, VIEWS,
)


@pytest.fixture
def audit_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def populated_graph(audit_dir):
    g = EngagementGraph(audit_dir)
    g.add_node("asset", "target.com", node_id="A-1")
    g.add_node("service", "REST API", node_id="S-1")
    g.add_node("endpoint", "GET /api/users", node_id="EP-1")
    g.add_node("endpoint", "POST /api/login", node_id="EP-2")
    g.add_node("identity", "admin@target.com", node_id="ID-1")
    g.add_node("finding", "IDOR on users", node_id="F-1",
               properties={"severity": "high", "vuln_class": "idor"})
    g.add_node("hypothesis", "Token reuse", node_id="H-1",
               properties={"status": "active", "priority": "high"})
    g.add_node("test_execution", "IDOR test", node_id="TE-1",
               properties={"status": "finding_detected"})
    g.add_node("evidence", "HTTP 200 for foreign ID", node_id="EV-1")
    g.add_node("capability", "read_data", node_id="CAP-1")

    g.add_edge("hosts", "A-1", "S-1", confidence="observed")
    g.add_edge("exposes", "S-1", "EP-1", confidence="observed")
    g.add_edge("exposes", "S-1", "EP-2", confidence="observed")
    g.add_edge("authenticates_to", "ID-1", "S-1", confidence="demonstrated")
    g.add_edge("tested_by", "EP-1", "TE-1", confidence="observed")
    g.add_edge("supports", "EV-1", "F-1", confidence="demonstrated")
    g.add_edge("grants", "F-1", "CAP-1", confidence="demonstrated")
    g.add_edge("involves", "H-1", "EP-2", confidence="hypothesized")
    return g


class TestCytoscapeElements:
    def test_all_nodes_exported(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph)
        nodes = [e for e in elements if e["group"] == "nodes"]
        assert len(nodes) == 10

    def test_all_edges_exported(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph)
        edges = [e for e in elements if e["group"] == "edges"]
        assert len(edges) == 8

    def test_node_has_required_fields(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph)
        node = next(e for e in elements if e["data"]["id"] == "A-1")
        assert node["group"] == "nodes"
        assert node["data"]["label"] == "target.com"
        assert node["data"]["node_type"] == "asset"
        assert node["classes"] == "asset"

    def test_edge_has_required_fields(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph)
        edge = next(e for e in elements
                    if e["group"] == "edges" and e["data"]["edge_type"] == "hosts")
        assert edge["data"]["source"] == "A-1"
        assert edge["data"]["target"] == "S-1"
        assert edge["data"]["confidence"] == "observed"

    def test_filter_by_node_type(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph,
                                          node_types=["asset", "service"])
        nodes = [e for e in elements if e["group"] == "nodes"]
        types = {n["data"]["node_type"] for n in nodes}
        assert types == {"asset", "service"}

    def test_filter_by_min_confidence(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph,
                                          min_confidence="observed")
        edges = [e for e in elements if e["group"] == "edges"]
        for e in edges:
            assert e["data"]["confidence"] in ("observed", "demonstrated", "disproved")

    def test_filter_by_edge_type(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph,
                                          edge_types=["hosts", "exposes"])
        edges = [e for e in elements if e["group"] == "edges"]
        types = {e["data"]["edge_type"] for e in edges}
        assert types <= {"hosts", "exposes"}

    def test_edges_only_between_included_nodes(self, populated_graph):
        elements = to_cytoscape_elements(populated_graph,
                                          node_types=["finding", "evidence"])
        node_ids = {e["data"]["id"] for e in elements if e["group"] == "nodes"}
        for e in elements:
            if e["group"] == "edges":
                assert e["data"]["source"] in node_ids
                assert e["data"]["target"] in node_ids

    def test_empty_graph(self, audit_dir):
        g = EngagementGraph(audit_dir)
        elements = to_cytoscape_elements(g)
        assert elements == []


class TestCytoscapeJSON:
    def test_valid_json(self, populated_graph):
        text = to_cytoscape_json(populated_graph)
        data = json.loads(text)
        assert isinstance(data, list)

    def test_view_architecture(self, populated_graph):
        text = to_cytoscape_json(populated_graph, view="architecture")
        data = json.loads(text)
        node_types = {e["data"]["node_type"] for e in data if e["group"] == "nodes"}
        assert node_types <= {"asset", "service", "endpoint", "trust_boundary"}

    def test_view_coverage(self, populated_graph):
        text = to_cytoscape_json(populated_graph, view="coverage")
        data = json.loads(text)
        node_types = {e["data"]["node_type"] for e in data if e["group"] == "nodes"}
        assert node_types <= {"endpoint", "test_execution", "hypothesis"}

    def test_write_to_file(self, populated_graph, audit_dir):
        path = os.path.join(audit_dir, "graph.json")
        to_cytoscape_json(populated_graph, path=path)
        assert os.path.exists(path)
        data = json.loads(open(path).read())
        assert isinstance(data, list)


class TestHTMLGeneration:
    def test_generates_valid_html(self, populated_graph):
        html = generate_html(populated_graph, title="Test Graph")
        assert "<!DOCTYPE html>" in html
        assert "cytoscape" in html.lower()
        assert "Test Graph" in html

    def test_contains_elements(self, populated_graph):
        html = generate_html(populated_graph)
        assert "A-1" in html
        assert "target.com" in html
        assert "hosts" in html

    def test_contains_filter_ui(self, populated_graph):
        html = generate_html(populated_graph)
        assert "node-filter" in html
        assert "conf-filter" in html
        assert "view-group" in html

    def test_contains_inspector(self, populated_graph):
        html = generate_html(populated_graph)
        assert "inspector" in html
        assert "inspector-table" in html

    def test_write_to_file(self, populated_graph, audit_dir):
        path = os.path.join(audit_dir, "graph.html")
        generate_html(populated_graph, path=path)
        assert os.path.exists(path)
        content = open(path).read()
        assert "<!DOCTYPE html>" in content

    def test_view_filter_applied(self, populated_graph):
        html = generate_html(populated_graph, view="attack_paths")
        assert "attack_paths" in html or "attack paths" in html

    def test_escapes_title(self, populated_graph):
        html = generate_html(populated_graph, title='<script>alert("xss")</script>')
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_all_views_exist(self):
        expected = {"all", "architecture", "trust", "identity",
                    "attack_paths", "coverage", "evidence"}
        assert set(VIEWS.keys()) == expected


class TestConstants:
    def test_all_node_types_have_color(self):
        from engine.graph import NODE_TYPES
        for nt in NODE_TYPES:
            assert nt in NODE_COLORS, f"Missing color for {nt}"

    def test_all_node_types_have_shape(self):
        from engine.graph import NODE_TYPES
        for nt in NODE_TYPES:
            assert nt in NODE_SHAPES, f"Missing shape for {nt}"

    def test_all_confidence_levels_have_style(self):
        from engine.graph import CONFIDENCE_LEVELS
        for c in CONFIDENCE_LEVELS:
            assert c in CONFIDENCE_STYLES, f"Missing style for {c}"
