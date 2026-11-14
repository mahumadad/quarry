"""Phase 5 tests — graph-driven hunting: briefings, gaps, suggestions, chains."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.graph import EngagementGraph
from engine.graph_hunt import (
    generate_briefing, coverage_gaps, suggest_next_targets,
    chain_suggestions, subgraph_for_agent, CoverageGap, HuntSuggestion,
)


@pytest.fixture
def audit_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def rich_graph(audit_dir):
    """A realistic graph with multiple node types and relationships."""
    g = EngagementGraph(audit_dir)
    g.add_node("asset", "target.com", node_id="A-1")
    g.add_node("service", "REST API", node_id="S-1")
    g.add_node("endpoint", "GET /api/users", node_id="EP-1")
    g.add_node("endpoint", "POST /api/login", node_id="EP-2")
    g.add_node("endpoint", "GET /api/admin", node_id="EP-3")
    g.add_node("identity", "user-a@test.com", node_id="ID-A")
    g.add_node("identity", "user-b@test.com", node_id="ID-B")
    g.add_node("finding", "IDOR on users", node_id="F-1",
               properties={"severity": "high", "vuln_class": "idor", "status": "confirmed"})
    g.add_node("hypothesis", "Token survives pwd change", node_id="H-1",
               properties={"status": "active", "priority": "high",
                           "basis": "JWT stateless"})
    g.add_node("hypothesis", "CSRF on settings", node_id="H-2",
               properties={"status": "disproved", "priority": "medium"})
    g.add_node("test_execution", "IDOR test user-a", node_id="TE-1",
               properties={"status": "finding_detected", "identity_used": "ID-A"})
    g.add_node("evidence", "HTTP 200 for foreign ID", node_id="EV-1")
    g.add_node("capability", "read_data", node_id="CAP-1")

    g.add_edge("hosts", "A-1", "S-1", confidence="observed")
    g.add_edge("exposes", "S-1", "EP-1", confidence="observed")
    g.add_edge("exposes", "S-1", "EP-2", confidence="observed")
    g.add_edge("exposes", "S-1", "EP-3", confidence="observed")
    g.add_edge("authenticates_to", "ID-A", "S-1", confidence="demonstrated")
    g.add_edge("authenticates_to", "ID-B", "S-1", confidence="demonstrated")
    g.add_edge("tested_by", "EP-1", "TE-1", confidence="observed")
    g.add_edge("supports", "EV-1", "F-1", confidence="demonstrated")
    g.add_edge("grants", "F-1", "CAP-1", confidence="demonstrated")
    g.add_edge("involves", "H-1", "EP-2", confidence="hypothesized")
    g.add_edge("produced", "TE-1", "EV-1", confidence="observed")
    return g


# -- Briefing ----------------------------------------------------------------

class TestGenerateBriefing:
    def test_briefing_for_service(self, rich_graph):
        b = generate_briefing(rich_graph, "S-1", depth=2)
        assert b.target_id == "S-1"
        assert b.target_label == "REST API"
        assert b.subgraph_nodes > 0
        assert b.subgraph_edges > 0

    def test_briefing_includes_capabilities(self, rich_graph):
        b = generate_briefing(rich_graph, "S-1", depth=5)
        cap_labels = [c["label"] for c in b.capabilities]
        assert "read_data" in cap_labels

    def test_briefing_includes_active_hypotheses(self, rich_graph):
        b = generate_briefing(rich_graph, "S-1", depth=3)
        hyp_ids = [h["id"] for h in b.active_hypotheses]
        assert "H-1" in hyp_ids
        assert "H-2" not in hyp_ids  # disproved

    def test_briefing_includes_findings(self, rich_graph):
        b = generate_briefing(rich_graph, "S-1", depth=5)
        finding_ids = [f["id"] for f in b.related_findings]
        assert "F-1" in finding_ids

    def test_briefing_has_context_summary(self, rich_graph):
        b = generate_briefing(rich_graph, "S-1", depth=3)
        assert "REST API" in b.context_summary
        assert "service" in b.context_summary

    def test_briefing_for_nonexistent_node(self, rich_graph):
        b = generate_briefing(rich_graph, "NOPE")
        assert b.target_label == "(not found)"
        assert b.subgraph_nodes == 0

    def test_briefing_for_endpoint(self, rich_graph):
        b = generate_briefing(rich_graph, "EP-1", depth=2)
        assert b.target_label == "GET /api/users"
        assert b.subgraph_nodes >= 2  # at least EP-1 + TE-1


# -- Coverage gaps -----------------------------------------------------------

class TestCoverageGaps:
    def test_untested_endpoints_flagged(self, rich_graph):
        gaps = coverage_gaps(rich_graph)
        untested = [g for g in gaps if g.missing == "no_tests"]
        untested_ids = {g.endpoint_id for g in untested}
        assert "EP-2" in untested_ids  # no tested_by edge
        assert "EP-3" in untested_ids

    def test_tested_endpoint_no_no_tests_gap(self, rich_graph):
        gaps = coverage_gaps(rich_graph)
        untested_ids = {g.endpoint_id for g in gaps if g.missing == "no_tests"}
        assert "EP-1" not in untested_ids

    def test_identity_gap_detected(self, rich_graph):
        gaps = coverage_gaps(rich_graph)
        identity_gaps = [g for g in gaps
                         if g.missing == "identity_gap" and g.endpoint_id == "EP-1"]
        assert len(identity_gaps) == 1
        assert "user-b" in identity_gaps[0].detail or "ID-B" in identity_gaps[0].detail

    def test_scoped_to_service(self, rich_graph):
        gaps = coverage_gaps(rich_graph, scope_node_id="S-1")
        ep_ids = {g.endpoint_id for g in gaps}
        assert ep_ids <= {"EP-1", "EP-2", "EP-3"}

    def test_empty_graph_no_gaps(self, audit_dir):
        g = EngagementGraph(audit_dir)
        gaps = coverage_gaps(g)
        assert gaps == []


# -- Suggest next targets ----------------------------------------------------

class TestSuggestNextTargets:
    def test_untested_endpoints_suggested(self, rich_graph):
        suggs = suggest_next_targets(rich_graph)
        untested_eps = [s for s in suggs if s.target_type == "endpoint"
                        and s.reason == "Untested endpoint"]
        untested_ids = {s.target_id for s in untested_eps}
        assert "EP-2" in untested_ids or "EP-3" in untested_ids

    def test_active_hypotheses_suggested(self, rich_graph):
        suggs = suggest_next_targets(rich_graph)
        hyp_suggs = [s for s in suggs if s.target_type == "hypothesis"]
        assert any(s.target_id == "H-1" for s in hyp_suggs)

    def test_disproved_hypotheses_not_suggested(self, rich_graph):
        suggs = suggest_next_targets(rich_graph)
        hyp_ids = {s.target_id for s in suggs if s.target_type == "hypothesis"}
        assert "H-2" not in hyp_ids

    def test_max_results_respected(self, rich_graph):
        suggs = suggest_next_targets(rich_graph, max_results=2)
        assert len(suggs) <= 2

    def test_empty_graph(self, audit_dir):
        g = EngagementGraph(audit_dir)
        suggs = suggest_next_targets(g)
        assert suggs == []

    def test_capability_enables_untested(self, audit_dir):
        g = EngagementGraph(audit_dir)
        g.add_node("capability", "internal_network", node_id="CAP-INT")
        g.add_node("service", "Internal DB", node_id="S-DB")
        g.add_edge("enables", "CAP-INT", "S-DB", confidence="inferred")
        suggs = suggest_next_targets(g)
        enabled = [s for s in suggs if s.target_id == "S-DB"]
        assert len(enabled) == 1
        assert "internal_network" in enabled[0].reason


# -- Chain suggestions ------------------------------------------------------

class TestChainSuggestions:
    def test_finds_chains_through_capabilities(self, audit_dir):
        g = EngagementGraph(audit_dir)
        g.add_node("finding", "SSRF", node_id="F-SSRF")
        g.add_node("capability", "internal_network", node_id="CAP-NET")
        g.add_node("service", "Metadata endpoint", node_id="S-META")
        g.add_edge("grants", "F-SSRF", "CAP-NET", confidence="demonstrated")
        g.add_edge("enables", "CAP-NET", "S-META", confidence="inferred")
        chains = chain_suggestions(g, max_depth=4)
        assert len(chains) >= 1
        assert chains[0]["finding_id"] == "F-SSRF"
        assert chains[0]["capability"] == "internal_network"
        assert chains[0]["enables_target_id"] == "S-META"

    def test_no_chains_without_enables(self, rich_graph):
        chains = chain_suggestions(rich_graph)
        assert isinstance(chains, list)


# -- Subgraph for agent -----------------------------------------------------

class TestSubgraphForAgent:
    def test_returns_dict_with_nodes_and_edges(self, rich_graph):
        sg = subgraph_for_agent(rich_graph, "S-1", depth=1)
        assert "nodes" in sg
        assert "edges" in sg
        assert "target" in sg
        assert sg["target"] == "S-1"

    def test_depth_limits_traversal(self, rich_graph):
        sg1 = subgraph_for_agent(rich_graph, "A-1", depth=1)
        sg2 = subgraph_for_agent(rich_graph, "A-1", depth=3)
        assert len(sg2["nodes"]) >= len(sg1["nodes"])

    def test_include_types_filters(self, rich_graph):
        sg = subgraph_for_agent(rich_graph, "S-1", depth=2,
                                include_types=["endpoint", "service"])
        node_types = {n["type"] for n in sg["nodes"]}
        assert node_types <= {"endpoint", "service"}

    def test_edges_reference_included_nodes(self, rich_graph):
        sg = subgraph_for_agent(rich_graph, "S-1", depth=2)
        node_ids = {n["id"] for n in sg["nodes"]}
        for e in sg["edges"]:
            assert e["source"] in node_ids
            assert e["target"] in node_ids

    def test_nonexistent_target_returns_empty(self, rich_graph):
        sg = subgraph_for_agent(rich_graph, "NOPE")
        assert sg["nodes"] == []
        assert sg["edges"] == []
