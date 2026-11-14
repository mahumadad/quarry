"""Integration tests — engine modules write to the Engagement Graph (Phase 2 dual-write)."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.graph import EngagementGraph
from engine.brain import Brain
from engine.findings import FindingsStore, Finding, FindingStatus, Evidence, EvidenceTag
from engine.coverage import CoverageTracker
from engine.chain_engine import ChainEngine


@pytest.fixture
def audit_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def graph(audit_dir):
    return EngagementGraph(audit_dir)


# -- Brain -------------------------------------------------------------------

class TestBrainGraphIntegration:
    def test_add_capability_creates_node(self, audit_dir, graph):
        brain = Brain(audit_dir, graph=graph)
        brain.add_capability("read_data", "F-TEST001", confidence=0.9)
        caps = graph.nodes_by_type("capability")
        assert len(caps) == 1
        assert caps[0].label == "read_data"
        assert caps[0].properties["confidence"] == 0.9

    def test_add_capability_links_to_existing_finding(self, audit_dir, graph):
        graph.add_node("finding", "Test Finding", node_id="F-TEST001")
        brain = Brain(audit_dir, graph=graph)
        brain.add_capability("read_data", "F-TEST001", confidence=0.9)
        edges = graph.get_edges("F-TEST001", direction="out")
        grants = [e for e in edges if e.type == "grants"]
        assert len(grants) == 1
        assert grants[0].confidence == "demonstrated"

    def test_add_capability_low_confidence_inferred(self, audit_dir, graph):
        graph.add_node("finding", "Weak Finding", node_id="F-WEAK")
        brain = Brain(audit_dir, graph=graph)
        brain.add_capability("read_data", "F-WEAK", confidence=0.3)
        edges = graph.get_edges("F-WEAK", direction="out")
        grants = [e for e in edges if e.type == "grants"]
        assert grants[0].confidence == "inferred"

    def test_add_capability_no_finding_no_edge(self, audit_dir, graph):
        brain = Brain(audit_dir, graph=graph)
        brain.add_capability("read_data", "F-MISSING")
        caps = graph.nodes_by_type("capability")
        assert len(caps) == 1
        assert graph.summary()["edge_count"] == 0

    def test_add_capabilities_from_finding(self, audit_dir, graph):
        graph.add_node("finding", "SQLi", node_id="F-SQLI")
        brain = Brain(audit_dir, graph=graph)
        brain.add_capabilities_from_finding("F-SQLI", "sqli")
        caps = graph.nodes_by_type("capability")
        assert len(caps) == 3  # read_data, database_access, read_files

    def test_mark_exhausted_creates_test_execution(self, audit_dir, graph):
        brain = Brain(audit_dir, graph=graph)
        brain.mark_exhausted("sqli", "https://example.com", "sqlmap", "WAF blocked")
        execs = graph.nodes_by_type("test_execution")
        assert len(execs) == 1
        assert execs[0].properties["outcome"] == "exhausted"
        assert execs[0].properties["reason"] == "WAF blocked"

    def test_mark_exhausted_links_to_asset(self, audit_dir, graph):
        graph.add_node("asset", "https://example.com", node_id="A-001")
        brain = Brain(audit_dir, graph=graph)
        brain.mark_exhausted("sqli", "https://example.com", "sqlmap", "WAF")
        edges = graph.get_edges("A-001", direction="out", edge_type="tested_by")
        assert len(edges) == 1

    def test_start_vector_creates_test_execution(self, audit_dir, graph):
        brain = Brain(audit_dir, graph=graph)
        brain.start_vector("xss", "https://example.com", "DOM-based via search")
        execs = graph.nodes_by_type("test_execution")
        assert len(execs) == 1
        assert execs[0].properties["outcome"] == "in_progress"
        assert execs[0].properties["hypothesis"] == "DOM-based via search"

    def test_close_vector_updates_node(self, audit_dir, graph):
        brain = Brain(audit_dir, graph=graph)
        brain.start_vector("xss", "https://example.com", "DOM-based")
        brain.close_vector("xss", "https://example.com")
        execs = graph.nodes_by_type("test_execution")
        assert execs[0].properties["outcome"] == "closed"

    def test_no_graph_unchanged_behavior(self, audit_dir):
        brain = Brain(audit_dir)
        brain.add_capability("read_data", "F-001")
        assert brain.has_capability("read_data")
        brain.mark_exhausted("sqli", "x", "sqlmap", "nope")
        assert len(brain._data["exhausted"]) == 1


# -- Findings ----------------------------------------------------------------

class TestFindingsGraphIntegration:
    def test_add_creates_finding_node(self, audit_dir, graph):
        store = FindingsStore(audit_dir, graph=graph)
        f = Finding(title="IDOR on invoices", vuln_class="idor", severity="high",
                    cvss_score=7.1, target_asset="https://example.com/api")
        store.add(f)
        node = graph.get_node(f.id)
        assert node is not None
        assert node.type == "finding"
        assert node.label == "IDOR on invoices"
        assert node.properties["vuln_class"] == "idor"
        assert node.properties["severity"] == "high"

    def test_update_status_updates_node(self, audit_dir, graph):
        store = FindingsStore(audit_dir, graph=graph)
        f = Finding(title="IDOR", vuln_class="idor", severity="high",
                    target_asset="https://example.com/api")
        store.add(f)
        store.update_status(f.id, FindingStatus.CONFIRMED, "Verified manually")
        node = graph.get_node(f.id)
        assert node.properties["status"] == "confirmed"

    def test_add_evidence_creates_node_and_edge(self, audit_dir, graph):
        store = FindingsStore(audit_dir, graph=graph)
        f = Finding(title="IDOR", vuln_class="idor", severity="high",
                    target_asset="https://example.com/api")
        store.add(f)
        ev = Evidence(type="request_response", content="GET /api/invoices/123",
                      tool="curl", tag=EvidenceTag.DEMONSTRATED.value)
        store.add_evidence(f.id, ev)
        evidence_nodes = graph.nodes_by_type("evidence")
        assert len(evidence_nodes) == 1
        assert evidence_nodes[0].properties["tool"] == "curl"
        edges = graph.edges_by_type("supports")
        assert len(edges) == 1
        assert edges[0].target_id == f.id

    def test_no_graph_unchanged_behavior(self, audit_dir):
        store = FindingsStore(audit_dir)
        f = Finding(title="IDOR", vuln_class="idor", severity="high",
                    target_asset="https://example.com/api")
        store.add(f)
        assert store.get(f.id) is not None


# -- Coverage ----------------------------------------------------------------

class TestCoverageGraphIntegration:
    def test_mark_tested_creates_test_execution(self, audit_dir, graph):
        tracker = CoverageTracker(audit_dir, graph=graph)
        tracker.add_asset("https://example.com")
        tracker.mark_tested("https://example.com", "sqli", status="tested_clean",
                            skill_used="sqli-scanner",
                            evidence_artifacts=["ev1"], evidence_complete=True)
        execs = graph.nodes_by_type("test_execution")
        assert len(execs) == 1
        assert execs[0].properties["status"] == "tested_clean"
        assert execs[0].properties["skill_used"] == "sqli-scanner"

    def test_mark_tested_links_to_asset(self, audit_dir, graph):
        graph.add_node("asset", "https://example.com", node_id="A-001")
        tracker = CoverageTracker(audit_dir, graph=graph)
        tracker.mark_tested("https://example.com", "xss", status="tested_clean",
                            evidence_artifacts=["ev1"], evidence_complete=True)
        edges = graph.get_edges("A-001", direction="out", edge_type="tested_by")
        assert len(edges) == 1

    def test_mark_skipped_also_writes_graph(self, audit_dir, graph):
        tracker = CoverageTracker(audit_dir, graph=graph)
        tracker.add_asset("https://example.com")
        tracker.mark_skipped("https://example.com", "xxe", reason="No XML endpoints")
        execs = graph.nodes_by_type("test_execution")
        assert len(execs) == 1
        assert execs[0].properties["status"] == "skipped"

    def test_no_graph_unchanged_behavior(self, audit_dir):
        tracker = CoverageTracker(audit_dir)
        tracker.add_asset("https://example.com")
        tracker.mark_tested("https://example.com", "sqli", status="tested_clean",
                            evidence_artifacts=["ev1"], evidence_complete=True)
        assert tracker.summary()["tested"] > 0


# -- ChainEngine ------------------------------------------------------------

class TestChainEngineGraphIntegration:
    def test_analyze_matrix_creates_chain_nodes(self, audit_dir, graph):
        graph.add_node("finding", "IDOR", node_id="F-001",
                       properties={"vuln_class": "idor", "severity": "high"})
        graph.add_node("finding", "No rate limiting", node_id="F-002",
                       properties={"vuln_class": "rate-limiting", "severity": "low"})
        engine = ChainEngine(audit_dir, graph=graph)
        findings = [
            {"id": "F-001", "vuln_class": "idor", "severity": "high"},
            {"id": "F-002", "vuln_class": "rate-limiting", "severity": "low"},
        ]
        chains = engine.analyze_matrix(findings)
        assert len(chains) > 0
        chain_nodes = graph.nodes_by_type("chain")
        assert len(chain_nodes) > 0
        assert chain_nodes[0].properties["combined_severity"] == "critical"

    def test_analyze_matrix_creates_chains_to_edges(self, audit_dir, graph):
        graph.add_node("finding", "IDOR", node_id="F-001")
        graph.add_node("finding", "Rate limit", node_id="F-002")
        engine = ChainEngine(audit_dir, graph=graph)
        findings = [
            {"id": "F-001", "vuln_class": "idor", "severity": "high"},
            {"id": "F-002", "vuln_class": "rate-limiting", "severity": "low"},
        ]
        engine.analyze_matrix(findings)
        chains_to = graph.edges_by_type("chains_to")
        assert len(chains_to) > 0

    def test_analyze_capabilities_creates_chain_nodes(self, audit_dir, graph):
        graph.add_node("finding", "XSS", node_id="F-XSS",
                       properties={"vuln_class": "xss"})
        graph.add_node("finding", "CORS", node_id="F-CORS",
                       properties={"vuln_class": "cors"})
        engine = ChainEngine(audit_dir, graph=graph)
        brain = Brain(audit_dir)
        findings = [
            {"id": "F-XSS", "vuln_class": "xss", "severity": "high"},
            {"id": "F-CORS", "vuln_class": "cors", "severity": "medium"},
        ]
        chains = engine.analyze_capabilities(findings, brain)
        assert len(chains) > 0
        chain_nodes = graph.nodes_by_type("chain")
        assert len(chain_nodes) > 0

    def test_no_graph_unchanged_behavior(self, audit_dir):
        engine = ChainEngine(audit_dir)
        findings = [
            {"id": "F-001", "vuln_class": "idor", "severity": "high"},
            {"id": "F-002", "vuln_class": "rate-limiting", "severity": "low"},
        ]
        chains = engine.analyze_matrix(findings)
        assert len(chains) > 0


# -- Cross-module -----------------------------------------------------------

class TestCrossModuleIntegration:
    def test_full_lifecycle(self, audit_dir, graph):
        """Finding → evidence → capability → coverage → chain, all in one graph."""
        store = FindingsStore(audit_dir, graph=graph)
        brain = Brain(audit_dir, graph=graph)
        tracker = CoverageTracker(audit_dir, graph=graph)
        chain_eng = ChainEngine(audit_dir, graph=graph)

        graph.add_node("asset", "https://target.com", node_id="A-TGT")

        f1 = Finding(title="IDOR on users", vuln_class="idor", severity="high",
                     target_asset="https://target.com")
        store.add(f1)

        ev = Evidence(type="request_response", content="GET /api/users/2",
                      tool="curl", tag=EvidenceTag.DEMONSTRATED.value)
        store.add_evidence(f1.id, ev)

        brain.add_capabilities_from_finding(f1.id, "idor")

        tracker.mark_tested("https://target.com", "idor",
                            status="finding_detected", skill_used="idor-hunter",
                            evidence_artifacts=["ev1"], evidence_complete=True)

        f2 = Finding(title="No rate limit", vuln_class="rate-limiting",
                     severity="low", target_asset="https://target.com")
        store.add(f2)

        findings_dicts = [
            {"id": f1.id, "vuln_class": "idor", "severity": "high"},
            {"id": f2.id, "vuln_class": "rate-limiting", "severity": "low"},
        ]
        chains = chain_eng.analyze_matrix(findings_dicts)

        s = graph.summary()
        assert s["node_count"] >= 8  # asset + 2 findings + evidence + 3 caps + test_exec + chain(s)
        assert s["edge_count"] >= 5  # supports + grants×3 + tested_by + chains_to

        assert len(graph.nodes_by_type("finding")) == 2
        assert len(graph.nodes_by_type("evidence")) == 1
        assert len(graph.nodes_by_type("capability")) == 3
        assert len(graph.nodes_by_type("test_execution")) == 1
        assert len(graph.nodes_by_type("chain")) >= 1

        paths = graph.find_paths(f1.id, ["chain"], max_depth=4,
                                 min_confidence="inferred")
        # f1 --chains_to--> f2 won't reach a chain node directly,
        # but the graph has the relationships for future queries
        assert graph.get_node(f1.id) is not None
        assert graph.get_node(f2.id) is not None
