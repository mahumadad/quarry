"""Phase 6 tests — independent finding verification via the graph."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.graph import EngagementGraph
from engine.test_tracker import TestExecutionTracker
from engine.graph_verify import (
    prepare_verification, record_verification, verification_summary,
    findings_needing_verification, VERIFICATION_STATUSES,
    VerificationRequest, VerificationResult,
)


@pytest.fixture
def audit_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def graph(audit_dir):
    return EngagementGraph(audit_dir)


@pytest.fixture
def tracker(audit_dir, graph):
    return TestExecutionTracker(audit_dir, graph=graph)


@pytest.fixture
def finding_graph(graph):
    """Graph with a finding, evidence, test execution, and target endpoint."""
    graph.add_node("endpoint", "GET /api/users/:id", node_id="EP-1")
    graph.add_node("finding", "IDOR on users", node_id="F-1",
                   properties={"severity": "high", "vuln_class": "idor",
                               "target_asset": "https://target.com/api",
                               "status": "confirmed"})
    graph.add_node("evidence", "HTTP 200 for foreign user ID", node_id="EV-1",
                   properties={"type": "request_response",
                               "content": "GET /api/users/2 → 200 OK",
                               "tool": "curl", "tag": "demonstrated"})
    graph.add_node("test_execution", "IDOR test attempt", node_id="TE-ORIG",
                   properties={"technique": "sequential-id-enum",
                               "tool": "curl",
                               "status": "finding_detected",
                               "identity_used": "account-a",
                               "notes": "Changed ID from 1 to 2"})

    graph.add_edge("supports", "EV-1", "F-1", confidence="demonstrated")
    graph.add_edge("tested_by", "EP-1", "TE-ORIG", confidence="observed")
    return graph


# -- prepare_verification ---------------------------------------------------

class TestPrepareVerification:
    def test_returns_request(self, finding_graph):
        vr = prepare_verification(finding_graph, "F-1")
        assert isinstance(vr, VerificationRequest)
        assert vr.finding_id == "F-1"
        assert vr.finding_label == "IDOR on users"
        assert vr.vuln_class == "idor"
        assert vr.severity == "high"

    def test_evidence_subgraph_excludes_finding(self, finding_graph):
        vr = prepare_verification(finding_graph, "F-1")
        node_types = {n["type"] for n in vr.evidence_subgraph["nodes"]}
        assert "finding" not in node_types

    def test_evidence_subgraph_includes_evidence(self, finding_graph):
        vr = prepare_verification(finding_graph, "F-1")
        ev_nodes = [n for n in vr.evidence_subgraph["nodes"]
                    if n["type"] == "evidence"]
        assert len(ev_nodes) == 1
        assert ev_nodes[0]["id"] == "EV-1"

    def test_evidence_artifacts_populated(self, finding_graph):
        vr = prepare_verification(finding_graph, "F-1")
        assert len(vr.evidence_artifacts) == 1
        assert vr.evidence_artifacts[0]["tool"] == "curl"
        assert "200 OK" in vr.evidence_artifacts[0]["content"]

    def test_steps_to_reproduce_generated(self, finding_graph):
        vr = prepare_verification(finding_graph, "F-1")
        assert len(vr.steps_to_reproduce) > 0

    def test_nonexistent_finding(self, graph):
        vr = prepare_verification(graph, "F-NOPE")
        assert vr.finding_label == "(not found)"
        assert vr.evidence_subgraph["nodes"] == []

    def test_finding_with_no_evidence(self, graph):
        graph.add_node("finding", "Bare finding", node_id="F-BARE",
                       properties={"severity": "low", "vuln_class": "info"})
        vr = prepare_verification(graph, "F-BARE")
        assert vr.finding_id == "F-BARE"
        assert len(vr.evidence_artifacts) == 0
        assert len(vr.steps_to_reproduce) == 0


# -- record_verification ----------------------------------------------------

class TestRecordVerification:
    def test_confirmed_creates_supports_edge(self, finding_graph, tracker):
        result = record_verification(
            finding_graph, tracker, "F-1",
            status="confirmed", technique="manual-replay",
            tool="curl", notes="Reproduced successfully")
        assert isinstance(result, VerificationResult)
        assert result.status == "confirmed"
        assert result.test_execution_id.startswith("TE-")

        supports = [e for e in finding_graph.edges_by_type("supports")
                    if e.properties.get("verification")]
        assert len(supports) == 1
        assert supports[0].target_id == "F-1"

    def test_not_reproduced_creates_refutes_edge(self, finding_graph, tracker):
        result = record_verification(
            finding_graph, tracker, "F-1",
            status="not_reproduced", technique="manual-replay",
            notes="Could not reproduce")
        assert result.status == "not_reproduced"

        refutes = [e for e in finding_graph.edges_by_type("refutes")
                   if e.properties.get("verification")]
        assert len(refutes) == 1
        assert refutes[0].target_id == "F-1"

    def test_partial_no_extra_edge(self, finding_graph, tracker):
        result = record_verification(
            finding_graph, tracker, "F-1",
            status="partial", notes="Partially reproduced")
        verification_edges = [
            e for e in finding_graph.get_edges("F-1", direction="in")
            if e.properties.get("verification")
        ]
        assert len(verification_edges) == 0

    def test_blocked_no_extra_edge(self, finding_graph, tracker):
        result = record_verification(
            finding_graph, tracker, "F-1",
            status="blocked", notes="WAF blocked request")
        assert result.status == "blocked"

    def test_invalid_status_raises(self, finding_graph, tracker):
        with pytest.raises(ValueError, match="Invalid verification status"):
            record_verification(finding_graph, tracker, "F-1",
                                status="maybe")

    def test_creates_test_execution_node(self, finding_graph, tracker):
        result = record_verification(
            finding_graph, tracker, "F-1",
            status="confirmed", technique="replay")
        te_node = finding_graph.get_node(result.test_execution_id)
        assert te_node is not None
        assert te_node.type == "test_execution"
        assert "verification:confirmed" in te_node.properties.get("notes", "")

    def test_maps_to_correct_te_status(self, finding_graph, tracker):
        r1 = record_verification(finding_graph, tracker, "F-1",
                                 status="confirmed")
        te1 = tracker.get(r1.test_execution_id)
        assert te1.status == "finding_detected"

        r2 = record_verification(finding_graph, tracker, "F-1",
                                 status="not_reproduced")
        te2 = tracker.get(r2.test_execution_id)
        assert te2.status == "pass"


# -- verification_summary ---------------------------------------------------

class TestVerificationSummary:
    def test_all_unverified(self, graph):
        graph.add_node("finding", "F1", node_id="F-1")
        graph.add_node("finding", "F2", node_id="F-2")
        s = verification_summary(graph)
        assert s["total_findings"] == 2
        assert s["unverified"] == 2
        assert s["verified"] == 0
        assert s["verification_rate"] == 0

    def test_with_verified(self, finding_graph, tracker):
        record_verification(finding_graph, tracker, "F-1",
                            status="confirmed")
        s = verification_summary(finding_graph)
        assert s["verified"] == 1
        assert s["verification_rate"] == 100.0

    def test_with_refuted(self, finding_graph, tracker):
        record_verification(finding_graph, tracker, "F-1",
                            status="not_reproduced")
        s = verification_summary(finding_graph)
        assert s["refuted"] == 1
        assert s["verified"] == 0

    def test_empty_graph(self, graph):
        s = verification_summary(graph)
        assert s["total_findings"] == 0
        assert s["verification_rate"] == 0


# -- findings_needing_verification ------------------------------------------

class TestFindingsNeedingVerification:
    def test_all_need_verification(self, graph):
        graph.add_node("finding", "High sev", node_id="F-H",
                       properties={"severity": "high", "vuln_class": "idor"})
        graph.add_node("finding", "Critical sev", node_id="F-C",
                       properties={"severity": "critical", "vuln_class": "rce"})
        needs = findings_needing_verification(graph)
        assert len(needs) == 2
        assert needs[0]["severity"] == "critical"
        assert needs[1]["severity"] == "high"

    def test_verified_excluded(self, finding_graph, tracker):
        record_verification(finding_graph, tracker, "F-1",
                            status="confirmed")
        needs = findings_needing_verification(finding_graph)
        ids = {f["id"] for f in needs}
        assert "F-1" not in ids

    def test_refuted_excluded(self, finding_graph, tracker):
        record_verification(finding_graph, tracker, "F-1",
                            status="not_reproduced")
        needs = findings_needing_verification(finding_graph)
        ids = {f["id"] for f in needs}
        assert "F-1" not in ids

    def test_empty_graph(self, graph):
        needs = findings_needing_verification(graph)
        assert needs == []
