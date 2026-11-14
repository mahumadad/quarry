"""Phase 3 tests — Hypothesis Journal + Test Execution Tracker + graph integration."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.graph import EngagementGraph
from engine.hypothesis import HypothesisJournal, Hypothesis, HYPOTHESIS_TRANSITIONS
from engine.test_tracker import TestExecutionTracker, TestExecution


@pytest.fixture
def audit_dir():
    return tempfile.mkdtemp()


@pytest.fixture
def graph(audit_dir):
    return EngagementGraph(audit_dir)


# -- HypothesisJournal (standalone) -----------------------------------------

class TestHypothesisJournal:
    def test_propose(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token survives password change",
                            "Old refresh token may remain valid",
                            "JWT tokens are stateless")
        assert h.id.startswith("H-")
        assert h.status == "active"
        assert h.label == "Token survives password change"

    def test_propose_invalid_priority(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        with pytest.raises(ValueError, match="Invalid priority"):
            journal.propose("X", "Y", "Z", priority="ultra")

    def test_start_testing(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token test", "desc", "basis")
        assert journal.start_testing(h.id, test_plan="Replay old token")
        assert journal.get(h.id).status == "testing"
        assert journal.get(h.id).test_plan == "Replay old token"

    def test_confirm(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token test", "desc", "basis")
        journal.start_testing(h.id)
        assert journal.confirm(h.id, finding_id="F-001", reason="Token was valid")
        assert journal.get(h.id).status == "confirmed"
        assert journal.get(h.id).resolution_id == "F-001"

    def test_disprove(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token test", "desc", "basis")
        journal.start_testing(h.id)
        assert journal.disprove(h.id, test_execution_id="TE-001",
                                reason="Token was revoked")
        assert journal.get(h.id).status == "disproved"

    def test_defer_and_reactivate(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token test", "desc", "basis")
        assert journal.defer(h.id, reason="Missing credentials")
        assert journal.get(h.id).status == "deferred"
        assert journal.reactivate(h.id)
        assert journal.get(h.id).status == "active"

    def test_invalid_transition(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("Token test", "desc", "basis")
        assert not journal.confirm(h.id)  # active → confirmed not allowed
        assert not journal.disprove(h.id)  # active → disproved not allowed

    def test_terminal_states(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        h = journal.propose("A", "B", "C")
        journal.start_testing(h.id)
        journal.confirm(h.id)
        assert not journal.start_testing(h.id)  # confirmed is terminal
        assert not journal.reactivate(h.id)

    def test_list_by_status(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        journal.propose("H1", "d", "b", priority="high")
        h2 = journal.propose("H2", "d", "b")
        journal.start_testing(h2.id)
        assert len(journal.list_by_status("active")) == 1
        assert len(journal.list_by_status("testing")) == 1
        assert len(journal.list_by_status()) == 2

    def test_list_by_priority(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        journal.propose("Low", "d", "b", priority="low")
        journal.propose("Critical", "d", "b", priority="critical")
        journal.propose("High", "d", "b", priority="high")
        ordered = journal.list_by_priority()
        assert [h.priority for h in ordered] == ["critical", "high", "low"]

    def test_persistence(self, audit_dir):
        journal1 = HypothesisJournal(audit_dir)
        h = journal1.propose("Persistent", "desc", "basis")
        journal2 = HypothesisJournal(audit_dir)
        assert journal2.get(h.id) is not None
        assert journal2.get(h.id).label == "Persistent"

    def test_summary(self, audit_dir):
        journal = HypothesisJournal(audit_dir)
        journal.propose("H1", "d", "b", priority="high")
        journal.propose("H2", "d", "b", priority="medium")
        h3 = journal.propose("H3", "d", "b", priority="high")
        journal.start_testing(h3.id)
        s = journal.summary()
        assert s["total"] == 3
        assert s["by_status"]["active"] == 2
        assert s["by_status"]["testing"] == 1
        assert s["by_priority"]["high"] == 2


# -- HypothesisJournal + Graph ----------------------------------------------

class TestHypothesisGraphIntegration:
    def test_propose_creates_node(self, audit_dir, graph):
        journal = HypothesisJournal(audit_dir, graph=graph)
        h = journal.propose("CORS round-trip", "Steal token via CORS",
                            "Permissive CORS observed")
        node = graph.get_node(h.id)
        assert node is not None
        assert node.type == "hypothesis"
        assert node.properties["status"] == "active"

    def test_propose_links_to_findings(self, audit_dir, graph):
        graph.add_node("finding", "CORS Finding", node_id="F-CORS")
        journal = HypothesisJournal(audit_dir, graph=graph)
        h = journal.propose("CORS round-trip", "desc", "basis",
                            related_finding_ids=["F-CORS"])
        edges = graph.get_edges(h.id, direction="out")
        derived = [e for e in edges if e.type == "derived_from"]
        assert len(derived) == 1
        assert derived[0].target_id == "F-CORS"

    def test_propose_links_to_assets(self, audit_dir, graph):
        graph.add_node("service", "REST API v1", node_id="S-REST")
        journal = HypothesisJournal(audit_dir, graph=graph)
        h = journal.propose("Token leak", "desc", "basis",
                            related_node_ids=["S-REST"])
        edges = graph.get_edges(h.id, direction="out")
        involves = [e for e in edges if e.type == "involves"]
        assert len(involves) == 1
        assert involves[0].confidence == "hypothesized"

    def test_transition_updates_node(self, audit_dir, graph):
        journal = HypothesisJournal(audit_dir, graph=graph)
        h = journal.propose("Test", "desc", "basis")
        journal.start_testing(h.id, test_plan="Run the test")
        node = graph.get_node(h.id)
        assert node.properties["status"] == "testing"

    def test_disprove_creates_refutes_edge(self, audit_dir, graph):
        journal = HypothesisJournal(audit_dir, graph=graph)
        h = journal.propose("CSRF possible", "desc", "basis")
        journal.start_testing(h.id)
        graph.add_node("test_execution", "CSRF test", node_id="TE-001")
        journal.disprove(h.id, test_execution_id="TE-001",
                         reason="Token validated server-side")
        refutes = graph.edges_by_type("refutes")
        assert len(refutes) == 1
        assert refutes[0].source_id == "TE-001"
        assert refutes[0].target_id == h.id


# -- TestExecutionTracker (standalone) --------------------------------------

class TestTestExecutionTracker:
    def test_record(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        te = tracker.record("IDOR test on /users", "sequential-id-enum",
                            tool="curl", vuln_class="idor", status="pass")
        assert te.id.startswith("TE-")
        assert te.status == "pass"
        assert te.technique == "sequential-id-enum"

    def test_record_invalid_status(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        with pytest.raises(ValueError, match="Invalid status"):
            tracker.record("X", "Y", status="exploded")

    def test_update_status(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        te = tracker.record("IDOR test", "id-enum", status="in_progress")
        assert tracker.update_status(te.id, "finding_detected",
                                     notes="Got 200 for foreign ID",
                                     finding_id="F-001")
        updated = tracker.get(te.id)
        assert updated.status == "finding_detected"
        assert updated.finding_id == "F-001"
        assert updated.notes == "Got 200 for foreign ID"

    def test_update_nonexistent(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        assert not tracker.update_status("TE-NOPE", "pass")

    def test_list_for_target(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        tracker.record("Test A", "tech-a", target_node_id="EP-001",
                        vuln_class="sqli", status="pass")
        tracker.record("Test B", "tech-b", target_node_id="EP-001",
                        vuln_class="xss", status="fail")
        tracker.record("Test C", "tech-c", target_node_id="EP-002",
                        status="pass")
        assert len(tracker.list_for_target("EP-001")) == 2
        assert len(tracker.list_for_target("EP-002")) == 1

    def test_list_by_status(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        tracker.record("A", "t", status="pass")
        tracker.record("B", "t", status="fail")
        tracker.record("C", "t", status="pass")
        assert len(tracker.list_by_status("pass")) == 2
        assert len(tracker.list_by_status("fail")) == 1
        assert len(tracker.list_by_status()) == 3

    def test_list_by_vuln_class(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        tracker.record("A", "t", vuln_class="sqli", status="pass")
        tracker.record("B", "t", vuln_class="sqli", status="fail")
        tracker.record("C", "t", vuln_class="xss", status="pass")
        assert len(tracker.list_by_vuln_class("sqli")) == 2

    def test_persistence(self, audit_dir):
        t1 = TestExecutionTracker(audit_dir)
        te = t1.record("Persistent", "tech", status="pass")
        t2 = TestExecutionTracker(audit_dir)
        assert t2.get(te.id) is not None

    def test_coverage_stats(self, audit_dir):
        tracker = TestExecutionTracker(audit_dir)
        tracker.record("A", "t", target_node_id="EP-1", vuln_class="sqli",
                        status="pass")
        tracker.record("B", "t", target_node_id="EP-1", vuln_class="xss",
                        status="fail")
        tracker.record("C", "t", target_node_id="EP-2", vuln_class="sqli",
                        status="pass")
        stats = tracker.coverage_stats()
        assert stats["total"] == 3
        assert stats["targets_tested"] == 2
        assert stats["by_status"]["pass"] == 2
        assert stats["by_vuln_class"]["sqli"] == 2


# -- TestExecutionTracker + Graph -------------------------------------------

class TestTestExecutionGraphIntegration:
    def test_record_creates_node(self, audit_dir, graph):
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        te = tracker.record("IDOR test", "id-enum", tool="curl",
                            vuln_class="idor", status="pass")
        node = graph.get_node(te.id)
        assert node is not None
        assert node.type == "test_execution"
        assert node.properties["status"] == "pass"

    def test_record_links_to_target(self, audit_dir, graph):
        graph.add_node("endpoint", "GET /api/users/:id", node_id="EP-001")
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        te = tracker.record("IDOR test", "id-enum", target_node_id="EP-001",
                            status="pass")
        edges = graph.get_edges("EP-001", direction="out", edge_type="tested_by")
        assert len(edges) == 1
        assert edges[0].target_id == te.id

    def test_record_finding_supports_hypothesis(self, audit_dir, graph):
        graph.add_node("hypothesis", "IDOR possible", node_id="H-001")
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        te = tracker.record("IDOR confirmed", "id-enum",
                            hypothesis_id="H-001",
                            status="finding_detected")
        supports = graph.edges_by_type("supports")
        assert len(supports) == 1
        assert supports[0].source_id == te.id
        assert supports[0].target_id == "H-001"

    def test_record_pass_refutes_hypothesis(self, audit_dir, graph):
        graph.add_node("hypothesis", "IDOR possible", node_id="H-001")
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        te = tracker.record("IDOR negative", "id-enum",
                            hypothesis_id="H-001", status="pass")
        refutes = graph.edges_by_type("refutes")
        assert len(refutes) == 1
        assert refutes[0].source_id == te.id

    def test_update_status_updates_node(self, audit_dir, graph):
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        te = tracker.record("IDOR test", "id-enum", status="in_progress")
        tracker.update_status(te.id, "finding_detected", notes="Got 200")
        node = graph.get_node(te.id)
        assert node.properties["status"] == "finding_detected"
        assert node.properties["notes"] == "Got 200"

    def test_untested_endpoints(self, audit_dir, graph):
        graph.add_node("endpoint", "GET /api/users", node_id="EP-001")
        graph.add_node("endpoint", "GET /api/goals", node_id="EP-002")
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        tracker.record("Test users", "id-enum", target_node_id="EP-001",
                        status="pass")
        untested = tracker.untested_endpoints()
        assert len(untested) == 1
        assert untested[0].id == "EP-002"

    def test_multiple_executions_per_endpoint(self, audit_dir, graph):
        graph.add_node("endpoint", "GET /api/users", node_id="EP-001")
        tracker = TestExecutionTracker(audit_dir, graph=graph)
        tracker.record("IDOR attempt 1", "id-enum", target_node_id="EP-001",
                        identity_used="Account-A", status="pass")
        tracker.record("IDOR attempt 2", "id-enum", target_node_id="EP-001",
                        identity_used="Account-B", status="finding_detected")
        edges = graph.get_edges("EP-001", direction="out", edge_type="tested_by")
        assert len(edges) == 2


# -- Cross-module Phase 3 ---------------------------------------------------

class TestPhase3CrossModule:
    def test_hypothesis_to_test_to_finding(self, audit_dir, graph):
        """Full Phase 3 lifecycle: hypothesis → test → confirm/disprove."""
        journal = HypothesisJournal(audit_dir, graph=graph)
        tracker = TestExecutionTracker(audit_dir, graph=graph)

        graph.add_node("endpoint", "POST /api/password-change", node_id="EP-PWD")

        h = journal.propose("Token survives password change",
                            "Old refresh token valid after change",
                            "JWT stateless, no revocation observed",
                            priority="high",
                            related_node_ids=["EP-PWD"])
        journal.start_testing(h.id, test_plan="Issue token, change pwd, replay")

        te = tracker.record("Replay old token after pwd change",
                            "token-replay", tool="curl",
                            target_node_id="EP-PWD",
                            hypothesis_id=h.id,
                            status="finding_detected")

        journal.confirm(h.id, finding_id="F-TOKEN-001",
                        reason="Old token accepted after password change")

        hyp_node = graph.get_node(h.id)
        assert hyp_node.properties["status"] == "confirmed"

        te_node = graph.get_node(te.id)
        assert te_node.properties["status"] == "finding_detected"

        supports = graph.edges_by_type("supports")
        assert any(e.source_id == te.id and e.target_id == h.id for e in supports)

        tested_by = graph.get_edges("EP-PWD", direction="out", edge_type="tested_by")
        assert len(tested_by) == 1

        involves = [e for e in graph.get_edges(h.id, direction="out")
                    if e.type == "involves"]
        assert any(e.target_id == "EP-PWD" for e in involves)

    def test_hypothesis_disproved_by_test(self, audit_dir, graph):
        journal = HypothesisJournal(audit_dir, graph=graph)
        tracker = TestExecutionTracker(audit_dir, graph=graph)

        h = journal.propose("CSRF on settings", "No CSRF token on form",
                            "Form observed without token", priority="medium")
        journal.start_testing(h.id)

        te = tracker.record("CSRF submit test", "form-submission",
                            tool="curl", hypothesis_id=h.id, status="pass")

        journal.disprove(h.id, test_execution_id=te.id,
                         reason="Server validates Origin header")

        hyp_node = graph.get_node(h.id)
        assert hyp_node.properties["status"] == "disproved"

        refutes = graph.edges_by_type("refutes")
        assert len(refutes) >= 1
        te_refutes = [e for e in refutes if e.source_id == te.id and e.target_id == h.id]
        assert len(te_refutes) >= 1
