"""Test Execution Tracker — structured test history.

Each test execution is a first-class graph node, replacing single-status
coverage cells with a full history of what was tested, how, and with what result.

Multiple executions per endpoint (different techniques, identities, dates).
Coverage becomes: "how many distinct test_executions with status=pass|finding_detected
exist per endpoint."
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from .custody import CustodyLog
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from custody import CustodyLog
    from storage import atomic_write_json, engagement_lock, read_json


EXECUTION_STATUSES = frozenset({
    "in_progress", "pass", "fail", "finding_detected",
    "blocked", "inconclusive", "tool_error", "skipped",
})
CONCLUSIVE_STATUSES = frozenset({"pass", "fail", "finding_detected"})


@dataclass
class TestExecution:
    id: str = ""
    label: str = ""
    technique: str = ""
    tool: str = ""
    target_node_id: str = ""
    identity_used: str = ""
    vuln_class: str = ""
    status: str = "in_progress"
    duration_ms: int | None = None
    notes: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    finding_id: str = ""
    hypothesis_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    source: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"TE-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


class TestExecutionTracker:
    def __init__(self, audit_dir: str, graph=None):
        self.audit_dir = audit_dir
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.exec_file = self.state_dir / "test-executions.json"
        self._graph = graph
        self._executions: dict[str, TestExecution] = {}
        self._load()

    def _load(self):
        self._executions = {}
        if self.exec_file.exists():
            data = read_json(self.exec_file)
            for raw in data.get("executions", []):
                te = TestExecution(**raw)
                self._executions[te.id] = te

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.exec_file, {
            "executions": [asdict(te) for te in self._executions.values()],
            "count": len(self._executions),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def record(self, label: str, technique: str, tool: str = "",
               target_node_id: str = "", identity_used: str = "",
               vuln_class: str = "", status: str = "in_progress",
               duration_ms: int | None = None, notes: str = "",
               evidence_refs: list[str] | None = None,
               finding_id: str = "", hypothesis_id: str = "",
               source: str = "") -> TestExecution:
        if status not in EXECUTION_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(EXECUTION_STATUSES)}")
        te = TestExecution(
            label=label, technique=technique, tool=tool,
            target_node_id=target_node_id, identity_used=identity_used,
            vuln_class=vuln_class, status=status,
            duration_ms=duration_ms, notes=notes,
            evidence_refs=evidence_refs or [],
            finding_id=finding_id, hypothesis_id=hypothesis_id,
            source=source,
        )
        with engagement_lock(Path(self.audit_dir)):
            self._load()
            self._executions[te.id] = te
            self._save()
            CustodyLog(self.audit_dir).append("test_execution_recorded", {
                "execution_id": te.id, "technique": technique,
                "target": target_node_id, "status": status})
        if self._graph:
            self._graph.add_node("test_execution", label, node_id=te.id,
                properties={"technique": technique, "tool": tool,
                            "vuln_class": vuln_class, "status": status,
                            "identity_used": identity_used,
                            "duration_ms": duration_ms, "notes": notes},
                source=source or "test_tracker")
            if target_node_id and self._graph.get_node(target_node_id):
                self._graph.add_edge("tested_by", target_node_id, te.id,
                                     confidence="observed",
                                     evidence_refs=evidence_refs or [])
            if hypothesis_id and self._graph.get_node(hypothesis_id):
                if status == "finding_detected":
                    self._graph.add_edge("supports", te.id, hypothesis_id,
                                         confidence="demonstrated")
                elif status in CONCLUSIVE_STATUSES:
                    self._graph.add_edge("refutes", te.id, hypothesis_id,
                                         confidence="demonstrated")
        return te

    def update_status(self, execution_id: str, status: str,
                      notes: str = "", finding_id: str = "",
                      duration_ms: int | None = None) -> bool:
        if status not in EXECUTION_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")
        with engagement_lock(Path(self.audit_dir)):
            self._load()
            te = self._executions.get(execution_id)
            if not te:
                return False
            old_status = te.status
            te.status = status
            te.updated_at = datetime.now(timezone.utc).isoformat()
            if notes:
                te.notes = notes
            if finding_id:
                te.finding_id = finding_id
            if duration_ms is not None:
                te.duration_ms = duration_ms
            self._save()
            CustodyLog(self.audit_dir).append("test_execution_updated", {
                "execution_id": execution_id, "from": old_status,
                "to": status})
        if self._graph and self._graph.get_node(execution_id):
            props: dict = {"status": status}
            if notes:
                props["notes"] = notes
            if duration_ms is not None:
                props["duration_ms"] = duration_ms
            self._graph.update_node(execution_id, props)
        return True

    def get(self, execution_id: str) -> TestExecution | None:
        return self._executions.get(execution_id)

    def list_for_target(self, target_node_id: str) -> list[TestExecution]:
        return [te for te in self._executions.values()
                if te.target_node_id == target_node_id]

    def list_by_status(self, status: str | None = None) -> list[TestExecution]:
        if status is None:
            return list(self._executions.values())
        return [te for te in self._executions.values() if te.status == status]

    def list_by_vuln_class(self, vuln_class: str) -> list[TestExecution]:
        return [te for te in self._executions.values()
                if te.vuln_class == vuln_class]

    def untested_endpoints(self) -> list:
        if not self._graph:
            return []
        return self._graph.unconnected("endpoint", "tested_by", direction="out")

    def coverage_stats(self) -> dict:
        by_status: dict[str, int] = {}
        by_vuln_class: dict[str, int] = {}
        targets: set[str] = set()
        for te in self._executions.values():
            by_status[te.status] = by_status.get(te.status, 0) + 1
            if te.vuln_class:
                by_vuln_class[te.vuln_class] = by_vuln_class.get(te.vuln_class, 0) + 1
            if te.target_node_id:
                targets.add(te.target_node_id)
        return {
            "total": len(self._executions),
            "by_status": by_status,
            "by_vuln_class": by_vuln_class,
            "targets_tested": len(targets),
        }

    def summary(self) -> dict:
        return self.coverage_stats()
