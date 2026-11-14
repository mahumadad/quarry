"""Hypothesis Journal — structured suspicion tracking.

Hypotheses are first-class graph nodes with a lifecycle:
active → testing → confirmed (becomes finding) | disproved | deferred

Each hypothesis tracks its basis (what originated the suspicion),
related graph nodes, and test executions that resolved it.
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


HYPOTHESIS_STATUSES = frozenset({"active", "testing", "confirmed", "disproved", "deferred"})

HYPOTHESIS_TRANSITIONS: dict[str, set[str]] = {
    "active": {"testing", "deferred"},
    "testing": {"confirmed", "disproved", "deferred", "active"},
    "confirmed": set(),
    "disproved": set(),
    "deferred": {"active"},
}

HYPOTHESIS_PRIORITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass
class Hypothesis:
    id: str = ""
    label: str = ""
    description: str = ""
    basis: str = ""
    status: str = "active"
    priority: str = "medium"
    related_finding_ids: list[str] = field(default_factory=list)
    related_node_ids: list[str] = field(default_factory=list)
    test_plan: str = ""
    resolution_id: str = ""
    resolution_reason: str = ""
    created_at: str = ""
    updated_at: str = ""
    source: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"H-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


class HypothesisJournal:
    def __init__(self, audit_dir: str, graph=None):
        self.audit_dir = audit_dir
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.hyp_file = self.state_dir / "hypotheses.json"
        self._graph = graph
        self._hypotheses: dict[str, Hypothesis] = {}
        self._load()

    def _load(self):
        self._hypotheses = {}
        if self.hyp_file.exists():
            data = read_json(self.hyp_file)
            for raw in data.get("hypotheses", []):
                h = Hypothesis(**raw)
                self._hypotheses[h.id] = h

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.hyp_file, {
            "hypotheses": [asdict(h) for h in self._hypotheses.values()],
            "count": len(self._hypotheses),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def propose(self, label: str, description: str, basis: str,
                priority: str = "medium",
                related_finding_ids: list[str] | None = None,
                related_node_ids: list[str] | None = None,
                source: str = "") -> Hypothesis:
        if priority not in HYPOTHESIS_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority!r}. Valid: {sorted(HYPOTHESIS_PRIORITIES)}")
        h = Hypothesis(
            label=label, description=description, basis=basis,
            priority=priority,
            related_finding_ids=related_finding_ids or [],
            related_node_ids=related_node_ids or [],
            source=source,
        )
        with engagement_lock(Path(self.audit_dir)):
            self._load()
            self._hypotheses[h.id] = h
            self._save()
            CustodyLog(self.audit_dir).append("hypothesis_proposed", {
                "hypothesis_id": h.id, "label": label, "priority": priority})
        if self._graph:
            self._graph.add_node("hypothesis", label, node_id=h.id,
                properties={"description": description, "basis": basis,
                            "status": "active", "priority": priority},
                source=source or "hypothesis_journal")
            for fid in (related_finding_ids or []):
                if self._graph.get_node(fid):
                    self._graph.add_edge("derived_from", h.id, fid,
                                         confidence="inferred")
            for nid in (related_node_ids or []):
                if self._graph.get_node(nid):
                    self._graph.add_edge("involves", h.id, nid,
                                         confidence="hypothesized")
        return h

    def _transition(self, hypothesis_id: str, new_status: str, **updates) -> bool:
        with engagement_lock(Path(self.audit_dir)):
            self._load()
            h = self._hypotheses.get(hypothesis_id)
            if not h:
                return False
            if new_status not in HYPOTHESIS_TRANSITIONS.get(h.status, set()):
                return False
            old_status = h.status
            h.status = new_status
            h.updated_at = datetime.now(timezone.utc).isoformat()
            for k, v in updates.items():
                if hasattr(h, k):
                    setattr(h, k, v)
            self._save()
            CustodyLog(self.audit_dir).append("hypothesis_transitioned", {
                "hypothesis_id": hypothesis_id, "from": old_status,
                "to": new_status})
        if self._graph and self._graph.get_node(hypothesis_id):
            props = {"status": new_status}
            props.update({k: v for k, v in updates.items()
                          if k not in ("id", "created_at")})
            self._graph.update_node(hypothesis_id, props)
        return True

    def start_testing(self, hypothesis_id: str, test_plan: str = "") -> bool:
        return self._transition(hypothesis_id, "testing", test_plan=test_plan)

    def confirm(self, hypothesis_id: str, finding_id: str = "",
                reason: str = "") -> bool:
        return self._transition(hypothesis_id, "confirmed",
                                resolution_id=finding_id,
                                resolution_reason=reason)

    def disprove(self, hypothesis_id: str, test_execution_id: str = "",
                 reason: str = "") -> bool:
        ok = self._transition(hypothesis_id, "disproved",
                              resolution_id=test_execution_id,
                              resolution_reason=reason)
        if ok and self._graph and test_execution_id:
            if (self._graph.get_node(test_execution_id) and
                    self._graph.get_node(hypothesis_id)):
                self._graph.add_edge("refutes", test_execution_id,
                                     hypothesis_id,
                                     confidence="demonstrated")
        return ok

    def defer(self, hypothesis_id: str, reason: str = "") -> bool:
        return self._transition(hypothesis_id, "deferred",
                                resolution_reason=reason)

    def reactivate(self, hypothesis_id: str) -> bool:
        return self._transition(hypothesis_id, "active",
                                resolution_id="", resolution_reason="")

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def list_by_status(self, status: str | None = None) -> list[Hypothesis]:
        if status is None:
            return list(self._hypotheses.values())
        return [h for h in self._hypotheses.values() if h.status == status]

    def list_by_priority(self, priority: str | None = None) -> list[Hypothesis]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        hyps = list(self._hypotheses.values())
        if priority:
            hyps = [h for h in hyps if h.priority == priority]
        hyps.sort(key=lambda h: order.get(h.priority, 99))
        return hyps

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for h in self._hypotheses.values():
            by_status[h.status] = by_status.get(h.status, 0) + 1
            by_priority[h.priority] = by_priority.get(h.priority, 0) + 1
        return {
            "total": len(self._hypotheses),
            "by_status": by_status,
            "by_priority": by_priority,
        }
