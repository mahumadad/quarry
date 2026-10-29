"""Deterministic, resumable workflow orchestrator.

The executor callback performs agent/tool work. The orchestrator owns ordering,
approvals, journaling, checkpoints and recovery; an interrupted task is never
silently considered complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import yaml
except ImportError:  # JSON workflow definitions remain supported
    yaml = None

try:
    from .artifacts import ArtifactStore
    from .custody import CustodyLog
    from .redaction import redact
    from .state import EngagementState, Phase
    from .storage import (StateCorruptionError, append_jsonl, atomic_write_json,
                          engagement_lock, read_json)
except ImportError:
    from artifacts import ArtifactStore
    from custody import CustodyLog
    from redaction import redact
    from state import EngagementState, Phase
    from storage import (StateCorruptionError, append_jsonl, atomic_write_json,
                         engagement_lock, read_json)

PHASE_MAP = {"scope": Phase.SCOPED, "recon": Phase.RECON, "mapping": Phase.MAPPED,
             "hunting": Phase.HUNTING, "chaining": Phase.CHAINING,
             "validation": Phase.VALIDATING, "reporting": Phase.REPORTING,
             "closeout": Phase.CLOSED}
TERMINAL = {"completed", "skipped"}
ACTIVE = {"pending", "running", "blocked", "failed", "interrupted"}


@dataclass
class Task:
    task_id: str
    run_id: str
    phase: str
    skill: str
    asset: str = ""
    vuln_class: str = ""
    technique: str = ""
    endpoint: str = ""
    identity: str = ""
    status: str = "pending"
    reason: str = ""
    gate: str = ""
    outputs: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    attempts: int = 0
    result: dict[str, Any] = field(default_factory=dict)


class Orchestrator:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.state_dir = self.audit_dir / ".pentest-state"
        self.runs_file = self.state_dir / "runs.json"
        self.journal_file = self.state_dir / "journal.jsonl"
        self.gates_file = self.state_dir / "gates.json"

    def _load_runs(self) -> dict:
        return read_json(self.runs_file, {"schema_version": 1, "runs": []})

    def _save_runs(self, data: dict) -> None:
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        atomic_write_json(self.runs_file, data)

    def _event(self, event: str, detail: dict) -> None:
        append_jsonl(self.journal_file, {"event": event, "detail": redact(detail),
            "at": datetime.now(timezone.utc).isoformat(), "seq": self._sequence() + 1})

    def _sequence(self) -> int:
        if not self.journal_file.exists():
            return 0
        with self.journal_file.open(encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def create_run(self, workflow_path: str | Path, cells: list[dict] | None = None) -> dict:
        path = Path(workflow_path)
        workflow = self._load_workflow(path)
        run_id = f"R-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
        workflow_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        tasks: list[Task] = []
        cells = cells or [{}]
        for phase in workflow.get("phases", []):
            phase_name = phase["name"]
            expanded = self._expand_skills(self._phase_skills(phase))
            for skill in expanded:
                phase_cells = cells if phase_name == "hunting" else [{}]
                for cell in phase_cells:
                    identity = f"{run_id}:{phase_name}:{skill}:{len(tasks)}"
                    tasks.append(Task(task_id=identity, run_id=run_id, phase=phase_name,
                        skill=skill, asset=cell.get("asset", ""),
                        vuln_class=cell.get("vuln_class", ""), technique=cell.get("technique", ""),
                        endpoint=cell.get("endpoint", ""), identity=cell.get("identity", ""),
                        gate=phase.get("gate", ""), outputs=list(phase.get("outputs") or [])))
        record = {"run_id": run_id, "workflow": str(path), "workflow_sha256": workflow_hash,
                  "status": "pending", "created_at": datetime.now(timezone.utc).isoformat(),
                  "tasks": [asdict(t) for t in tasks]}
        with engagement_lock(self.audit_dir):
            data = self._load_runs()
            data["runs"].append(record)
            self._save_runs(data)
            self._event("run_created", {"run_id": run_id, "workflow_sha256": workflow_hash,
                                       "task_count": len(tasks)})
        return record

    def run(self, run_id: str, executor: Callable[[Task, dict], dict] | None = None,
            resume: bool = True) -> dict:
        if executor is None:
            return self.resume_plan(run_id)
        if resume:
            self.recover_interrupted(run_id)
        while True:
            with engagement_lock(self.audit_dir):
                data, record = self._mutable_run(run_id)
                task_data = next((t for t in record["tasks"] if t["status"] in
                                  {"pending", "interrupted"}), None)
                if task_data is None:
                    record["status"] = "blocked" if any(t["status"] == "blocked" for t in record["tasks"]) else (
                        "failed" if any(t["status"] == "failed" for t in record["tasks"]) else "completed")
                    self._save_runs(data)
                    return record
                if task_data["gate"] and not self._gate_allowed(task_data):
                    task_data["status"] = "blocked"
                    task_data["reason"] = f"Gate not approved: {task_data['gate']}"
                    record["status"] = "blocked"
                    self._save_runs(data)
                    self._event("task_blocked", {"task_id": task_data["task_id"],
                                                "reason": task_data["reason"]})
                    return record
                task_data["status"] = "running"
                task_data["attempts"] += 1
                task_data["started_at"] = datetime.now(timezone.utc).isoformat()
                task_data["reason"] = ""
                record["status"] = "running"
                self._save_runs(data)
                self._event("task_started", {"task_id": task_data["task_id"],
                                            "attempt": task_data["attempts"]})
            task = Task(**task_data)
            context = self.briefing(run_id, task.task_id)
            try:
                result = executor(task, context)
                status = result.pop("status", "completed")
                if status not in TERMINAL | {"failed", "blocked"}:
                    raise ValueError(f"Invalid executor status: {status}")
            except Exception as exc:
                result, status = {"error": f"{type(exc).__name__}: {exc}"}, "failed"
            with engagement_lock(self.audit_dir):
                data, record = self._mutable_run(run_id)
                current = next(t for t in record["tasks"] if t["task_id"] == task.task_id)
                current.update({"status": status, "result": redact(result),
                    "reason": result.get("reason", result.get("error", "")),
                    "finished_at": datetime.now(timezone.utc).isoformat()})
                self._save_runs(data)
                self._event("task_finished", {"task_id": task.task_id, "status": status,
                                              "reason": current["reason"]})
                CustodyLog(self.audit_dir).append("workflow_task", {
                    "run_id": run_id, "task_id": task.task_id, "status": status})
                phase_tasks = [t for t in record["tasks"] if t["phase"] == task.phase]
                phase_done = all(t["status"] in TERMINAL for t in phase_tasks)
            if phase_done and task.phase in PHASE_MAP:
                engagement = EngagementState(self.audit_dir)
                destination = PHASE_MAP[task.phase]
                if engagement.phase != destination and engagement.can_transition(destination):
                    engagement.transition(destination)
                    CustodyLog(self.audit_dir).append("phase_changed", {
                        "run_id": run_id, "phase": destination.value})
            if status in {"failed", "blocked"}:
                return self.get_run(run_id)

    def approve_gate(self, run_id: str, phase: str, gate: str, actor: str = "operator") -> None:
        if actor != "operator":
            raise PermissionError("Gate approval requires the operator")
        with engagement_lock(self.audit_dir):
            data = read_json(self.gates_file, {"approvals": []})
            data.setdefault("approvals", []).append({"run_id": run_id, "phase": phase,
                "gate": gate, "actor": actor, "at": datetime.now(timezone.utc).isoformat()})
            atomic_write_json(self.gates_file, data)
            self._event("gate_approved", {"run_id": run_id, "phase": phase, "gate": gate})
            CustodyLog(self.audit_dir).operator_gate(f"{run_id}:{phase}:{gate}", True)
            blocked = [t["task_id"] for t in self.get_run(run_id)["tasks"]
                       if t["phase"] == phase and t["status"] == "blocked"]
        for task_id in blocked:
            self.update_task(task_id, status="pending", reason="Gate approved")

    def update_task(self, task_id: str, **updates) -> None:
        with engagement_lock(self.audit_dir):
            data = self._load_runs()
            for record in data["runs"]:
                for task in record["tasks"]:
                    if task["task_id"] == task_id:
                        task.update(redact(updates))
                        self._save_runs(data)
                        self._event("task_updated", {"task_id": task_id, **updates})
                        return
        raise KeyError(task_id)

    def recover_interrupted(self, run_id: str) -> list[str]:
        recovered = []
        with engagement_lock(self.audit_dir):
            data, record = self._mutable_run(run_id)
            for task in record["tasks"]:
                if task["status"] == "running":
                    task["status"] = "interrupted"
                    task["reason"] = "Process interrupted after task start; verify artifacts before retry"
                    recovered.append(task["task_id"])
            if recovered:
                self._save_runs(data)
                for task_id in recovered:
                    self._event("task_interrupted", {"task_id": task_id})
        return recovered

    def resume_plan(self, run_id: str | None = None) -> dict:
        record = self.get_run(run_id) if run_id else self.latest_run()
        if not record:
            return {"run_id": None, "next_tasks": [], "status": "no_run"}
        next_tasks = [t for t in record["tasks"] if t["status"] in ACTIVE]
        return {"run_id": record["run_id"], "status": record["status"],
                "workflow_sha256": record["workflow_sha256"],
                "next_tasks": next_tasks[:10], "pending_count": len(next_tasks),
                "completed": sum(t["status"] == "completed" for t in record["tasks"]),
                "skipped": sum(t["status"] == "skipped" for t in record["tasks"]),
                "failed": sum(t["status"] == "failed" for t in record["tasks"]),
                "interrupted": sum(t["status"] == "interrupted" for t in record["tasks"])}

    def briefing(self, run_id: str, task_id: str) -> dict:
        record = self.get_run(run_id)
        task = next(t for t in record["tasks"] if t["task_id"] == task_id)
        return {"run_id": run_id, "task": task, "audit_dir": str(self.audit_dir),
                "completed_tasks": [t["task_id"] for t in record["tasks"] if t["status"] == "completed"],
                "recent_failures": [t for t in record["tasks"] if t["status"] == "failed"][-5:],
                "artifacts": ArtifactStore(self.audit_dir).list()[-20:],
                "instruction": "Save raw evidence before interpreting; never mark incomplete output tested_clean"}

    def doctor(self) -> dict:
        issues = []
        try:
            data = self._load_runs()
            for record in data["runs"]:
                for task in record["tasks"]:
                    if task["status"] == "completed" and not task.get("finished_at"):
                        issues.append({"type": "invalid_completion", "task_id": task["task_id"]})
                    if task["status"] == "running":
                        issues.append({"type": "orphaned_running", "task_id": task["task_id"]})
        except StateCorruptionError as exc:
            issues.append({"type": "corrupt_state", "detail": str(exc)})
        artifacts = ArtifactStore(self.audit_dir).verify()
        custody = CustodyLog(self.audit_dir).verify()
        if not artifacts["intact"]:
            issues.append({"type": "artifact_integrity", "detail": artifacts})
        if not custody["intact"]:
            issues.append({"type": "custody_integrity", "detail": custody})
        return {"ok": not issues, "issues": issues, "artifacts": artifacts, "custody": custody}

    def latest_run(self) -> dict | None:
        runs = self._load_runs()["runs"]
        return runs[-1] if runs else None

    def get_run(self, run_id: str) -> dict:
        return self._mutable_run(run_id)[1]

    def _mutable_run(self, run_id: str) -> tuple[dict, dict]:
        data = self._load_runs()
        record = next((r for r in data["runs"] if r["run_id"] == run_id), None)
        if record is None:
            raise KeyError(run_id)
        return data, record

    def _gate_allowed(self, task: dict) -> bool:
        gate = task["gate"]
        if gate in {"coverage_check", "rebuttal_complete"}:
            return True  # evaluated by the corresponding executor; its result is persisted
        approvals = read_json(self.gates_file, {"approvals": []}).get("approvals", [])
        return any(a["run_id"] == task["run_id"] and a["phase"] == task["phase"] and
                   a["gate"] == gate for a in approvals)

    @staticmethod
    def _load_workflow(path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(path)
        if path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML workflows")
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    @staticmethod
    def _phase_skills(phase: dict) -> list[str]:
        """Read every supported workflow skill list without dropping platform/hunt cells."""
        skills: list[str] = []
        for key in ("skills", "priority_classes", "secondary_classes", "hunt_classes", "platform_skills"):
            skills.extend(phase.get(key) or [])
        return skills or [phase["name"]]

    @staticmethod
    def _expand_skills(skills: list[str]) -> list[str]:
        """Expand a skill glob against its canonical directory, preserving order."""
        expanded: list[str] = []
        skill_root = Path(__file__).resolve().parent.parent / "skills"
        for skill in skills:
            pattern = "hunt/*/SKILL.md" if skill == "hunt-*" else f"*/{skill}/SKILL.md"
            matches = sorted(skill_root.glob(pattern))
            if not matches and skill.startswith("hunt-"):
                # Legacy workflow names such as hunt-sqli map to canonical skills/hunt/sqli.
                matches = sorted(skill_root.glob(f"*/{skill.removeprefix('hunt-')}/SKILL.md"))
            candidates = [p.parent.name for p in matches] if matches else [skill]
            for candidate in candidates:
                if candidate not in expanded:
                    expanded.append(candidate)
        return expanded


def main() -> int:
    parser = argparse.ArgumentParser(prog="engine.orchestrator")
    parser.add_argument("command", choices=["create", "plan", "resume", "recover", "doctor"])
    parser.add_argument("--audit-dir", default=".")
    parser.add_argument("--workflow")
    parser.add_argument("--run-id")
    parser.add_argument("--cells", help="JSON list of asset/vuln_class/technique/endpoint/identity cells")
    args = parser.parse_args()
    orchestrator = Orchestrator(args.audit_dir)
    if args.command == "create":
        if not args.workflow:
            parser.error("create requires --workflow")
        result = orchestrator.create_run(args.workflow, json.loads(args.cells) if args.cells else None)
    elif args.command in {"plan", "resume"}:
        result = orchestrator.resume_plan(args.run_id)
    elif args.command == "recover":
        if not args.run_id:
            parser.error("recover requires --run-id")
        result = {"recovered": orchestrator.recover_interrupted(args.run_id)}
    else:
        result = orchestrator.doctor()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if args.command != "doctor" or result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
