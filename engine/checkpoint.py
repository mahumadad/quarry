"""Checkpoint and resume for engagement state.

Periodically snapshots engagement progress so work can resume after
interruption (session timeout, crash, operator break). The router
consults the latest checkpoint to skip completed skills and resume
from where hunting left off.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import atomic_write_json
except ImportError:
    from storage import atomic_write_json


@dataclass
class Checkpoint:
    checkpoint_id: str = ""
    timestamp: str = ""
    phase: str = ""
    completed_skills: list[str] = field(default_factory=list)
    current_skill: str = ""
    findings_count: int = 0
    coverage_snapshot: dict = field(default_factory=dict)
    brain_snapshot: dict = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self):
        if not self.checkpoint_id:
            self.checkpoint_id = uuid.uuid4().hex[:12]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class CheckpointManager:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.checkpoint_file = self.state_dir / "checkpoints.json"
        self._checkpoints: list[Checkpoint] = []
        self._load()

    def _load(self):
        if self.checkpoint_file.exists():
            data = json.loads(self.checkpoint_file.read_text())
            self._checkpoints = [Checkpoint(**c) for c in data.get("checkpoints", [])]

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.checkpoint_file, {
            "checkpoints": [asdict(c) for c in self._checkpoints],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def create(
        self,
        phase: str,
        completed_skills: list[str],
        current_skill: str = "",
        findings_count: int = 0,
        coverage_snapshot: dict | None = None,
        brain_snapshot: dict | None = None,
        notes: str = "",
    ) -> Checkpoint:
        cp = Checkpoint(
            phase=phase,
            completed_skills=completed_skills,
            current_skill=current_skill,
            findings_count=findings_count,
            coverage_snapshot=coverage_snapshot or {},
            brain_snapshot=brain_snapshot or {},
            notes=notes,
        )
        self._checkpoints.append(cp)
        self._save()
        return cp

    def latest(self) -> Checkpoint | None:
        return self._checkpoints[-1] if self._checkpoints else None

    def get(self, checkpoint_id: str) -> Checkpoint | None:
        for cp in self._checkpoints:
            if cp.checkpoint_id == checkpoint_id:
                return cp
        return None

    def resume_plan(self) -> dict:
        # The run journal is authoritative; legacy checkpoints remain a fallback.
        if (self.state_dir / "runs.json").exists():
            try:
                from .orchestrator import Orchestrator
            except ImportError:
                from orchestrator import Orchestrator
            return Orchestrator(self.state_dir.parent).resume_plan()
        cp = self.latest()
        if not cp:
            return {"skip_skills": [], "resume_at": "", "phase": "", "findings_at_checkpoint": 0}
        return {
            "skip_skills": cp.completed_skills,
            "resume_at": cp.current_skill,
            "phase": cp.phase,
            "findings_at_checkpoint": cp.findings_count,
        }

    def list_checkpoints(self) -> list[Checkpoint]:
        return list(self._checkpoints)

    def delete_old(self, keep: int = 5):
        if len(self._checkpoints) > keep:
            self._checkpoints = self._checkpoints[-keep:]
            self._save()
