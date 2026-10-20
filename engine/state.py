"""Engagement state machine.

States: INIT → SCOPED → RECON → MAPPED → HUNTING → CHAINING → VALIDATING → REPORTING → CLOSED

Persists to .pentest-state/engagement.json in the audit directory.
"""

import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Phase(str, Enum):
    INIT = "init"
    SCOPED = "scoped"
    RECON = "recon"
    MAPPED = "mapped"
    HUNTING = "hunting"
    CHAINING = "chaining"
    VALIDATING = "validating"
    REPORTING = "reporting"
    CLOSED = "closed"


TRANSITIONS = {
    Phase.INIT: [Phase.SCOPED],
    Phase.SCOPED: [Phase.RECON],
    Phase.RECON: [Phase.MAPPED, Phase.HUNTING],
    Phase.MAPPED: [Phase.HUNTING],
    Phase.HUNTING: [Phase.CHAINING, Phase.VALIDATING],
    Phase.CHAINING: [Phase.VALIDATING, Phase.HUNTING],
    Phase.VALIDATING: [Phase.REPORTING, Phase.HUNTING, Phase.CHAINING],
    Phase.REPORTING: [Phase.CLOSED, Phase.HUNTING],
    Phase.CLOSED: [],
}


class EngagementState:
    def __init__(self, audit_dir: str):
        self.audit_dir = Path(audit_dir)
        self.state_dir = self.audit_dir / ".pentest-state"
        self.state_file = self.state_dir / "engagement.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {
            "engagement_id": None,
            "target": None,
            "phase": Phase.INIT.value,
            "created_at": None,
            "updated_at": None,
            "phase_history": [],
            "metadata": {},
        }

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.state_file.write_text(json.dumps(self._data, indent=2))

    @property
    def phase(self) -> Phase:
        return Phase(self._data["phase"])

    @property
    def target(self) -> str | None:
        return self._data.get("target")

    def initialize(self, engagement_id: str, target: str, metadata: dict | None = None):
        self._data.update({
            "engagement_id": engagement_id,
            "target": target,
            "phase": Phase.INIT.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "phase_history": [],
            "metadata": metadata or {},
        })
        self._save()

    def transition(self, to_phase: Phase) -> bool:
        current = self.phase
        if to_phase not in TRANSITIONS.get(current, []):
            return False
        self._data["phase_history"].append({
            "from": current.value,
            "to": to_phase.value,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        self._data["phase"] = to_phase.value
        self._save()
        return True

    def can_transition(self, to_phase: Phase) -> bool:
        return to_phase in TRANSITIONS.get(self.phase, [])

    def to_dict(self) -> dict:
        return dict(self._data)
