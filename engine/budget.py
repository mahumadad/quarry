"""Tool call budget and timeout management.

Prevents runaway execution by tracking tool calls per phase and per agent.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_LIMITS = {
    "recon": 150,
    "mapped": 50,
    "hunting": 200,
    "chaining": 80,
    "validating": 100,
    "reporting": 50,
    "default": 100,
}

DEFAULT_TIMEOUT_SECONDS = 120
HARD_TIMEOUT_SECONDS = 1200  # 20 minutes
MAX_IDENTICAL_RETRIES = 3
WARN_THRESHOLD = 0.8  # warn at 80% budget


@dataclass
class BudgetTracker:
    phase: str
    limit: int = 0
    used: int = 0
    identical_commands: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.limit:
            self.limit = DEFAULT_LIMITS.get(self.phase, DEFAULT_LIMITS["default"])

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def usage_ratio(self) -> float:
        return self.used / self.limit if self.limit > 0 else 1.0

    def record_call(self, command: str) -> dict:
        """Record a tool call. Returns status dict with warnings."""
        self.used += 1
        cmd_key = command.strip()[:200]
        self.identical_commands[cmd_key] = self.identical_commands.get(cmd_key, 0) + 1

        result = {
            "allowed": True,
            "used": self.used,
            "remaining": self.remaining,
            "warnings": [],
        }

        if self.identical_commands[cmd_key] > MAX_IDENTICAL_RETRIES:
            result["allowed"] = False
            result["warnings"].append(
                f"Command retried {self.identical_commands[cmd_key]} times "
                f"(max {MAX_IDENTICAL_RETRIES}). Change approach."
            )

        if self.used >= self.limit:
            result["allowed"] = False
            result["warnings"].append(
                f"Budget exhausted: {self.used}/{self.limit} calls in phase {self.phase}. "
                f"Escalate to operator."
            )
        elif self.usage_ratio >= WARN_THRESHOLD:
            result["warnings"].append(
                f"Budget warning: {self.used}/{self.limit} calls "
                f"({self.usage_ratio:.0%}) in phase {self.phase}."
            )

        return result


class BudgetManager:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.budget_file = self.state_dir / "budget.json"
        self._trackers: dict[str, BudgetTracker] = {}
        self._load()

    def _load(self):
        if self.budget_file.exists():
            data = json.loads(self.budget_file.read_text())
            for phase, td in data.get("trackers", {}).items():
                self._trackers[phase] = BudgetTracker(**td)

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.budget_file.write_text(json.dumps({
            "trackers": {k: asdict(v) for k, v in self._trackers.items()},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def get_tracker(self, phase: str) -> BudgetTracker:
        if phase not in self._trackers:
            self._trackers[phase] = BudgetTracker(phase=phase)
        return self._trackers[phase]

    def record_call(self, phase: str, command: str) -> dict:
        tracker = self.get_tracker(phase)
        result = tracker.record_call(command)
        self._save()
        return result

    def summary(self) -> dict:
        return {
            phase: {"used": t.used, "limit": t.limit, "remaining": t.remaining}
            for phase, t in self._trackers.items()
        }
