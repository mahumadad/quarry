"""Anti-loop detection.

Detects when an agent is stuck in a loop (repeating the same actions)
and forces a strategy change or escalation.
"""

import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


MAX_IDENTICAL_CONSECUTIVE = 3
MAX_SIMILAR_WINDOW = 10
SIMILARITY_THRESHOLD = 0.8


@dataclass
class LoopDetector:
    window_size: int = 20
    history: deque = field(default_factory=lambda: deque(maxlen=20))
    loop_count: int = 0
    interventions: list[dict] = field(default_factory=list)

    def record_action(self, action: str, context: str = "") -> dict:
        """Record an action and check for loops.

        Returns:
          {"loop_detected": bool, "type": str, "recommendation": str}
        """
        entry = {"action": action[:500], "context": context[:200],
                 "at": datetime.now(timezone.utc).isoformat()}
        self.history.append(entry)

        identical = self._check_identical_consecutive(action)
        if identical:
            self.loop_count += 1
            result = {
                "loop_detected": True,
                "type": "identical_consecutive",
                "count": identical,
                "recommendation": (
                    f"Same action repeated {identical} times. "
                    "STOP and change approach: different tool, different parameters, "
                    "or escalate to operator."
                ),
            }
            self.interventions.append(result)
            return result

        similar = self._check_similar_pattern()
        if similar:
            self.loop_count += 1
            result = {
                "loop_detected": True,
                "type": "similar_pattern",
                "recommendation": (
                    "Similar actions repeated in a pattern. "
                    "Step back: review what information is missing, "
                    "try a fundamentally different technique, or ask the operator."
                ),
            }
            self.interventions.append(result)
            return result

        return {"loop_detected": False}

    def _check_identical_consecutive(self, action: str) -> int:
        count = 0
        for entry in reversed(self.history):
            if entry["action"] == action[:500]:
                count += 1
            else:
                break
        return count if count >= MAX_IDENTICAL_CONSECUTIVE else 0

    def _check_similar_pattern(self) -> bool:
        if len(self.history) < MAX_SIMILAR_WINDOW:
            return False
        recent = [e["action"] for e in list(self.history)[-MAX_SIMILAR_WINDOW:]]
        unique = set(recent)
        if len(unique) <= 2 and len(recent) >= MAX_SIMILAR_WINDOW:
            return True
        return False

    def reset(self):
        self.history.clear()
        self.loop_count = 0

    def summary(self) -> dict:
        return {
            "total_actions": len(self.history),
            "loop_count": self.loop_count,
            "interventions": len(self.interventions),
        }
