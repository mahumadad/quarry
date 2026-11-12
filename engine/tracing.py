"""Decision tracing and observability for agent behavior.

Logs every decision point the agent makes during an engagement:
tool choices, strategy shifts, escalations, skips. Enables post-hoc
debugging of "why did the agent do X instead of Y".

Trace lives in .pentest-state/trace.jsonl (append-only).
"""

import json
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import append_jsonl
except ImportError:
    from storage import append_jsonl


@dataclass
class TraceEntry:
    decision_type: str  # tool_choice, strategy_shift, escalation, skip, fallback
    context: str = ""
    alternatives_considered: list[str] = field(default_factory=list)
    chosen: str = ""
    rationale: str = ""
    phase: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class DecisionTracer:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.trace_file = self.state_dir / "trace.jsonl"

    def trace(self, decision_type: str, chosen: str, rationale: str = "",
              context: str = "", alternatives: list[str] | None = None,
              phase: str = "") -> TraceEntry:
        entry = TraceEntry(
            decision_type=decision_type,
            context=context,
            alternatives_considered=alternatives or [],
            chosen=chosen,
            rationale=rationale,
            phase=phase,
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(self.trace_file, asdict(entry))
        return entry

    def tool_choice(self, tool: str, rationale: str = "",
                    alternatives: list[str] | None = None,
                    phase: str = "") -> TraceEntry:
        return self.trace("tool_choice", chosen=tool, rationale=rationale,
                          alternatives=alternatives, phase=phase)

    def strategy_shift(self, new_strategy: str, reason: str,
                       old_strategy: str = "", phase: str = "") -> TraceEntry:
        return self.trace("strategy_shift", chosen=new_strategy,
                          rationale=reason,
                          alternatives=[old_strategy] if old_strategy else [],
                          phase=phase)

    def escalation(self, what: str, reason: str, phase: str = "") -> TraceEntry:
        return self.trace("escalation", chosen=what, rationale=reason,
                          phase=phase)

    def skip(self, what: str, reason: str, phase: str = "") -> TraceEntry:
        return self.trace("skip", chosen=what, rationale=reason, phase=phase)

    def _read_entries(self) -> list[dict]:
        if not self.trace_file.exists():
            return []
        entries = []
        with self.trace_file.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def replay(self, from_time: str = "", to_time: str = "") -> list[dict]:
        entries = self._read_entries()
        if from_time:
            entries = [e for e in entries if e.get("timestamp", "") >= from_time]
        if to_time:
            entries = [e for e in entries if e.get("timestamp", "") <= to_time]
        return entries

    def summary(self) -> dict:
        entries = self._read_entries()
        if not entries:
            return {"total_decisions": 0, "by_type": {}, "by_phase": {}}

        by_type = Counter(e.get("decision_type", "") for e in entries)
        by_phase = Counter(e.get("phase", "") for e in entries)
        tools_chosen = Counter(e.get("chosen", "") for e in entries
                               if e.get("decision_type") == "tool_choice")

        timestamps = sorted(e.get("timestamp", "") for e in entries if e.get("timestamp"))
        avg_gap_seconds = 0.0
        if len(timestamps) >= 2:
            first = datetime.fromisoformat(timestamps[0])
            last = datetime.fromisoformat(timestamps[-1])
            total_seconds = (last - first).total_seconds()
            avg_gap_seconds = total_seconds / (len(timestamps) - 1)

        return {
            "total_decisions": len(entries),
            "by_type": dict(by_type),
            "by_phase": dict(by_phase),
            "top_tools": dict(tools_chosen.most_common(10)),
            "avg_seconds_between_decisions": round(avg_gap_seconds, 1),
            "escalation_count": by_type.get("escalation", 0),
            "strategy_shifts": by_type.get("strategy_shift", 0),
        }
