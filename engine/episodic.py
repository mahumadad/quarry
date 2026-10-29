"""Episodic memory — cross-engagement success/failure patterns.

Extends the knowledge base with episodic patterns indexed by
(vuln_class, tech_stack, outcome).  When a technique succeeds or fails,
the pattern is stored for future engagements: "Last time SQLi failed
on Laravel 10, JSON content-type bypass worked."

Storage: ~/.pentest/episodic.json (separate from per-engagement state).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_STORE = Path.home() / ".pentest" / "episodic.json"


@dataclass
class EpisodicPattern:
    vuln_class: str
    tech_stack: str
    technique: str
    outcome: str  # "success" | "failure" | "partial"
    context: str = ""
    bypass_used: str = ""
    alternative_that_worked: str = ""
    target_anon: str = ""
    engagement_date: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.vuln_class.lower(), self.tech_stack.lower(), self.outcome.lower())


class EpisodicStore:
    def __init__(self, store_path: Path | None = None):
        self._path = store_path or DEFAULT_STORE
        self._patterns: list[EpisodicPattern] = []
        self._load()

    def _load(self):
        self._patterns = []
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                for p in data.get("patterns", []):
                    self._patterns.append(EpisodicPattern(**p))
            except (json.JSONDecodeError, TypeError):
                pass

    def _save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "pattern_count": len(self._patterns),
            "patterns": [asdict(p) for p in self._patterns],
        }
        self._path.write_text(json.dumps(data, indent=2))

    def record(self, vuln_class: str, tech_stack: str, technique: str,
               outcome: str, *, context: str = "", bypass_used: str = "",
               alternative_that_worked: str = "", target_anon: str = "",
               tags: list[str] | None = None) -> EpisodicPattern:
        pattern = EpisodicPattern(
            vuln_class=vuln_class,
            tech_stack=tech_stack,
            technique=technique,
            outcome=outcome,
            context=context,
            bypass_used=bypass_used,
            alternative_that_worked=alternative_that_worked,
            target_anon=target_anon,
            engagement_date=datetime.now(timezone.utc).strftime("%Y-%m"),
            tags=tags or [],
        )
        self._patterns.append(pattern)
        self._save()
        return pattern

    def what_worked_for(self, vuln_class: str,
                        tech_stack: str = "") -> list[EpisodicPattern]:
        vc = vuln_class.lower()
        ts = tech_stack.lower()
        results = [
            p for p in self._patterns
            if p.vuln_class.lower() == vc and p.outcome.lower() == "success"
        ]
        if ts:
            stack_match = [p for p in results if ts in p.tech_stack.lower()]
            if stack_match:
                return stack_match
        return results

    def what_failed_for(self, vuln_class: str,
                        tech_stack: str = "") -> list[EpisodicPattern]:
        vc = vuln_class.lower()
        ts = tech_stack.lower()
        results = [
            p for p in self._patterns
            if p.vuln_class.lower() == vc and p.outcome.lower() == "failure"
        ]
        if ts:
            stack_match = [p for p in results if ts in p.tech_stack.lower()]
            if stack_match:
                return stack_match
        return results

    def suggest_bypass(self, vuln_class: str,
                       tech_stack: str) -> list[str]:
        """Return bypass techniques that worked for this vuln_class+stack."""
        patterns = self.what_worked_for(vuln_class, tech_stack)
        bypasses = []
        for p in patterns:
            if p.bypass_used and p.bypass_used not in bypasses:
                bypasses.append(p.bypass_used)
        return bypasses

    def suggest_alternative(self, vuln_class: str, failed_technique: str,
                            tech_stack: str = "") -> list[str]:
        """After a technique fails, suggest what worked instead."""
        vc = vuln_class.lower()
        ft = failed_technique.lower()
        ts = tech_stack.lower()

        alternatives = []
        for p in self._patterns:
            if (p.vuln_class.lower() == vc
                    and p.outcome.lower() == "failure"
                    and ft in p.technique.lower()
                    and p.alternative_that_worked):
                if not ts or ts in p.tech_stack.lower():
                    if p.alternative_that_worked not in alternatives:
                        alternatives.append(p.alternative_that_worked)
        return alternatives

    def stats(self) -> dict:
        by_class: dict[str, dict[str, int]] = {}
        for p in self._patterns:
            vc = p.vuln_class.lower()
            if vc not in by_class:
                by_class[vc] = {"success": 0, "failure": 0, "partial": 0}
            outcome = p.outcome.lower()
            if outcome in by_class[vc]:
                by_class[vc][outcome] += 1

        return {
            "total_patterns": len(self._patterns),
            "by_vuln_class": by_class,
            "unique_stacks": len({p.tech_stack.lower() for p in self._patterns}),
        }
