"""Cross-engagement knowledge base: technique effectiveness memory.

engine.brain tracks intelligence WITHIN one engagement. This module persists
what worked ACROSS engagements — anonymized (no client names, no real
targets) so the plugin gets cumulatively better: which bypass defeated which
WAF, which payload shape worked on which stack, which techniques exhausted.

Stored OUTSIDE the engagement dir (default ~/.pentest/knowledge.json) so it
survives engagement cleanup. All records must be anonymized before writing —
see CLAUDE.md Memory-first rules ({target_domain}, {target_ip} placeholders).
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_KB_PATH = Path.home() / ".pentest" / "knowledge.json"


@dataclass
class TechniqueRecord:
    """One anonymized observation of a technique against a stack."""
    technique: str                 # e.g. "ssrf-decimal-ip-bypass", "jwt-alg-confusion"
    vuln_class: str = ""
    stack: list[str] = field(default_factory=list)   # ["nginx", "django", "postgres"]
    waf: str = ""                  # "cloudflare", "akamai", "" if none
    outcome: str = ""              # "worked" | "blocked" | "partial" | "not-applicable"
    bypass_of: str = ""            # what control it defeated, if any
    notes: str = ""                # anonymized detail — NO client/target identifiers
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 1

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now

    def key(self) -> str:
        stack_key = ",".join(sorted(self.stack))
        return f"{self.technique}|{self.vuln_class}|{stack_key}|{self.waf}|{self.outcome}"


class KnowledgeBase:
    """Append/merge/query interface over the persistent technique store."""

    def __init__(self, path: str | Path = DEFAULT_KB_PATH):
        self.kb_file = Path(path)
        self._records: dict[str, TechniqueRecord] = {}
        self._load()

    def _load(self):
        if self.kb_file.exists():
            data = json.loads(self.kb_file.read_text())
            for r in data.get("records", []):
                rec = TechniqueRecord(**r)
                self._records[rec.key()] = rec

    def _save(self):
        self.kb_file.parent.mkdir(parents=True, exist_ok=True)
        self.kb_file.write_text(json.dumps({
            "records": [asdict(r) for r in self._records.values()],
            "count": len(self._records),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def record(self, rec: TechniqueRecord) -> TechniqueRecord:
        """Insert or merge (bump times_seen + last_seen) an observation."""
        existing = self._records.get(rec.key())
        if existing:
            existing.times_seen += 1
            existing.last_seen = datetime.now(timezone.utc).isoformat()
            if rec.notes and rec.notes not in existing.notes:
                existing.notes = (existing.notes + " | " + rec.notes).strip(" |")
            rec = existing
        else:
            self._records[rec.key()] = rec
        self._save()
        return rec

    def what_worked(self, stack: list[str] | None = None, waf: str = "",
                    vuln_class: str = "") -> list[TechniqueRecord]:
        """Query before testing: techniques with outcome=worked for a similar
        stack/WAF. Feeds research-first skill with empirical priors."""
        out = []
        for r in self._records.values():
            if r.outcome != "worked":
                continue
            if vuln_class and r.vuln_class != vuln_class:
                continue
            if waf and r.waf and r.waf != waf:
                continue
            if stack and r.stack and not set(r.stack) & set(stack):
                continue
            out.append(r)
        return sorted(out, key=lambda r: r.times_seen, reverse=True)

    def what_failed(self, stack: list[str] | None = None, waf: str = "") -> list[TechniqueRecord]:
        """Techniques already seen blocked on similar stacks — avoid re-burning budget."""
        return [r for r in self._records.values()
                if r.outcome == "blocked"
                and (not waf or not r.waf or r.waf == waf)
                and (not stack or not r.stack or set(r.stack) & set(stack))]

    def record_episode(self, vuln_class: str, tech_stack: list[str],
                        waf: str, technique: str, outcome: str,
                        context: str = "") -> TechniqueRecord:
        """Record an episodic memory pattern (Gap 9).

        Higher-level than record(): captures the full episode context
        (vuln_class + stack + WAF + technique + outcome) as a reusable
        pattern for future engagements.
        """
        rec = TechniqueRecord(
            technique=technique,
            vuln_class=vuln_class,
            stack=tech_stack,
            waf=waf,
            outcome=outcome,
            notes=context,
        )
        return self.record(rec)

    def suggest_for_context(self, vuln_class: str, tech_stack: list[str],
                             waf: str = "") -> dict:
        """Given a target context, suggest techniques based on episodic memory.

        Returns prioritized list: what worked first, then untried, then
        explicitly marks what was blocked.
        """
        worked = self.what_worked(stack=tech_stack, waf=waf, vuln_class=vuln_class)
        blocked = self.what_failed(stack=tech_stack, waf=waf)
        blocked_techniques = {r.technique for r in blocked}

        all_for_class = [r for r in self._records.values()
                         if r.vuln_class == vuln_class]
        all_techniques = {r.technique for r in all_for_class}
        tried_techniques = {r.technique for r in worked} | blocked_techniques

        return {
            "recommended": [
                {"technique": r.technique, "times_worked": r.times_seen,
                 "notes": r.notes, "bypass_of": r.bypass_of}
                for r in worked[:10]
            ],
            "avoid": [
                {"technique": r.technique, "times_blocked": r.times_seen,
                 "waf": r.waf, "notes": r.notes}
                for r in blocked[:10]
            ],
            "untried_known": sorted(all_techniques - tried_techniques),
            "context": {
                "vuln_class": vuln_class,
                "stack": tech_stack,
                "waf": waf,
                "total_episodes": len(all_for_class),
            },
        }

    def summary(self) -> dict:
        by_outcome: dict[str, int] = {}
        for r in self._records.values():
            by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + r.times_seen
        return {"techniques": len(self._records), "observations_by_outcome": by_outcome}
