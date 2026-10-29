"""Compatibility router backed by the canonical YAML workflows.

New execution belongs in Orchestrator. This class only serves legacy callers and
never maintains a second, divergent list of phases or skills.
"""
from __future__ import annotations

from pathlib import Path

try:
    from .orchestrator import Orchestrator
except ImportError:
    from orchestrator import Orchestrator

WORKFLOW_BY_TYPE = {"web_app": "web-app-pentest.yaml", "api_only": "api-pentest.yaml",
                    "network": "ad-pentest.yaml", "mobile_api": "mobile-pentest.yaml"}
PHASE_ALIASES = {"profile": "mapping", "hunt": "hunting", "chain": "chaining",
                 "validate": "validation", "report": "reporting"}


class Router:
    def __init__(self, engagement_type: str = "web_app", workflow_path: str | None = None):
        self.engagement_type = engagement_type
        root = Path(__file__).resolve().parent.parent / "workflows"
        self.workflow_path = Path(workflow_path) if workflow_path else root / WORKFLOW_BY_TYPE.get(
            engagement_type, "web-app-pentest.yaml")
        self.workflow = Orchestrator._load_workflow(self.workflow_path)
        self.phases = self.workflow.get("phases", [])

    def get_phase_skills(self, phase: str) -> list[str]:
        canonical = PHASE_ALIASES.get(phase, phase)
        for definition in self.phases:
            if definition.get("name") == canonical:
                return Orchestrator._expand_skills(Orchestrator._phase_skills(definition))
        return []

    def get_next_phase(self, current_phase: str) -> str | None:
        names = [p.get("name") for p in self.phases]
        canonical = PHASE_ALIASES.get(current_phase, current_phase)
        try:
            index = names.index(canonical)
            return names[index + 1] if index + 1 < len(names) else None
        except ValueError:
            return None

    def get_hunt_priority(self, coverage_gaps: list[dict], brain_suggestions: list[dict]) -> list[str]:
        skills = self.get_phase_skills("hunting")
        gaps = {g.get("vuln_class", "") for g in coverage_gaps}
        suggestions = {s.get("vuln_class", "") for s in brain_suggestions}
        prioritized, rest = [], []
        for skill in skills:
            skill_class = skill.split("/")[-1].removeprefix("hunt-")
            if skill_class in suggestions:
                prioritized.insert(0, skill)
            elif skill_class in gaps:
                prioritized.append(skill)
            else:
                rest.append(skill)
        return prioritized + rest

    def skip_skill(self, skill: str, exhausted_classes: set[str]) -> bool:
        return skill.split("/")[-1].removeprefix("hunt-") in exhausted_classes

    def available_types(self) -> list[str]:
        return list(WORKFLOW_BY_TYPE)

    def summary(self) -> dict:
        return {"engagement_type": self.engagement_type, "workflow": str(self.workflow_path),
                "phases": {p["name"]: len(self.get_phase_skills(p["name"])) for p in self.phases},
                "total_skills": sum(len(self.get_phase_skills(p["name"])) for p in self.phases)}
