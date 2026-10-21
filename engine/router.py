"""Deterministic engagement router.

Static map of engagement type → agent groups → execution order.
No LLM decides what runs next — the router does, based on engagement
state, coverage gaps, and Brain intelligence.
"""

import json
from pathlib import Path


ENGAGEMENT_ROUTES = {
    "web_app": {
        "recon": [
            "recon/subdomain-enum",
            "recon/port-scan",
            "recon/tech-fingerprint",
            "recon/js-analysis",
            "recon/api-discovery",
            "recon/surface-probes",
        ],
        "profile": [
            "core/app-profile",
        ],
        "hunt": [
            "hunt/auth-bypass",
            "hunt/idor",
            "hunt/xss",
            "hunt/sqli",
            "hunt/ssrf",
            "hunt/csrf",
            "hunt/jwt",
            "hunt/hunt-oauth",
            "hunt/hunt-file-upload",
            "hunt/hunt-api-abuse",
            "hunt/hunt-business-logic",
            "hunt/hunt-rate-limiting",
            "hunt/hunt-session-management",
            "hunt/ssti",
            "hunt/xxe",
            "hunt/rce",
            "hunt/hunt-mass-assignment",
            "hunt/hunt-broken-access-control",
        ],
        "chain": [
            "chain/chain-analysis",
            "chain/account-takeover-chain",
            "chain/data-exfiltration-chain",
            "chain/privilege-escalation-chain",
        ],
        "validate": [
            "validate/finding-validation",
            "validate/severity-validation",
            "validate/evidence-review",
        ],
        "report": [
            "report/executive-summary",
            "report/technical-report",
            "report/remediation-priorities",
        ],
    },
    "api_only": {
        "recon": [
            "recon/api-discovery",
            "recon/tech-fingerprint",
            "recon/surface-probes",
        ],
        "profile": [
            "core/app-profile",
        ],
        "hunt": [
            "hunt/auth-bypass",
            "hunt/idor",
            "hunt/sqli",
            "hunt/ssrf",
            "hunt/jwt",
            "hunt/hunt-api-abuse",
            "hunt/hunt-rate-limiting",
            "hunt/hunt-mass-assignment",
            "hunt/hunt-broken-access-control",
            "hunt/hunt-business-logic",
            "hunt/rce",
            "hunt/graphql",
            "hunt/hunt-parameter-pollution",
        ],
        "chain": [
            "chain/chain-analysis",
            "chain/data-exfiltration-chain",
            "chain/privilege-escalation-chain",
        ],
        "validate": [
            "validate/finding-validation",
            "validate/severity-validation",
        ],
        "report": [
            "report/technical-report",
            "report/remediation-priorities",
        ],
    },
    "network": {
        "recon": [
            "recon/subdomain-enum",
            "recon/port-scan",
            "recon/service-enum",
        ],
        "hunt": [
            "hunt/hunt-default-creds",
            "hunt/hunt-ssh-brute",
            "hunt/hunt-smb-enum",
            "hunt/ssrf",
            "hunt/rce",
        ],
        "validate": [
            "validate/finding-validation",
        ],
        "report": [
            "report/technical-report",
        ],
    },
    "mobile_api": {
        "recon": [
            "recon/api-discovery",
            "recon/tech-fingerprint",
            "recon/surface-probes",
        ],
        "profile": [
            "core/app-profile",
        ],
        "hunt": [
            "hunt/auth-bypass",
            "hunt/idor",
            "hunt/jwt",
            "hunt/hunt-api-abuse",
            "hunt/hunt-broken-access-control",
            "hunt/hunt-session-management",
            "hunt/hunt-rate-limiting",
            "hunt/hunt-business-logic",
            "hunt/ssrf",
            "hunt/sqli",
        ],
        "chain": [
            "chain/chain-analysis",
            "chain/account-takeover-chain",
        ],
        "validate": [
            "validate/finding-validation",
            "validate/severity-validation",
        ],
        "report": [
            "report/technical-report",
        ],
    },
}

PHASE_ORDER = ["recon", "profile", "hunt", "chain", "validate", "report"]


class Router:
    def __init__(self, engagement_type: str = "web_app"):
        self.engagement_type = engagement_type
        self.route = ENGAGEMENT_ROUTES.get(engagement_type, ENGAGEMENT_ROUTES["web_app"])

    def get_phase_skills(self, phase: str) -> list[str]:
        return self.route.get(phase, [])

    def get_next_phase(self, current_phase: str) -> str | None:
        try:
            idx = PHASE_ORDER.index(current_phase)
            if idx + 1 < len(PHASE_ORDER):
                return PHASE_ORDER[idx + 1]
        except ValueError:
            pass
        return None

    def get_hunt_priority(self, coverage_gaps: list[dict],
                          brain_suggestions: list[dict]) -> list[str]:
        """Prioritize hunt skills based on coverage gaps and Brain intelligence."""
        hunt_skills = self.route.get("hunt", [])
        gap_classes = {g.get("vuln_class", "") for g in coverage_gaps}
        brain_classes = {s.get("vuln_class", "") for s in brain_suggestions}

        prioritized = []
        rest = []

        for skill in hunt_skills:
            skill_class = skill.split("/")[-1].replace("hunt-", "")
            if skill_class in brain_classes:
                prioritized.insert(0, skill)
            elif skill_class in gap_classes:
                prioritized.append(skill)
            else:
                rest.append(skill)

        return prioritized + rest

    def skip_skill(self, skill: str, exhausted_classes: set[str]) -> bool:
        """Should this skill be skipped (already exhausted)?"""
        skill_class = skill.split("/")[-1].replace("hunt-", "")
        return skill_class in exhausted_classes

    def available_types(self) -> list[str]:
        return list(ENGAGEMENT_ROUTES.keys())

    def summary(self) -> dict:
        return {
            "engagement_type": self.engagement_type,
            "phases": {p: len(self.route.get(p, [])) for p in PHASE_ORDER},
            "total_skills": sum(len(self.route.get(p, [])) for p in PHASE_ORDER),
        }
