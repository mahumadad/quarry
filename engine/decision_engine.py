"""Decision engine: recommend skills and parameters from an AppProfile.

Given detected tech stack, auth type, API style, and WAF, produces an
ordered RecommendationPlan of skills to run with priority scores and
parameter hints.  Skills appearing for multiple stack components get
boosted priority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


STACK_SKILL_MAP: dict[str, list[str]] = {
    "django": ["hunt/sqli", "hunt/ssti", "hunt/deserialization", "hunt/csrf", "hunt/idor"],
    "flask": ["hunt/ssti", "hunt/sqli", "hunt/ssrf", "hunt/deserialization"],
    "fastapi": ["hunt/sqli", "hunt/ssrf", "hunt/auth-bypass", "hunt/idor"],
    "rails": ["hunt/deserialization", "hunt/sqli", "hunt/csrf", "hunt/open-redirect", "hunt/xss"],
    "laravel": ["hunt/deserialization", "hunt/sqli", "hunt/file-upload", "hunt/xss", "hunt/csrf"],
    "spring": ["hunt/deserialization", "hunt/ssti", "hunt/rce", "hunt/sqli", "hunt/ssrf"],
    "express": ["hunt/xss", "hunt/ssrf", "hunt/prototype-pollution", "hunt/sqli"],
    "nextjs": ["hunt/xss", "hunt/ssrf", "recon/js-analysis", "hunt/open-redirect"],
    "nuxt": ["hunt/xss", "hunt/ssrf", "recon/js-analysis"],
    "react": ["hunt/xss", "recon/js-analysis", "hunt/open-redirect"],
    "angular": ["hunt/xss", "recon/js-analysis", "hunt/open-redirect", "hunt/css-injection"],
    "aspnet": ["hunt/deserialization", "hunt/sqli", "hunt/xss", "hunt/mass-assignment"],
    "php": ["hunt/sqli", "hunt/lfi-rfi", "hunt/file-upload", "hunt/rce", "hunt/xss"],
    "wordpress": ["platform/wordpress-attack", "hunt/sqli", "hunt/xss", "hunt/file-upload"],
    "magento": ["hunt/sqli", "hunt/xss", "hunt/idor", "hunt/csrf", "hunt/deserialization"],
    "drupal": ["hunt/sqli", "hunt/xss", "hunt/deserialization", "hunt/rce"],
    "graphql": ["hunt/graphql", "hunt/idor", "hunt/auth-bypass", "hunt/rate-limiting"],
    "grpc": ["hunt/grpc", "hunt/auth-bypass", "hunt/idor"],
    "websocket": ["hunt/websocket", "hunt/auth-bypass", "hunt/rate-limiting"],
    "jwt": ["hunt/jwt", "hunt/auth-bypass", "hunt/session-management"],
    "oauth": ["hunt/oauth", "hunt/open-redirect", "hunt/csrf"],
    "saml": ["hunt/auth-bypass", "hunt/xxe", "hunt/xss"],
    "nginx": ["hunt/host-header", "hunt/open-redirect", "hunt/http-smuggling"],
    "apache": ["hunt/host-header", "hunt/open-redirect", "hunt/lfi-rfi"],
    "iis": ["hunt/host-header", "hunt/xss", "hunt/deserialization"],
    "tomcat": ["hunt/deserialization", "hunt/rce", "hunt/file-upload"],
    "aws": ["platform/aws-attack", "recon/cloud-recon", "hunt/ssrf"],
    "gcp": ["platform/gcp-attack", "recon/cloud-recon", "hunt/ssrf"],
    "azure": ["platform/azure-attack", "recon/cloud-recon", "hunt/ssrf"],
    "kubernetes": ["platform/kubernetes-attack", "hunt/ssrf", "hunt/idor"],
    "docker": ["platform/docker-attack", "hunt/ssrf"],
    "redis": ["hunt/ssrf", "hunt/auth-bypass", "hunt/info-disclosure"],
    "elasticsearch": ["hunt/ssrf", "hunt/info-disclosure", "hunt/auth-bypass"],
    "mongodb": ["hunt/sqli", "hunt/auth-bypass", "hunt/info-disclosure"],
    "mysql": ["hunt/sqli", "hunt/info-disclosure"],
    "postgresql": ["hunt/sqli", "hunt/info-disclosure"],
    "rabbitmq": ["hunt/auth-bypass", "hunt/info-disclosure"],
    "kafka": ["hunt/auth-bypass", "hunt/info-disclosure"],
    "active-directory": ["platform/active-directory", "hunt/auth-bypass"],
    "android": ["platform/mobile-android", "hunt/auth-bypass", "hunt/idor"],
    "ios": ["platform/mobile-ios", "hunt/auth-bypass", "hunt/idor"],
    "vtex": ["hunt/xss", "hunt/idor", "hunt/api-abuse", "hunt/open-redirect"],
    "shopify": ["hunt/xss", "hunt/idor", "hunt/api-abuse", "hunt/csrf"],
}

AUTH_SKILLS: dict[str, list[str]] = {
    "oauth": ["hunt/oauth", "hunt/open-redirect", "hunt/csrf"],
    "jwt": ["hunt/jwt", "hunt/auth-bypass", "hunt/session-management"],
    "saml": ["hunt/auth-bypass", "hunt/xxe"],
    "mfa": ["hunt/2fa-bypass", "hunt/auth-bypass"],
    "api-key": ["hunt/info-disclosure", "hunt/api-abuse"],
    "basic": ["hunt/auth-bypass", "hunt/rate-limiting"],
    "session-cookie": ["hunt/session-management", "hunt/csrf", "hunt/xss"],
    "sso": ["hunt/oauth", "hunt/auth-bypass", "hunt/open-redirect"],
    "password-reset": ["hunt/password-reset", "hunt/email-injection"],
    "magic-link": ["hunt/password-reset", "hunt/open-redirect", "hunt/rate-limiting"],
}

API_STYLE_SKILLS: dict[str, list[str]] = {
    "rest": ["hunt/idor", "hunt/api-abuse", "hunt/mass-assignment", "hunt/rate-limiting"],
    "graphql": ["hunt/graphql", "hunt/idor", "hunt/rate-limiting"],
    "grpc": ["hunt/grpc", "hunt/idor"],
    "soap": ["hunt/xxe", "hunt/sqli"],
    "websocket": ["hunt/websocket", "hunt/auth-bypass"],
}

WAF_ADJUSTMENTS: dict[str, dict] = {
    "cloudflare": {
        "rate_limit_ms": 500,
        "encoding": "double-url-encode",
        "notes": "Bypass via CF-Connecting-IP header spoofing if origin IP known. Use chunked transfer for large payloads.",
        "param_hints": {"ffuf_rate": "2", "nuclei_rate": "5", "nuclei_bulk": "2"},
    },
    "akamai": {
        "rate_limit_ms": 800,
        "encoding": "unicode-normalize",
        "notes": "Pragma: akamai-x-get-true-cache-key for cache analysis. Try HTTP/2 HPACK smuggling.",
        "param_hints": {"ffuf_rate": "1", "nuclei_rate": "3"},
    },
    "aws-waf": {
        "rate_limit_ms": 300,
        "encoding": "json-body",
        "notes": "JSON body payloads often bypass regex rules. Test with Content-Type: application/json.",
        "param_hints": {"ffuf_rate": "5", "nuclei_rate": "10"},
    },
    "modsecurity": {
        "rate_limit_ms": 200,
        "encoding": "multipart-boundary",
        "notes": "Paranoia levels vary. Try multipart/form-data boundary manipulation.",
        "param_hints": {"ffuf_rate": "5", "nuclei_rate": "15"},
    },
    "imperva": {
        "rate_limit_ms": 600,
        "encoding": "double-url-encode",
        "notes": "IP rotation may help. Test with X-Forwarded-For header chains.",
        "param_hints": {"ffuf_rate": "2", "nuclei_rate": "5"},
    },
    "fortinet": {
        "rate_limit_ms": 300,
        "encoding": "unicode-normalize",
        "notes": "FortiWeb rules are often default. Check /login page for FortiOS version.",
        "param_hints": {"ffuf_rate": "3", "nuclei_rate": "10"},
    },
    "sucuri": {
        "rate_limit_ms": 400,
        "encoding": "case-variation",
        "notes": "Try direct origin IP if discovered via DNS history / CT logs.",
        "param_hints": {"ffuf_rate": "3", "nuclei_rate": "8"},
    },
    "barracuda": {
        "rate_limit_ms": 400,
        "encoding": "double-url-encode",
        "notes": "Often configured with default rules. Test HPP and parameter pollution.",
        "param_hints": {"ffuf_rate": "3", "nuclei_rate": "8"},
    },
    "none": {
        "rate_limit_ms": 0,
        "encoding": "plain",
        "notes": "No WAF detected — full-speed testing allowed.",
        "param_hints": {"ffuf_rate": "50", "nuclei_rate": "50", "nuclei_bulk": "25"},
    },
}

UNIVERSAL_SKILLS = [
    "recon/active-recon",
    "recon/tech-fingerprint",
    "hunt/info-disclosure",
    "hunt/broken-access-control",
    "hunt/cors",
    "hunt/clickjacking",
    "hunt/rate-limiting",
    "core/email-security",
]


@dataclass
class SkillRecommendation:
    name: str
    priority: int = 0
    reason: str = ""
    param_hints: dict = field(default_factory=dict)
    phase: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "priority": self.priority,
            "reason": self.reason,
            "param_hints": self.param_hints,
            "phase": self.phase,
        }


@dataclass
class RecommendationPlan:
    skills: list[SkillRecommendation] = field(default_factory=list)
    waf_notes: str = ""
    waf_param_hints: dict = field(default_factory=dict)
    estimated_phases: int = 0
    tech_stack: list[str] = field(default_factory=list)
    auth_types: list[str] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "skills": [s.to_dict() for s in self.skills],
            "waf_notes": self.waf_notes,
            "waf_param_hints": self.waf_param_hints,
            "estimated_phases": self.estimated_phases,
            "tech_stack": self.tech_stack,
            "auth_types": self.auth_types,
            "generated_at": self.generated_at,
        }

    def by_phase(self) -> dict[str, list[SkillRecommendation]]:
        phases: dict[str, list[SkillRecommendation]] = {}
        for s in self.skills:
            phases.setdefault(s.phase, []).append(s)
        return phases

    def top(self, n: int = 10) -> list[SkillRecommendation]:
        return self.skills[:n]


def recommend(app_profile: dict) -> RecommendationPlan:
    """Produce an ordered skill plan from an AppProfile dict.

    Expected keys in app_profile:
      tech_stack: list[str]  — detected technologies (lowercase)
      auth_type: str | list[str]  — authentication mechanisms
      api_style: str  — "rest", "graphql", "grpc", "soap", "websocket"
      waf: str  — detected WAF (lowercase) or "none"
      detected_versions: dict  — optional, product→version
    """
    tech_stack = [t.lower() for t in app_profile.get("tech_stack", [])]
    auth_raw = app_profile.get("auth_type", [])
    auth_types = [auth_raw] if isinstance(auth_raw, str) else [a.lower() for a in auth_raw]
    api_style = app_profile.get("api_style", "rest").lower()
    waf = app_profile.get("waf", "none").lower()

    skill_scores: dict[str, dict] = {}

    def _add(name: str, priority: int, reason: str, phase: str, hints: dict | None = None):
        if name in skill_scores:
            skill_scores[name]["priority"] += priority
            if reason not in skill_scores[name]["reason"]:
                skill_scores[name]["reason"] += f"; {reason}"
        else:
            skill_scores[name] = {
                "priority": priority,
                "reason": reason,
                "phase": phase,
                "param_hints": hints or {},
            }

    for tech in tech_stack:
        for skill in STACK_SKILL_MAP.get(tech, []):
            _add(skill, 10, f"stack:{tech}", _infer_phase(skill))

    for auth in auth_types:
        for skill in AUTH_SKILLS.get(auth, []):
            _add(skill, 8, f"auth:{auth}", _infer_phase(skill))

    for skill in API_STYLE_SKILLS.get(api_style, []):
        _add(skill, 7, f"api:{api_style}", _infer_phase(skill))

    for skill in UNIVERSAL_SKILLS:
        _add(skill, 3, "universal", _infer_phase(skill))

    waf_info = WAF_ADJUSTMENTS.get(waf, WAF_ADJUSTMENTS.get("none", {}))
    waf_hints = waf_info.get("param_hints", {})
    waf_notes = waf_info.get("notes", "")

    if waf != "none":
        for entry in skill_scores.values():
            entry["param_hints"].update(waf_hints)

    ordered = sorted(skill_scores.items(), key=lambda kv: (-kv[1]["priority"], kv[0]))

    skills = [
        SkillRecommendation(
            name=name,
            priority=data["priority"],
            reason=data["reason"],
            param_hints=data["param_hints"],
            phase=data["phase"],
        )
        for name, data in ordered
    ]

    phases = {s.phase for s in skills}

    return RecommendationPlan(
        skills=skills,
        waf_notes=waf_notes,
        waf_param_hints=waf_hints,
        estimated_phases=len(phases),
        tech_stack=tech_stack,
        auth_types=auth_types,
    )


def recommend_for_finding(finding: dict, app_profile: dict) -> list[SkillRecommendation]:
    """Given a finding, recommend follow-up skills for chain exploitation."""
    vc = finding.get("vuln_class", "").lower()
    from .chain_engine import ENABLES_MAP
    enabled = ENABLES_MAP.get(vc, [])
    plan = recommend(app_profile)
    return [s for s in plan.skills if any(e in s.name for e in enabled)]


def _infer_phase(skill_name: str) -> str:
    if skill_name.startswith("recon/"):
        return "recon"
    if skill_name.startswith("platform/"):
        return "platform"
    if skill_name.startswith("hunt/"):
        return "hunting"
    if skill_name.startswith("core/"):
        return "core"
    if skill_name.startswith("chain/"):
        return "chaining"
    if skill_name.startswith("report/"):
        return "reporting"
    if skill_name.startswith("validate/"):
        return "validating"
    return "hunting"
