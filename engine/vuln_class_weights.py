"""Impact/frequency prior per vulnerability class ("bounty economics").

The router already honours brain suggestions and coverage gaps first; this
module adds the missing signal for everything else: *which classes are worth
hunting first* when nothing else distinguishes them. Weights are a 0..1 prior
blending real-world severity and how often the class actually pays out in
pentest/bounty work — not a hard severity (CVSS stays the finding's job).

Keyed by the class slug, i.e. the last path segment of a hunt skill
(`skills/hunt/<slug>/SKILL.md` -> `<slug>`), matching how
`Router.get_hunt_priority` derives the class from a skill path.
"""
from __future__ import annotations

DEFAULT_WEIGHT = 0.5

# Crown jewels: direct or near-direct path to code exec, data, or full account
# compromise. Hunt these first.
_CROWN = {
    "rce": 0.98,
    "sqli": 0.97,
    "ssrf": 0.95,
    "deserialization": 0.95,
    "auth-bypass": 0.94,
    "broken-access-control": 0.92,
    "idor": 0.90,
    "ssti": 0.90,
}

# High: frequent, high-severity, strong chain primitives.
_HIGH = {
    "oauth": 0.86,
    "jwt": 0.85,
    "nosqli": 0.82,
    "file-upload": 0.82,
    "graphql": 0.80,
    "mass-assignment": 0.80,
    "xxe": 0.80,
    "lfi-rfi": 0.80,
    "ldap-xpath-injection": 0.76,
    "http-smuggling": 0.78,
    "host-header": 0.74,
    "prototype-pollution": 0.74,
    # framework-specific hunts usually chain to RCE/leak
    "nextjs": 0.72,
    "nodejs": 0.72,
    "aspnet": 0.72,
    "laravel": 0.72,
    "springboot": 0.72,
}

# Medium-high: common, exploitable, often chained.
_MED_HIGH = {
    "business-logic": 0.70,
    "race-condition": 0.70,
    "saml": 0.70,
    "cache-poisoning": 0.68,
    "parser-desync": 0.68,
    "password-reset": 0.67,
    "2fa-bypass": 0.67,
    "shadow-api": 0.66,
    "api-abuse": 0.65,
    "websocket": 0.64,
    "cors": 0.63,
    "authz-matrix": 0.63,
    "credential-testing": 0.62,
    "parameter-pollution": 0.60,
    "xss": 0.60,
}

# Medium: real but usually lower impact or needs a chain to matter.
_MEDIUM = {
    "crlf-injection": 0.56,
    "email-injection": 0.55,
    "ntlm-info-disclosure": 0.55,
    "info-disclosure": 0.54,
    "session-management": 0.54,
    "subdomain-takeover": 0.53,
    "dom-based": 0.55,
    "exceptional-conditions": 0.52,
    "captcha-bypass": 0.48,
    "grpc": 0.52,
    "fuzzing": 0.50,
}

# Lower: low standalone impact; valuable mainly as chain anchors or hygiene.
_LOW = {
    "cryptographic-oracle": 0.44,
    "css-injection": 0.40,
    "data-exfiltration-test": 0.42,
    "persistence-check": 0.40,
    "lateral-movement": 0.45,
    "post-exploitation": 0.45,
    "open-redirect": 0.35,
    "clickjacking": 0.33,
    "rate-limiting": 0.34,
}

VULN_CLASS_WEIGHT: dict[str, float] = {
    **_CROWN, **_HIGH, **_MED_HIGH, **_MEDIUM, **_LOW,
}


def class_weight(vuln_class: str) -> float:
    """Prior for a class slug; unknown or empty -> DEFAULT_WEIGHT."""
    return VULN_CLASS_WEIGHT.get(vuln_class, DEFAULT_WEIGHT)


def rank_classes(classes: list[str]) -> list[str]:
    """Return the classes ordered by weight, highest first (stable on ties)."""
    return sorted(classes, key=lambda c: -class_weight(c))
