"""Engagement intelligence — capability graph and exhaustion tracking.

The Brain is the persistent memory of an engagement. It tracks:
- Capabilities gained (what the attacker can do now)
- Vectors exhausted (what was tried and failed)
- Vectors active (what is in progress)
- Briefings (generated before each agent dispatch)

Persists to .pentest-state/brain.json.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


# Capability taxonomy — what a finding GIVES an attacker
CAPABILITY_TAXONOMY = {
    "read_data": "Can read application data",
    "write_data": "Can write/modify application data",
    "delete_data": "Can delete application data",
    "steal_token": "Can steal authentication tokens/cookies",
    "forge_request": "Can forge authenticated requests",
    "impersonate_user": "Can act as another user",
    "impersonate_admin": "Can act as an admin",
    "execute_js": "Can execute JavaScript in user context",
    "execute_server": "Can execute code on the server",
    "read_files": "Can read server filesystem",
    "write_files": "Can write to server filesystem",
    "internal_network": "Can reach internal network services",
    "cloud_metadata": "Can access cloud instance metadata",
    "cloud_credentials": "Can obtain cloud IAM credentials",
    "database_access": "Can query the database directly",
    "influence_workflow": "Can manipulate business logic flow",
    "denial_of_service": "Can disrupt service availability",
    "pivot_host": "Can move laterally to another host",
    "exfiltrate_bulk": "Can extract data at scale",
}

# What each finding class typically gives and needs
FINDING_CAPABILITIES = {
    "xss": {"gives": ["execute_js", "steal_token", "forge_request"], "needs": []},
    "sqli": {"gives": ["read_data", "database_access", "read_files"], "needs": []},
    "ssrf": {"gives": ["internal_network", "cloud_metadata", "read_files"], "needs": []},
    "idor": {"gives": ["read_data", "write_data", "delete_data"], "needs": []},
    "rce": {"gives": ["execute_server", "read_files", "write_files", "pivot_host"], "needs": []},
    "ssti": {"gives": ["execute_server", "read_files"], "needs": []},
    "lfi": {"gives": ["read_files"], "needs": []},
    "file-upload": {"gives": ["write_files", "execute_server"], "needs": []},
    "auth-bypass": {"gives": ["impersonate_user", "impersonate_admin"], "needs": []},
    "csrf": {"gives": ["forge_request", "influence_workflow"], "needs": []},
    "cors": {"gives": ["read_data", "steal_token"], "needs": ["execute_js"]},
    "open-redirect": {"gives": ["steal_token"], "needs": []},
    "xxe": {"gives": ["read_files", "internal_network"], "needs": []},
    "deserialization": {"gives": ["execute_server"], "needs": []},
    "jwt": {"gives": ["impersonate_user", "impersonate_admin"], "needs": []},
    "race-condition": {"gives": ["influence_workflow", "write_data"], "needs": []},
    "info-disclosure": {"gives": [], "needs": []},
    "subdomain-takeover": {"gives": ["steal_token", "execute_js"], "needs": []},
    "cache-poisoning": {"gives": ["execute_js", "influence_workflow"], "needs": []},
    "http-smuggling": {"gives": ["forge_request", "internal_network"], "needs": []},
    "prototype-pollution": {"gives": ["execute_js", "influence_workflow"], "needs": []},
    "mass-assignment": {"gives": ["write_data", "impersonate_admin"], "needs": []},
    "graphql": {"gives": ["read_data", "denial_of_service"], "needs": []},
    "websocket": {"gives": ["forge_request", "read_data"], "needs": []},
}

# Trust boundary levels for chain scoring
TRUST_BOUNDARIES = [
    "unauthenticated",
    "authenticated_user",
    "privileged_user",
    "admin",
    "host_access",
    "cloud_account",
    "infrastructure",
]


@dataclass
class CapabilityEntry:
    capability: str
    source_finding_id: str
    confidence: float = 0.0  # 0-1
    gained_at: str = ""
    notes: str = ""

    def __post_init__(self):
        if not self.gained_at:
            self.gained_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ExhaustedVector:
    vuln_class: str
    asset: str
    technique: str
    reason: str  # why it failed
    attempts: int = 1
    exhausted_at: str = ""

    def __post_init__(self):
        if not self.exhausted_at:
            self.exhausted_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ActiveVector:
    vuln_class: str
    asset: str
    hypothesis: str
    started_at: str = ""
    agent: str = ""

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


class Brain:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.brain_file = self.state_dir / "brain.json"
        self._data = self._load()

    def _load(self) -> dict:
        if self.brain_file.exists():
            return json.loads(self.brain_file.read_text())
        return {
            "capabilities": [],
            "exhausted": [],
            "active": [],
            "notes": [],
            "updated_at": None,
        }

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.brain_file.write_text(json.dumps(self._data, indent=2))

    def add_capability(self, capability: str, source_finding_id: str,
                       confidence: float = 1.0, notes: str = "") -> bool:
        if capability not in CAPABILITY_TAXONOMY:
            return False
        entry = CapabilityEntry(
            capability=capability,
            source_finding_id=source_finding_id,
            confidence=confidence,
            notes=notes,
        )
        self._data["capabilities"].append(asdict(entry))
        self._save()
        return True

    def add_capabilities_from_finding(self, finding_id: str, vuln_class: str,
                                       confidence: float = 1.0):
        caps = FINDING_CAPABILITIES.get(vuln_class, {}).get("gives", [])
        for cap in caps:
            self.add_capability(cap, finding_id, confidence)

    def has_capability(self, capability: str) -> bool:
        return any(c["capability"] == capability for c in self._data["capabilities"])

    def get_capabilities(self) -> list[dict]:
        return list(self._data["capabilities"])

    def mark_exhausted(self, vuln_class: str, asset: str, technique: str,
                       reason: str, attempts: int = 1):
        entry = ExhaustedVector(
            vuln_class=vuln_class, asset=asset, technique=technique,
            reason=reason, attempts=attempts,
        )
        self._data["exhausted"].append(asdict(entry))
        self._save()

    def is_exhausted(self, vuln_class: str, asset: str) -> list[dict]:
        return [e for e in self._data["exhausted"]
                if e["vuln_class"] == vuln_class and e["asset"] == asset]

    def start_vector(self, vuln_class: str, asset: str, hypothesis: str,
                     agent: str = ""):
        entry = ActiveVector(
            vuln_class=vuln_class, asset=asset, hypothesis=hypothesis,
            agent=agent,
        )
        self._data["active"].append(asdict(entry))
        self._save()

    def close_vector(self, vuln_class: str, asset: str):
        self._data["active"] = [
            a for a in self._data["active"]
            if not (a["vuln_class"] == vuln_class and a["asset"] == asset)
        ]
        self._save()

    def get_active_vectors(self) -> list[dict]:
        return list(self._data["active"])

    def add_note(self, note: str):
        self._data["notes"].append({
            "note": note,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        self._save()

    def generate_briefing(self, target_vuln_class: str = "",
                          target_asset: str = "") -> dict:
        """Generate a briefing for an agent about to start work."""
        briefing = {
            "capabilities_gained": self.get_capabilities(),
            "capability_summary": [
                CAPABILITY_TAXONOMY[c["capability"]]
                for c in self._data["capabilities"]
            ],
        }
        if target_vuln_class and target_asset:
            briefing["already_tried"] = self.is_exhausted(
                target_vuln_class, target_asset)
            briefing["currently_active"] = [
                a for a in self._data["active"]
                if a["vuln_class"] == target_vuln_class
            ]
        briefing["active_vector_count"] = len(self._data["active"])
        briefing["exhausted_count"] = len(self._data["exhausted"])
        briefing["recent_notes"] = self._data["notes"][-5:]
        return briefing

    def suggest_next_targets(self, findings: list[dict],
                             coverage_gaps: list[dict]) -> list[dict]:
        """Suggest what to hunt next based on capabilities and gaps."""
        suggestions = []
        current_caps = {c["capability"] for c in self._data["capabilities"]}
        exhausted_pairs = {
            (e["vuln_class"], e["asset"]) for e in self._data["exhausted"]
        }

        for gap in coverage_gaps:
            vc = gap.get("vuln_class", "")
            asset = gap.get("asset", "")
            if (vc, asset) in exhausted_pairs:
                continue
            needed = FINDING_CAPABILITIES.get(vc, {}).get("needs", [])
            if all(n in current_caps for n in needed):
                suggestions.append({
                    "vuln_class": vc,
                    "asset": asset,
                    "reason": f"Prerequisites met: {needed}" if needed else "No prerequisites",
                    "potential_gives": FINDING_CAPABILITIES.get(vc, {}).get("gives", []),
                })

        suggestions.sort(key=lambda s: len(s["potential_gives"]), reverse=True)
        return suggestions[:10]

    def summary(self) -> dict:
        return {
            "capabilities_count": len(self._data["capabilities"]),
            "unique_capabilities": list({c["capability"] for c in self._data["capabilities"]}),
            "exhausted_count": len(self._data["exhausted"]),
            "active_count": len(self._data["active"]),
            "notes_count": len(self._data["notes"]),
        }
