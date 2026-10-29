"""Fire / Smoke / Ice priority classification.

Deterministic triage tier based on CVSS 4.0 + EPSS + CISA KEV + public
exploit availability.  Tier modulates remediation PRIORITY, not severity
(CVSS stays untouched).

Based on CVEngine's model, adapted to this plugin's data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class Tier(str, Enum):
    FIRE = "fire"
    SMOKE = "smoke"
    ICE = "ice"


TIER_LABELS = {
    Tier.FIRE: "P1 — validate and report immediately",
    Tier.SMOKE: "Investigate this phase, confirm exploitability",
    Tier.ICE: "Backlog — register, monitor, re-evaluate monthly",
}


@dataclass(frozen=True)
class PriorityInput:
    cvss_score: float = 0.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    in_cisa_kev: bool = False
    has_public_exploit: bool = False
    has_metasploit_module: bool = False
    has_unverified_poc: bool = False
    in_enisa_euvd: bool = False
    version_match: bool = False
    in_chain: bool = False
    evidence_tag: str = "unproven"


@dataclass
class PriorityResult:
    tier: Tier
    signals: list[str]
    action: str
    score: int
    computed_at: str = ""

    def __post_init__(self):
        if not self.computed_at:
            self.computed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "signals": self.signals,
            "action": self.action,
            "score": self.score,
            "computed_at": self.computed_at,
        }


def classify(inp: PriorityInput) -> PriorityResult:
    """Pure function: classify a finding into Fire / Smoke / Ice.

    Fire signals (any one is enough):
      - CVE in CISA KEV
      - Verified public exploit (Metasploit module or ExploitDB verified)
      - EPSS > 0.7

    Smoke signals (any one):
      - CVSS >= 7.0 AND EPSS > 0.1
      - Unverified PoC exists
      - Listed in ENISA EUVD as exploited
      - Exact product+version match in target inventory

    Everything else → Ice.

    The numeric score (0–100) ranks within a tier for sorting.
    """
    signals: list[str] = []

    # --- Fire checks ---
    if inp.in_cisa_kev:
        signals.append("CISA KEV member")
    if inp.has_metasploit_module:
        signals.append("Metasploit module available")
    if inp.has_public_exploit:
        signals.append("Verified public exploit")
    if inp.epss_score > 0.7:
        signals.append(f"EPSS {inp.epss_score:.3f} > 0.7")

    fire_signals = len(signals)
    if fire_signals > 0:
        score = _fire_score(inp, fire_signals)
        return PriorityResult(
            tier=Tier.FIRE,
            signals=signals,
            action=TIER_LABELS[Tier.FIRE],
            score=score,
        )

    # --- Smoke checks ---
    if inp.cvss_score >= 7.0 and inp.epss_score > 0.1:
        signals.append(f"CVSS {inp.cvss_score} + EPSS {inp.epss_score:.3f}")
    if inp.has_unverified_poc:
        signals.append("Unverified PoC exists")
    if inp.in_enisa_euvd:
        signals.append("ENISA EUVD listed as exploited")
    if inp.version_match:
        signals.append("Exact product+version match in inventory")

    if signals:
        score = _smoke_score(inp, len(signals))
        return PriorityResult(
            tier=Tier.SMOKE,
            signals=signals,
            action=TIER_LABELS[Tier.SMOKE],
            score=score,
        )

    # --- Ice ---
    return PriorityResult(
        tier=Tier.ICE,
        signals=["No exploitation signals"],
        action=TIER_LABELS[Tier.ICE],
        score=_ice_score(inp),
    )


def classify_finding(finding_dict: dict) -> PriorityResult:
    """Convenience: classify from a Finding's dict representation.

    Reads metadata.epss_score, metadata.epss_percentile,
    metadata.cisa_kev, metadata.public_exploit, etc.
    """
    meta = finding_dict.get("metadata", {})
    inp = PriorityInput(
        cvss_score=finding_dict.get("cvss_score", 0.0),
        epss_score=meta.get("epss_score", 0.0),
        epss_percentile=meta.get("epss_percentile", 0.0),
        in_cisa_kev=meta.get("cisa_kev", False),
        has_public_exploit=meta.get("public_exploit", False),
        has_metasploit_module=meta.get("metasploit_module", False),
        has_unverified_poc=meta.get("unverified_poc", False),
        in_enisa_euvd=meta.get("enisa_euvd", False),
        version_match=meta.get("version_match", False),
        in_chain=bool(finding_dict.get("chain_refs")),
        evidence_tag=finding_dict.get("evidence_tag", "unproven"),
    )
    return classify(inp)


def batch_classify(findings: list[dict]) -> list[dict]:
    """Classify a list of findings, return sorted by tier then score desc."""
    results = []
    tier_order = {Tier.FIRE: 0, Tier.SMOKE: 1, Tier.ICE: 2}
    for f in findings:
        result = classify_finding(f)
        results.append({
            "finding_id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cvss_score": f.get("cvss_score", 0.0),
            **result.to_dict(),
        })
    results.sort(key=lambda r: (tier_order.get(Tier(r["tier"]), 9), -r["score"]))
    return results


# --- Internal scoring (0–100 within tier) ---

def _fire_score(inp: PriorityInput, signal_count: int) -> int:
    score = 50
    score += min(signal_count * 10, 30)
    if inp.evidence_tag == "demonstrated":
        score += 10
    if inp.in_chain:
        score += 5
    score += int(inp.epss_score * 5)
    return min(score, 100)


def _smoke_score(inp: PriorityInput, signal_count: int) -> int:
    score = 30
    score += min(signal_count * 10, 20)
    score += int(inp.cvss_score * 3)
    if inp.evidence_tag == "demonstrated":
        score += 10
    elif inp.evidence_tag == "inferred":
        score += 5
    if inp.in_chain:
        score += 5
    return min(score, 100)


def _ice_score(inp: PriorityInput) -> int:
    score = int(inp.cvss_score * 5)
    score += int(inp.epss_score * 10)
    if inp.evidence_tag == "inferred":
        score += 5
    if inp.in_chain:
        score += 5
    return min(score, 100)
