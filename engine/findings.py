"""Finding lifecycle management.

Status flow: DETECTED → CONFIRMED → EXPLOITED → CHAINED → VALIDATED → REPORTED

Each finding carries evidence, CVSS, MITRE mapping, and chain references.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

try:
    from .custody import CustodyLog
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from custody import CustodyLog
    from storage import atomic_write_json, engagement_lock, read_json


HUNT_MODE_SEVERITY_GATES = {
    "bounty": 8.0,
    "pentest": 4.0,
    "comprehensive": 0.0,
}


def severity_gate_check(mode: str, cvss_score: float) -> tuple[bool, str]:
    """Check if a finding meets the severity gate for the engagement mode."""
    threshold = HUNT_MODE_SEVERITY_GATES.get(mode, 0.0)
    if cvss_score >= threshold:
        return True, ""
    return False, f"CVSS {cvss_score} below {mode} threshold ({threshold})"


class FindingStatus(str, Enum):
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    CHAINED = "chained"
    VALIDATED = "validated"
    REPORTED = "reported"
    KILLED = "killed"


class EvidenceTag(str, Enum):
    DEMONSTRATED = "demonstrated"
    INFERRED = "inferred"
    UNPROVEN = "unproven"


STATUS_TRANSITIONS = {
    FindingStatus.DETECTED: [FindingStatus.CONFIRMED, FindingStatus.KILLED],
    FindingStatus.CONFIRMED: [FindingStatus.EXPLOITED, FindingStatus.CHAINED, FindingStatus.VALIDATED, FindingStatus.KILLED],
    FindingStatus.EXPLOITED: [FindingStatus.CHAINED, FindingStatus.VALIDATED, FindingStatus.KILLED],
    FindingStatus.CHAINED: [FindingStatus.VALIDATED, FindingStatus.KILLED],
    FindingStatus.VALIDATED: [FindingStatus.REPORTED],
    FindingStatus.REPORTED: [],
    FindingStatus.KILLED: [],
}


@dataclass
class Evidence:
    type: str  # request_response, tool_output, screenshot, log
    content: str
    timestamp: str = ""
    tool: str = ""
    tag: str = EvidenceTag.UNPROVEN.value

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    id: str = ""
    title: str = ""
    vuln_class: str = ""
    cwe: list[str] = field(default_factory=list)
    severity: str = ""  # critical, high, medium, low, info
    cvss_vector: str = ""
    cvss_score: float = 0.0
    status: str = FindingStatus.DETECTED.value
    target_asset: str = ""
    description: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    evidence: list[dict] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    chain_refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence_tag: str = EvidenceTag.UNPROVEN.value
    created_at: str = ""
    updated_at: str = ""
    status_history: list[dict] = field(default_factory=list)
    rebuttal_result: str = ""  # ACCEPTED, STALL, KILLED
    rebuttal_rounds: int = 0
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = f"F-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at


class FindingsStore:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.findings_file = self.state_dir / "findings.json"
        self._findings: dict[str, Finding] = {}
        self._load()

    def _load(self):
        self._findings = {}
        if self.findings_file.exists():
            data = read_json(self.findings_file)
            for fd in data.get("findings", []):
                f = Finding(**fd)
                self._findings[f.id] = f

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.findings_file, {
            "findings": [asdict(f) for f in self._findings.values()],
            "count": len(self._findings),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def add(self, finding: Finding) -> Finding:
        if finding.status != FindingStatus.DETECTED.value:
            raise ValueError(
                f"New findings must start as '{FindingStatus.DETECTED.value}', "
                f"got '{finding.status}'. Use update_status() to advance.")
        with engagement_lock(self.state_dir.parent):
            self._load()
            self._findings[finding.id] = finding
            self._save()
            CustodyLog(self.state_dir.parent).append("finding_created", {
                "finding_id": finding.id, "vuln_class": finding.vuln_class,
                "target_asset": finding.target_asset})
        return finding

    def get(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def update_status(self, finding_id: str, new_status: FindingStatus, reason: str = "") -> bool:
        with engagement_lock(self.state_dir.parent):
            self._load()
            f = self._findings.get(finding_id)
            if not f:
                return False
            current = FindingStatus(f.status)
            if new_status not in STATUS_TRANSITIONS.get(current, []):
                return False
            if new_status == FindingStatus.VALIDATED:
                if not f.evidence:
                    raise ValueError(f"Cannot validate {finding_id}: no evidence attached")
                if f.evidence_tag == EvidenceTag.UNPROVEN.value:
                    raise ValueError(f"Cannot validate {finding_id}: evidence_tag is still 'unproven'")
                if len(f.steps_to_reproduce) < 1:
                    raise ValueError(f"Cannot validate {finding_id}: no steps_to_reproduce")
            previous = f.status
            f.status_history.append({"from": previous, "to": new_status.value,
                "reason": reason, "at": datetime.now(timezone.utc).isoformat()})
            f.status = new_status.value
            f.updated_at = datetime.now(timezone.utc).isoformat()
            self._save()
            CustodyLog(self.state_dir.parent).append("status_change", {
                "finding_id": finding_id, "from": previous, "to": new_status.value,
                "reason": reason})
        return True

    def add_evidence(self, finding_id: str, evidence: Evidence) -> bool:
        with engagement_lock(self.state_dir.parent):
            self._load()
            f = self._findings.get(finding_id)
            if not f:
                return False
            ev_dict = asdict(evidence)
            ev_dict["sha256"] = hashlib.sha256(evidence.content.encode("utf-8")).hexdigest()
            f.evidence.append(ev_dict)
            f.updated_at = datetime.now(timezone.utc).isoformat()
            self._save()
            CustodyLog(self.state_dir.parent).evidence_captured(
                finding_id, ev_dict["sha256"], evidence.tool or evidence.type)
        return True

    def verify_evidence_integrity(self, finding_id: str) -> list[dict]:
        """Check all evidence hashes. Returns list of tampered items."""
        f = self._findings.get(finding_id)
        if not f:
            return []
        tampered = []
        for i, ev in enumerate(f.evidence):
            stored_hash = ev.get("sha256", "")
            if not stored_hash:
                tampered.append({"index": i, "reason": "no hash"})
                continue
            computed = hashlib.sha256(
                ev.get("content", "").encode("utf-8")
            ).hexdigest()
            if computed != stored_hash:
                tampered.append({
                    "index": i,
                    "reason": "hash mismatch",
                    "expected": stored_hash,
                    "actual": computed,
                })
        return tampered

    def list_by_status(self, status: FindingStatus | None = None) -> list[Finding]:
        if status is None:
            return list(self._findings.values())
        return [f for f in self._findings.values() if f.status == status.value]

    def list_by_class(self, vuln_class: str) -> list[Finding]:
        return [f for f in self._findings.values() if f.vuln_class == vuln_class]

    def list_chainable(self) -> list[Finding]:
        """Findings that are confirmed or exploited and can participate in chains."""
        chainable = {FindingStatus.CONFIRMED.value, FindingStatus.EXPLOITED.value, FindingStatus.CHAINED.value}
        return [f for f in self._findings.values() if f.status in chainable]

    def completion_score(self, finding_id: str) -> dict:
        """Numeric completeness metric for a finding (Gap #15).

        Scores 0-100 based on what's filled in: evidence, CVSS, MITRE,
        steps to reproduce, remediation, evidence tag quality, rebuttal.
        """
        f = self._findings.get(finding_id)
        if not f:
            return {"finding_id": finding_id, "score": 0, "missing": ["not found"]}

        checks = {
            "has_evidence": (bool(f.evidence), 20),
            "has_cvss": (bool(f.cvss_vector), 15),
            "has_mitre": (bool(f.mitre_attack), 10),
            "has_steps": (len(f.steps_to_reproduce) >= 2, 15),
            "has_remediation": (bool(f.remediation), 10),
            "evidence_demonstrated": (f.evidence_tag == EvidenceTag.DEMONSTRATED.value, 15),
            "has_impact": (bool(f.impact), 5),
            "has_description": (bool(f.description), 5),
            "rebuttal_passed": (f.rebuttal_result == "ACCEPTED", 5),
        }

        score = 0
        missing = []
        for check_name, (passed, weight) in checks.items():
            if passed:
                score += weight
            else:
                missing.append(check_name)

        return {
            "finding_id": finding_id,
            "score": score,
            "max": 100,
            "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D",
            "missing": missing,
        }

    def bulk_completion_scores(self) -> list[dict]:
        """Completion scores for all findings, sorted lowest first."""
        scores = [self.completion_score(fid) for fid in self._findings]
        return sorted(scores, key=lambda s: s["score"])

    def summary(self) -> dict:
        by_status = {}
        by_severity = {}
        by_class = {}
        for f in self._findings.values():
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
        return {
            "total": len(self._findings),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_class": by_class,
        }
