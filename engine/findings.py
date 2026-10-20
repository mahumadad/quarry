"""Finding lifecycle management.

Status flow: DETECTED → CONFIRMED → EXPLOITED → CHAINED → VALIDATED → REPORTED

Each finding carries evidence, CVSS, MITRE mapping, and chain references.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


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
        if self.findings_file.exists():
            data = json.loads(self.findings_file.read_text())
            for fd in data.get("findings", []):
                f = Finding(**fd)
                self._findings[f.id] = f

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.findings_file.write_text(json.dumps({
            "findings": [asdict(f) for f in self._findings.values()],
            "count": len(self._findings),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def add(self, finding: Finding) -> Finding:
        self._findings[finding.id] = finding
        self._save()
        return finding

    def get(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def update_status(self, finding_id: str, new_status: FindingStatus, reason: str = "") -> bool:
        f = self._findings.get(finding_id)
        if not f:
            return False
        current = FindingStatus(f.status)
        if new_status not in STATUS_TRANSITIONS.get(current, []):
            return False
        f.status_history.append({
            "from": f.status,
            "to": new_status.value,
            "reason": reason,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        f.status = new_status.value
        f.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def add_evidence(self, finding_id: str, evidence: Evidence) -> bool:
        f = self._findings.get(finding_id)
        if not f:
            return False
        f.evidence.append(asdict(evidence))
        f.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

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
