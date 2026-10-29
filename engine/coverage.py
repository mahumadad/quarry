"""Coverage at asset × class × endpoint × identity × technique granularity."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from storage import atomic_write_json, engagement_lock, read_json

ALL_VULN_CLASSES = [
    "sqli", "xss-reflected", "xss-stored", "xss-dom", "ssrf", "idor", "csrf", "rce",
    "ssti", "xxe", "lfi", "rfi", "auth-bypass", "race-condition", "cors", "open-redirect",
    "info-disclosure", "deserialization", "graphql", "websocket", "jwt", "oauth", "api-abuse",
    "file-upload", "cache-poisoning", "http-smuggling", "subdomain-takeover", "crlf-injection",
    "clickjacking", "host-header-injection", "parameter-pollution", "prototype-pollution",
    "mass-assignment", "broken-access-control", "business-logic", "rate-limiting",
    "password-reset", "2fa-bypass", "session-management", "email-injection",
    "css-injection", "cryptographic-oracle",
]
STATUSES = {"not_tested", "tested_clean", "finding_detected", "partial", "inconclusive",
            "blocked", "skipped", "not_applicable", "tool_unavailable", "out_of_scope",
            "deferred", "retest_required"}
CONCLUSIVE = {"tested_clean", "finding_detected"}
NOT_APPLICABLE = {"not_applicable", "out_of_scope"}


@dataclass
class CoverageEntry:
    asset: str
    vuln_class: str
    status: str = "not_tested"
    skill_used: str = ""
    notes: str = ""
    tested_at: str = ""
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    identity: str = ""
    technique: str = ""
    evidence_artifacts: list[str] = field(default_factory=list)
    evidence_complete: bool = False
    run_id: str = ""
    task_id: str = ""

    @property
    def key(self) -> str:
        return "\x1f".join([self.asset, self.vuln_class, self.endpoint, self.method,
                            self.parameter, self.identity, self.technique])


class CoverageTracker:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.coverage_file = self.state_dir / "coverage.json"
        self._entries: dict[str, CoverageEntry] = {}
        self._assets: set[str] = set()
        self._load()

    def _load(self):
        self._entries, self._assets = {}, set()
        if not self.coverage_file.exists():
            return
        data = read_json(self.coverage_file)
        for raw in data.get("entries", []):
            entry = CoverageEntry(**raw)
            # Legacy tested cells have no artifact metadata; preserve their status
            # but do not claim artifact-backed conclusive coverage.
            self._entries[entry.key] = entry
            self._assets.add(entry.asset)

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.coverage_file, {
            "schema_version": 2, "entries": [asdict(e) for e in self._entries.values()],
            "summary": self.summary(), "updated_at": datetime.now(timezone.utc).isoformat()})

    def add_asset(self, asset: str):
        with engagement_lock(self.state_dir.parent):
            self._load()
            self._assets.add(asset)
            for vuln_class in ALL_VULN_CLASSES:
                entry = CoverageEntry(asset=asset, vuln_class=vuln_class)
                self._entries.setdefault(entry.key, entry)
            self._save()

    def add_surface(self, asset: str, endpoint: str = "", method: str = "",
                    parameters: list[str] | None = None, identities: list[str] | None = None,
                    vuln_classes: list[str] | None = None) -> None:
        with engagement_lock(self.state_dir.parent):
            self._load()
            self._assets.add(asset)
            for vuln_class in vuln_classes or ALL_VULN_CLASSES:
                if vuln_class not in ALL_VULN_CLASSES:
                    raise ValueError(f"Unknown vulnerability class: {vuln_class}")
                for parameter in parameters or [""]:
                    for identity in identities or [""]:
                        entry = CoverageEntry(asset=asset, vuln_class=vuln_class,
                            endpoint=endpoint, method=method.upper(), parameter=parameter,
                            identity=identity)
                        self._entries.setdefault(entry.key, entry)
            self._save()

    def mark_tested(self, asset: str, vuln_class: str, status: str = "tested_clean",
                    skill_used: str = "", notes: str = "", endpoint: str = "", method: str = "",
                    parameter: str = "", identity: str = "", technique: str = "",
                    evidence_artifacts: list[str] | None = None, evidence_complete: bool = False,
                    run_id: str = "", task_id: str = ""):
        if status not in STATUSES:
            raise ValueError(f"Invalid coverage status: {status}")
        artifacts = evidence_artifacts or []
        if status in CONCLUSIVE and (not evidence_complete or not artifacts):
            raise ValueError("Conclusive coverage requires complete evidence artifact references")
        with engagement_lock(self.state_dir.parent):
            self._load()
            self._assets.add(asset)
            entry = CoverageEntry(asset=asset, vuln_class=vuln_class, status=status,
                skill_used=skill_used, notes=notes, tested_at=datetime.now(timezone.utc).isoformat(),
                endpoint=endpoint, method=method.upper(), parameter=parameter, identity=identity,
                technique=technique, evidence_artifacts=artifacts,
                evidence_complete=evidence_complete, run_id=run_id, task_id=task_id)
            self._entries[entry.key] = entry
            self._save()

    def mark_skipped(self, asset: str, vuln_class: str, reason: str = ""):
        self.mark_tested(asset, vuln_class, status="skipped", notes=reason)

    def get_gaps(self) -> list[dict]:
        return [{"asset": e.asset, "vuln_class": e.vuln_class, "endpoint": e.endpoint,
                 "method": e.method, "parameter": e.parameter, "identity": e.identity,
                 "technique": e.technique, "status": e.status, "reason": e.notes}
                for e in self._entries.values() if e.status not in CONCLUSIVE | NOT_APPLICABLE]

    def get_asset_coverage(self, asset: str) -> dict:
        entries = [e for e in self._entries.values() if e.asset == asset]
        applicable = [e for e in entries if e.status not in NOT_APPLICABLE]
        conclusive = [e for e in applicable if e.status in CONCLUSIVE]
        return {"asset": asset, "total": len(entries), "applicable": len(applicable),
                "tested": len(conclusive), "ratio": len(conclusive) / len(applicable) if applicable else 1.0,
                "by_status": self._count_by_status(entries)}

    def summary(self) -> dict:
        entries = list(self._entries.values())
        applicable = [e for e in entries if e.status not in NOT_APPLICABLE]
        conclusive = [e for e in applicable if e.status in CONCLUSIVE]
        executed = [e for e in applicable if e.status != "not_tested"]
        by_status = self._count_by_status(entries)
        return {"assets": len(self._assets), "vuln_classes": len(ALL_VULN_CLASSES),
                "total_cells": len(entries), "applicable_cells": len(applicable),
                "executed": len(executed), "tested": len(conclusive),
                "findings": by_status.get("finding_detected", 0),
                "skipped": by_status.get("skipped", 0),
                "not_tested": by_status.get("not_tested", 0),
                "coverage_ratio": len(conclusive) / len(applicable) if applicable else 0.0,
                "executed_ratio": len(executed) / len(applicable) if applicable else 0.0,
                "by_status": by_status}

    @staticmethod
    def _count_by_status(entries) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in entries:
            counts[entry.status] = counts.get(entry.status, 0) + 1
        return counts
