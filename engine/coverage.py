"""Coverage tracking: vuln_class × asset matrix.

Tracks what was tested and what wasn't. At end of engagement,
reports gaps for operator review.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


ALL_VULN_CLASSES = [
    "sqli", "xss-reflected", "xss-stored", "xss-dom", "ssrf", "idor",
    "csrf", "rce", "ssti", "xxe", "lfi", "rfi", "auth-bypass",
    "race-condition", "cors", "open-redirect", "info-disclosure",
    "deserialization", "graphql", "websocket", "jwt", "oauth",
    "api-abuse", "file-upload", "cache-poisoning", "http-smuggling",
    "subdomain-takeover", "crlf-injection", "clickjacking",
    "host-header-injection", "parameter-pollution", "prototype-pollution",
    "mass-assignment", "broken-access-control", "business-logic",
    "rate-limiting", "password-reset", "2fa-bypass", "session-management",
    "email-injection",
]


@dataclass
class CoverageEntry:
    asset: str
    vuln_class: str
    status: str = "not_tested"  # not_tested, tested_clean, finding_detected, skipped
    skill_used: str = ""
    notes: str = ""
    tested_at: str = ""


class CoverageTracker:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.coverage_file = self.state_dir / "coverage.json"
        self._matrix: dict[str, dict[str, CoverageEntry]] = {}
        self._assets: set[str] = set()
        self._load()

    def _load(self):
        if self.coverage_file.exists():
            data = json.loads(self.coverage_file.read_text())
            for entry_data in data.get("entries", []):
                e = CoverageEntry(**entry_data)
                self._matrix.setdefault(e.asset, {})[e.vuln_class] = e
                self._assets.add(e.asset)

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        entries = []
        for asset_entries in self._matrix.values():
            for entry in asset_entries.values():
                entries.append(asdict(entry))
        self.coverage_file.write_text(json.dumps({
            "entries": entries,
            "summary": self.summary(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def add_asset(self, asset: str):
        self._assets.add(asset)
        if asset not in self._matrix:
            self._matrix[asset] = {}
            for vc in ALL_VULN_CLASSES:
                self._matrix[asset][vc] = CoverageEntry(asset=asset, vuln_class=vc)
            self._save()

    def mark_tested(self, asset: str, vuln_class: str, status: str = "tested_clean",
                    skill_used: str = "", notes: str = ""):
        if asset not in self._matrix:
            self.add_asset(asset)
        entry = self._matrix[asset].get(vuln_class)
        if not entry:
            entry = CoverageEntry(asset=asset, vuln_class=vuln_class)
            self._matrix[asset][vuln_class] = entry
        entry.status = status
        entry.skill_used = skill_used
        entry.notes = notes
        entry.tested_at = datetime.now(timezone.utc).isoformat()
        self._save()

    def mark_skipped(self, asset: str, vuln_class: str, reason: str = ""):
        self.mark_tested(asset, vuln_class, status="skipped", notes=reason)

    def get_gaps(self) -> list[dict]:
        """Return all asset × vuln_class combinations not yet tested."""
        gaps = []
        for asset, classes in self._matrix.items():
            for vc, entry in classes.items():
                if entry.status == "not_tested":
                    gaps.append({"asset": asset, "vuln_class": vc})
        return gaps

    def get_asset_coverage(self, asset: str) -> dict:
        if asset not in self._matrix:
            return {"asset": asset, "total": 0, "tested": 0, "ratio": 0.0}
        entries = self._matrix[asset]
        total = len(entries)
        tested = sum(1 for e in entries.values() if e.status != "not_tested")
        return {
            "asset": asset,
            "total": total,
            "tested": tested,
            "ratio": tested / total if total > 0 else 0.0,
            "by_status": self._count_by_status(entries),
        }

    def summary(self) -> dict:
        total_cells = 0
        tested_cells = 0
        finding_cells = 0
        skipped_cells = 0
        for asset_entries in self._matrix.values():
            for entry in asset_entries.values():
                total_cells += 1
                if entry.status == "tested_clean":
                    tested_cells += 1
                elif entry.status == "finding_detected":
                    tested_cells += 1
                    finding_cells += 1
                elif entry.status == "skipped":
                    skipped_cells += 1
        return {
            "assets": len(self._assets),
            "vuln_classes": len(ALL_VULN_CLASSES),
            "total_cells": total_cells,
            "tested": tested_cells,
            "findings": finding_cells,
            "skipped": skipped_cells,
            "not_tested": total_cells - tested_cells - skipped_cells,
            "coverage_ratio": tested_cells / total_cells if total_cells > 0 else 0.0,
        }

    @staticmethod
    def _count_by_status(entries: dict[str, CoverageEntry]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in entries.values():
            counts[e.status] = counts.get(e.status, 0) + 1
        return counts
