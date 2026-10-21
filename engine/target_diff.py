"""Target change detection between scans.

Compares current target state against a previous snapshot to detect
new endpoints, removed services, technology changes, new subdomains,
and certificate changes.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TargetSnapshot:
    snapshot_id: str = ""
    timestamp: str = ""
    assets: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self):
        if not self.snapshot_id:
            self.snapshot_id = uuid.uuid4().hex[:12]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class DiffResult:
    added_assets: list[dict] = field(default_factory=list)
    removed_assets: list[dict] = field(default_factory=list)
    added_endpoints: list[dict] = field(default_factory=list)
    removed_endpoints: list[dict] = field(default_factory=list)
    changed_technologies: dict = field(default_factory=dict)
    added_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)
    certificate_changes: list[dict] = field(default_factory=list)
    summary: str = ""


def _asset_key(a: dict) -> str:
    return f"{a.get('hostname', '')}:{','.join(str(p) for p in sorted(a.get('ports', [])))}"


def _endpoint_key(e: dict) -> str:
    return f"{e.get('method', 'GET')} {e.get('path', '')}"


class TargetDiffEngine:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.snapshot_file = self.state_dir / "target_snapshots.json"
        self._snapshots: list[TargetSnapshot] = []
        self._load()

    def _load(self):
        if self.snapshot_file.exists():
            data = json.loads(self.snapshot_file.read_text())
            self._snapshots = [TargetSnapshot(**s) for s in data.get("snapshots", [])]

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_file.write_text(json.dumps({
            "snapshots": [asdict(s) for s in self._snapshots],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def create_snapshot(
        self,
        assets: list[dict] | None = None,
        endpoints: list[dict] | None = None,
        technologies: list[str] | None = None,
        subdomains: list[str] | None = None,
        certificates: list[dict] | None = None,
        notes: str = "",
    ) -> TargetSnapshot:
        snap = TargetSnapshot(
            assets=assets or [],
            endpoints=endpoints or [],
            technologies=technologies or [],
            subdomains=subdomains or [],
            certificates=certificates or [],
            notes=notes,
        )
        self._snapshots.append(snap)
        self._save()
        return snap

    def latest_snapshot(self) -> TargetSnapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    def _get_snapshot(self, snapshot_id: str) -> TargetSnapshot | None:
        for s in self._snapshots:
            if s.snapshot_id == snapshot_id:
                return s
        return None

    def diff(self, old_id: str = "", new_id: str = "") -> DiffResult:
        if old_id:
            old = self._get_snapshot(old_id)
        elif len(self._snapshots) >= 2:
            old = self._snapshots[-2]
        else:
            return DiffResult(summary="Not enough snapshots to diff")

        if new_id:
            new = self._get_snapshot(new_id)
        else:
            new = self._snapshots[-1] if self._snapshots else None

        if not old or not new:
            return DiffResult(summary="Snapshot not found")

        old_assets = {_asset_key(a): a for a in old.assets}
        new_assets = {_asset_key(a): a for a in new.assets}
        added_assets = [new_assets[k] for k in set(new_assets) - set(old_assets)]
        removed_assets = [old_assets[k] for k in set(old_assets) - set(new_assets)]

        old_endpoints = {_endpoint_key(e): e for e in old.endpoints}
        new_endpoints = {_endpoint_key(e): e for e in new.endpoints}
        added_endpoints = [new_endpoints[k] for k in set(new_endpoints) - set(old_endpoints)]
        removed_endpoints = [old_endpoints[k] for k in set(old_endpoints) - set(new_endpoints)]

        old_techs = set(old.technologies)
        new_techs = set(new.technologies)
        changed_technologies = {
            "added": sorted(new_techs - old_techs),
            "removed": sorted(old_techs - new_techs),
        }

        old_subs = set(old.subdomains)
        new_subs = set(new.subdomains)
        added_subdomains = sorted(new_subs - old_subs)
        removed_subdomains = sorted(old_subs - new_subs)

        old_certs = {c.get("domain", ""): c for c in old.certificates}
        new_certs = {c.get("domain", ""): c for c in new.certificates}
        cert_changes = []
        for domain in set(old_certs) | set(new_certs):
            oc = old_certs.get(domain)
            nc = new_certs.get(domain)
            if oc and not nc:
                cert_changes.append({"domain": domain, "change": "removed"})
            elif nc and not oc:
                cert_changes.append({"domain": domain, "change": "added", "cert": nc})
            elif oc and nc and oc != nc:
                cert_changes.append({"domain": domain, "change": "modified", "old": oc, "new": nc})

        result = DiffResult(
            added_assets=added_assets,
            removed_assets=removed_assets,
            added_endpoints=added_endpoints,
            removed_endpoints=removed_endpoints,
            changed_technologies=changed_technologies,
            added_subdomains=added_subdomains,
            removed_subdomains=removed_subdomains,
            certificate_changes=cert_changes,
        )
        result.summary = self._generate_summary(result)
        return result

    def auto_diff(self) -> DiffResult | None:
        if len(self._snapshots) < 2:
            return None
        return self.diff()

    def list_snapshots(self) -> list[TargetSnapshot]:
        return list(self._snapshots)

    def _generate_summary(self, d: DiffResult) -> str:
        parts = []
        if d.added_assets:
            parts.append(f"+{len(d.added_assets)} assets")
        if d.removed_assets:
            parts.append(f"-{len(d.removed_assets)} assets")
        if d.added_endpoints:
            parts.append(f"+{len(d.added_endpoints)} endpoints")
        if d.removed_endpoints:
            parts.append(f"-{len(d.removed_endpoints)} endpoints")
        if d.changed_technologies.get("added"):
            parts.append(f"+{len(d.changed_technologies['added'])} techs")
        if d.changed_technologies.get("removed"):
            parts.append(f"-{len(d.changed_technologies['removed'])} techs")
        if d.added_subdomains:
            parts.append(f"+{len(d.added_subdomains)} subdomains")
        if d.removed_subdomains:
            parts.append(f"-{len(d.removed_subdomains)} subdomains")
        if d.certificate_changes:
            parts.append(f"{len(d.certificate_changes)} cert changes")
        return ", ".join(parts) if parts else "No changes detected"
