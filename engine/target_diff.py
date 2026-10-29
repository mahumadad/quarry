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

    def diff_scope_from_git(self, base_ref: str = "main",
                            head_ref: str = "HEAD") -> dict:
        """Generate a scope narrowed to files/endpoints changed in a PR (Gap 8).

        Runs `git diff --name-only base..head` to find changed files, then
        filters to security-relevant ones (routes, controllers, models, configs).
        Returns a dict suitable for narrowing scan scope.
        """
        import subprocess
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"],
                capture_output=True, text=True, timeout=30,
                cwd=str(self.state_dir.parent),
            )
            changed_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        except (subprocess.SubprocessError, FileNotFoundError):
            return {"error": "git diff failed", "files": [], "scope_narrowed": False}

        security_patterns = {
            "routes": [], "controllers": [], "models": [],
            "auth": [], "config": [], "migrations": [], "other": [],
        }
        security_extensions = {".py", ".js", ".ts", ".rb", ".go", ".java",
                               ".php", ".yaml", ".yml", ".json", ".xml",
                               ".env", ".conf", ".cfg", ".toml"}

        for f in changed_files:
            ext = Path(f).suffix.lower()
            if ext not in security_extensions:
                continue
            fl = f.lower()
            if any(w in fl for w in ("route", "url", "endpoint", "api")):
                security_patterns["routes"].append(f)
            elif any(w in fl for w in ("controller", "handler", "view", "resolver")):
                security_patterns["controllers"].append(f)
            elif any(w in fl for w in ("model", "schema", "entity")):
                security_patterns["models"].append(f)
            elif any(w in fl for w in ("auth", "login", "session", "token", "password", "permission")):
                security_patterns["auth"].append(f)
            elif any(w in fl for w in ("config", "setting", ".env", "secret")):
                security_patterns["config"].append(f)
            elif "migration" in fl:
                security_patterns["migrations"].append(f)
            else:
                security_patterns["other"].append(f)

        total_relevant = sum(len(v) for v in security_patterns.values())
        return {
            "base_ref": base_ref,
            "head_ref": head_ref,
            "total_changed": len(changed_files),
            "security_relevant": total_relevant,
            "by_category": security_patterns,
            "scope_narrowed": total_relevant > 0,
            "recommendation": (
                f"Narrow scan to {total_relevant} security-relevant files "
                f"(out of {len(changed_files)} changed)."
                if total_relevant else "No security-relevant changes detected in this diff."
            ),
        }

    def list_snapshots(self) -> list[TargetSnapshot]:
        return list(self._snapshots)

    def diff_from_git(self, repo_path: str, base_branch: str = "main") -> dict:
        """Limit scan scope to files/endpoints changed in a PR (Gap #8).

        Runs git diff against base_branch and extracts:
        - Changed source files (routes, controllers, models)
        - Affected endpoints (from route annotations)
        - New dependencies
        """
        import subprocess
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{base_branch}...HEAD"],
                capture_output=True, text=True, timeout=30,
                cwd=repo_path)
            if result.returncode != 0:
                return {"error": result.stderr.strip(), "changed_files": []}
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"error": str(e), "changed_files": []}

        changed_files = [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

        route_files = [f for f in changed_files if any(
            kw in f.lower() for kw in [
                "route", "controller", "view", "endpoint", "api",
                "handler", "urls.py", "router", "middleware",
            ])]

        config_files = [f for f in changed_files if any(
            kw in f.lower() for kw in [
                "config", "settings", "env", ".yml", ".yaml",
                ".json", ".toml", "docker", "nginx", "apache",
            ])]

        dep_files = [f for f in changed_files if any(
            f.endswith(ext) for ext in [
                "requirements.txt", "Pipfile", "Pipfile.lock",
                "package.json", "package-lock.json", "yarn.lock",
                "Gemfile", "Gemfile.lock", "go.mod", "go.sum",
                "pom.xml", "build.gradle", "Cargo.toml", "composer.json",
            ])]

        endpoints = []
        for rf in route_files:
            full_path = Path(repo_path) / rf
            if full_path.exists() and full_path.stat().st_size < 500_000:
                try:
                    content = full_path.read_text(errors="replace")
                    endpoints.extend(self._extract_endpoints_from_source(content))
                except OSError:
                    pass

        return {
            "base_branch": base_branch,
            "changed_files": changed_files,
            "total_changed": len(changed_files),
            "route_files": route_files,
            "config_files": config_files,
            "dependency_files": dep_files,
            "affected_endpoints": endpoints,
            "scope_recommendation": self._scope_recommendation(
                route_files, config_files, dep_files, endpoints),
        }

    @staticmethod
    def _extract_endpoints_from_source(content: str) -> list[str]:
        """Heuristic extraction of API endpoints from source code."""
        import re
        patterns = [
            re.compile(r'''@(?:app|router|api)\.(?:get|post|put|delete|patch)\s*\(\s*['"](/[^'"]*?)['"]''', re.I),
            re.compile(r'''path\s*\(\s*['"](/[^'"]*?)['"]'''),
            re.compile(r'''url\s*\(\s*r?['"](/[^'"]*?)['"]'''),
            re.compile(r'''(?:GET|POST|PUT|DELETE|PATCH)\s+['"](/[^'"]*?)['"]'''),
            re.compile(r'''Route\s*\(\s*['"](/[^'"]*?)['"]''', re.I),
        ]
        found = set()
        for pat in patterns:
            for m in pat.finditer(content):
                found.add(m.group(1))
        return sorted(found)

    @staticmethod
    def _scope_recommendation(route_files, config_files, dep_files, endpoints) -> str:
        parts = []
        if endpoints:
            parts.append(f"Test {len(endpoints)} affected endpoint(s)")
        if route_files:
            parts.append(f"Review {len(route_files)} route/controller file(s)")
        if config_files:
            parts.append(f"Check {len(config_files)} config change(s) for security impact")
        if dep_files:
            parts.append(f"Audit {len(dep_files)} dependency file(s) for known CVEs")
        if not parts:
            parts.append("No security-relevant files changed")
        return "; ".join(parts)

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
