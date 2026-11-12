"""Local wordlist inventory and reproducible selection.

No lists are downloaded and no third-party installer is executed. Every scan
records path, size, mtime and SHA-256; a task can therefore reproduce exactly
which list it used instead of reporting a vague filename.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from storage import atomic_write_json, engagement_lock, read_json

SUFFIXES = {".txt", ".lst", ".wordlist", ".words"}
PURPOSE_TAGS = {
    "web": {"web", "directory", "directories", "content", "common", "raft"},
    "api": {"api", "route", "routes", "rest", "graphql"},
    "dns": {"dns", "subdomain", "subdomains", "vhost"},
    "parameters": {"parameter", "parameters", "param", "burp"},
    "passwords": {"password", "passwords", "credential", "rockyou"},
    "jwt": {"jwt", "token", "secret"},
}
TECHNOLOGIES = {"php", "asp", "aspx", "dotnet", "java", "node", "wordpress",
                "drupal", "joomla", "mongo", "mongodb", "jwt"}
PURPOSE_ALIASES = {"directories": "web", "content-discovery": "web",
                   "subdomains": "dns", "params": "parameters", "password": "passwords"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class WordlistIndex:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.state_file = self.audit_dir / ".pentest-state" / "wordlists.json"
        self.records: list[dict] = []

    def scan(self, roots: list[str | Path]) -> list[dict]:
        records: list[dict] = []
        seen: set[str] = set()
        for raw_root in roots:
            root = Path(raw_root).expanduser().resolve()
            if not root.exists():
                continue
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in paths:
                if (not path.is_file() or path.is_symlink() or path.suffix.lower() not in SUFFIXES
                        or str(path) in seen):
                    continue
                seen.add(str(path))
                stat = path.stat()
                tokens = {part.lower() for part in path.parts}
                tokens.update(part.lower() for part in path.stem.replace("_", "-").split("-"))
                purposes = sorted(name for name, tags in PURPOSE_TAGS.items() if tokens & tags)
                records.append({
                    "path": str(path),
                    "name": path.name,
                    "bytes": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "sha256": _sha256(path),
                    "purposes": purposes,
                    "technologies": sorted(tokens & TECHNOLOGIES),
                })
        self.records = sorted(records, key=lambda item: item["path"])
        previous = read_json(self.state_file, {})
        with engagement_lock(self.audit_dir):
            atomic_write_json(self.state_file, {
                "schema_version": 1,
                "records": self.records,
                "selections": previous.get("selections", []),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        return list(self.records)

    def load(self) -> list[dict]:
        data = read_json(self.state_file, {"records": []})
        self.records = data.get("records", [])
        return list(self.records)

    def select(self, purpose: str, technology: str = "", max_bytes: int | None = None,
               run_id: str = "manual", task_id: str = "recon") -> dict:
        if not self.records:
            self.load()
        canonical_purpose = PURPOSE_ALIASES.get(purpose.lower(), purpose.lower())
        if canonical_purpose not in PURPOSE_TAGS:
            raise ValueError(f"Unknown wordlist purpose: {purpose}")
        technology = technology.lower()
        candidates = []
        for record in self.records:
            if canonical_purpose not in record.get("purposes", []):
                continue
            if max_bytes is not None and record["bytes"] > max_bytes:
                continue
            technologies = record.get("technologies", [])
            if technology and technologies and technology not in technologies:
                continue
            score = 10 if technology and technology in technologies else 0
            candidates.append((score, record))
        if not candidates:
            raise LookupError(
                f"No indexed wordlist for purpose={canonical_purpose}, technology={technology or 'any'}; "
                "record tool_unavailable/deferred coverage instead of claiming a clean result")
        # Technology match first, then stable path order. Never select by filesystem order.
        selected = sorted(candidates, key=lambda item: (-item[0], item[1]["path"]))[0][1]
        selection = {
            "run_id": run_id,
            "task_id": task_id,
            "criteria": {"purpose": canonical_purpose, "technology": technology,
                         "max_bytes": max_bytes},
            "selected": selected,
            "selected_at": datetime.now(timezone.utc).isoformat(),
        }
        with engagement_lock(self.audit_dir):
            data = read_json(self.state_file, {"records": self.records, "selections": []})
            data.setdefault("selections", []).append(selection)
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            atomic_write_json(self.state_file, data)
        return selection
