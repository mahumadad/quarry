"""Isolated multi-account sessions; live secrets stay in the encrypted vault."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import append_jsonl, atomic_write_json, read_json
    from .vault import Vault
except ImportError:
    from storage import append_jsonl, atomic_write_json, read_json
    from vault import Vault


@dataclass
class Session:
    name: str
    role: str = ""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    base_url: str = ""
    created_at: str = ""
    last_used_at: str = ""
    notes: str = ""
    vault_ref: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.vault_ref:
            self.vault_ref = f"session:{self.name}"


@dataclass
class DiffResult:
    url: str
    session_a: str
    session_b: str
    status_a: int = 0
    status_b: int = 0
    body_a: str = ""
    body_b: str = ""
    data_crossed: bool = False
    tested_at: str = ""

    def __post_init__(self):
        if not self.tested_at:
            self.tested_at = datetime.now(timezone.utc).isoformat()


class SessionManager:
    def __init__(self, audit_dir: str):
        self.audit_dir = audit_dir
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.sessions_file = self.state_dir / "sessions.json"
        self.vault = Vault(audit_dir)
        self._sessions: dict[str, Session] = {}
        self._load()

    def _load(self):
        if not self.sessions_file.exists():
            return
        data = read_json(self.sessions_file)
        changed = False
        for raw in data.get("sessions", []):
            session = Session(**raw)
            if session.cookies or session.headers:
                # Migrate legacy plaintext material immediately.
                self._store_material(session)
                session.cookies, session.headers = {}, {}
                changed = True
            credential = self.vault.get(session.vault_ref)
            if credential:
                material = json.loads(credential.value)
                session.cookies = material.get("cookies", {})
                session.headers = material.get("headers", {})
            self._sessions[session.name] = session
        if changed:
            self._save()

    def _store_material(self, session: Session) -> None:
        self.vault.store(session.vault_ref, "session_material", json.dumps({
            "cookies": session.cookies, "headers": session.headers}), target=session.base_url)

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        records = []
        for session in self._sessions.values():
            raw = asdict(session)
            raw["cookies"], raw["headers"] = {}, {}
            records.append(raw)
        atomic_write_json(self.sessions_file, {"sessions": records,
            "updated_at": datetime.now(timezone.utc).isoformat()})

    def register(self, session: Session) -> Session:
        self._store_material(session)
        self._sessions[session.name] = session
        self._save()
        return session

    def get(self, name: str) -> Session | None:
        return self._sessions.get(name)

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def update_material(self, name: str, cookies: dict | None = None,
                        headers: dict | None = None) -> bool:
        session = self._sessions.get(name)
        if not session:
            return False
        if cookies:
            session.cookies.update(cookies)
        if headers:
            session.headers.update(headers)
        session.last_used_at = datetime.now(timezone.utc).isoformat()
        self._store_material(session)
        self._save()
        return True

    def curl_flags(self, name: str) -> str:
        """Sensitive output: never include this string in logs or model context."""
        session = self._sessions.get(name)
        if not session:
            raise KeyError(f"unknown session: {name}")
        parts = [f'-b "{k}={v}"' for k, v in session.cookies.items()]
        parts += [f'-H "{k}: {v}"' for k, v in session.headers.items()]
        session.last_used_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return " ".join(parts)

    def record_diff(self, diff: DiffResult) -> None:
        append_jsonl(self.state_dir / "session-diffs.jsonl", asdict(diff))

    def has_pair(self) -> bool:
        authed = [s for s in self._sessions.values() if s.cookies or s.headers]
        return len(authed) >= 2
