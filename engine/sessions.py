"""Multi-account session management for access-control testing.

IDOR / broken-access-control / privilege-escalation testing requires issuing
the SAME request as different identities (user A, user B, admin, anonymous)
and diffing the responses. This module keeps one isolated session per test
identity: cookie jar, auth headers, tokens — never mixed, always attributable.

Credentials come from engine.vault (never hardcoded here). This module only
manages LIVE session material (cookies/tokens) captured after login.

State lives in .pentest-state/sessions.json
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Session:
    """Live authenticated context for one test identity."""
    name: str                       # e.g. "user_a", "user_b", "admin", "anon"
    role: str = ""                  # free-form: "tenant1-user", "org-admin"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)   # Authorization, X-API-Key, CSRF...
    base_url: str = ""
    created_at: str = ""
    last_used_at: str = ""
    notes: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class DiffResult:
    """Outcome of issuing the same request as two identities."""
    url: str
    session_a: str
    session_b: str
    status_a: int = 0
    status_b: int = 0
    body_a: str = ""
    body_b: str = ""
    data_crossed: bool = False      # True when B's data appears in A's response
    tested_at: str = ""

    def __post_init__(self):
        if not self.tested_at:
            self.tested_at = datetime.now(timezone.utc).isoformat()


class SessionManager:
    """Registry of named sessions + helpers for cross-identity diffing."""

    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.sessions_file = self.state_dir / "sessions.json"
        self._sessions: dict[str, Session] = {}
        self._load()

    def _load(self):
        if self.sessions_file.exists():
            data = json.loads(self.sessions_file.read_text())
            for s in data.get("sessions", []):
                sess = Session(**s)
                self._sessions[sess.name] = sess

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_file.write_text(json.dumps({
            "sessions": [asdict(s) for s in self._sessions.values()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def register(self, session: Session) -> Session:
        self._sessions[session.name] = session
        self._save()
        return session

    def get(self, name: str) -> Session | None:
        return self._sessions.get(name)

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def update_material(self, name: str, cookies: dict | None = None,
                        headers: dict | None = None) -> bool:
        """Refresh cookies/headers after re-login (tokens expire mid-engagement)."""
        sess = self._sessions.get(name)
        if not sess:
            return False
        if cookies:
            sess.cookies.update(cookies)
        if headers:
            sess.headers.update(headers)
        sess.last_used_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def curl_flags(self, name: str) -> str:
        """Render a session as curl flags — keeps identity usage explicit and
        reproducible in evidence (the exact auth material used is in the log)."""
        sess = self._sessions.get(name)
        if not sess:
            raise KeyError(f"unknown session: {name}")
        parts = []
        for k, v in sess.cookies.items():
            parts.append(f'-b "{k}={v}"')
        for k, v in sess.headers.items():
            parts.append(f'-H "{k}: {v}"')
        sess.last_used_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return " ".join(parts)

    def record_diff(self, diff: DiffResult) -> None:
        """Append a cross-identity diff to the audit trail (feeds findings)."""
        diffs_file = self.state_dir / "session-diffs.jsonl"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with diffs_file.open("a") as fh:
            fh.write(json.dumps(asdict(diff)) + "\n")

    def has_pair(self) -> bool:
        """Access-control testing needs at least two distinct identities."""
        authed = [s for s in self._sessions.values() if s.cookies or s.headers]
        return len(authed) >= 2
