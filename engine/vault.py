"""Credential vault — secure storage for engagement credentials.

Stores test credentials, API keys, tokens, and session cookies used
during the engagement. Credentials are stored in-memory with optional
persistence to an encrypted file.

Persists to .pentest-state/vault.json (plaintext — operator's machine only).
For shared environments, use environment variables instead.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Credential:
    name: str
    cred_type: str  # password, api_key, token, cookie, header, cert
    value: str
    target: str = ""
    username: str = ""
    scope: str = ""  # what this credential grants access to
    expires_at: str = ""
    notes: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


class Vault:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.vault_file = self.state_dir / "vault.json"
        self._credentials: dict[str, Credential] = {}
        self._load()

    def _load(self):
        if self.vault_file.exists():
            data = json.loads(self.vault_file.read_text())
            for cd in data.get("credentials", []):
                c = Credential(**cd)
                self._credentials[c.name] = c

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file.write_text(json.dumps({
            "credentials": [asdict(c) for c in self._credentials.values()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    def store(self, name: str, cred_type: str, value: str,
              target: str = "", username: str = "", scope: str = "",
              expires_at: str = "", notes: str = "") -> Credential:
        cred = Credential(
            name=name, cred_type=cred_type, value=value,
            target=target, username=username, scope=scope,
            expires_at=expires_at, notes=notes,
        )
        self._credentials[name] = cred
        self._save()
        return cred

    def get(self, name: str) -> Credential | None:
        return self._credentials.get(name)

    def get_for_target(self, target: str) -> list[Credential]:
        return [c for c in self._credentials.values()
                if c.target == target]

    def get_by_type(self, cred_type: str) -> list[Credential]:
        return [c for c in self._credentials.values()
                if c.cred_type == cred_type]

    def remove(self, name: str) -> bool:
        if name in self._credentials:
            del self._credentials[name]
            self._save()
            return True
        return False

    def list_names(self) -> list[str]:
        return list(self._credentials.keys())

    def summary(self) -> dict:
        by_type = {}
        for c in self._credentials.values():
            by_type[c.cred_type] = by_type.get(c.cred_type, 0) + 1
        return {
            "total": len(self._credentials),
            "by_type": by_type,
            "targets": list({c.target for c in self._credentials.values() if c.target}),
        }
