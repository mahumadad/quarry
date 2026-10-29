"""Encrypted credential vault (Fernet/AES; legacy plaintext is migrated on load).

Set PENTEST_VAULT_KEY to a Fernet key managed outside the engagement for stronger
key separation. A local 0600 key is created only as a development fallback.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

try:
    from .storage import atomic_write_json, read_json
except ImportError:
    from storage import atomic_write_json, read_json


@dataclass
class Credential:
    name: str
    cred_type: str
    value: str
    target: str = ""
    username: str = ""
    scope: str = ""
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
        self.key_file = self.state_dir / "vault.key"
        self._fernet = Fernet(self._key())
        self._credentials: dict[str, Credential] = {}
        self._load()

    def _key(self) -> bytes:
        configured = os.environ.get("PENTEST_VAULT_KEY", "").strip()
        if configured:
            return configured.encode("ascii")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.key_file.exists():
            return self.key_file.read_bytes().strip()
        key = Fernet.generate_key()
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key + b"\n")
        return key

    def _load(self):
        if not self.vault_file.exists():
            return
        data = read_json(self.vault_file)
        if data.get("encryption") == "fernet":
            try:
                plaintext = self._fernet.decrypt(data["ciphertext"].encode("ascii"))
                records = json.loads(plaintext)
            except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Vault cannot be decrypted; refusing to overwrite it") from exc
        else:  # explicit migration of the old plaintext format
            records = data.get("credentials", [])
        for cd in records:
            credential = Credential(**cd)
            self._credentials[credential.name] = credential
        if data.get("encryption") != "fernet":
            self._save()

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        records = [asdict(c) for c in self._credentials.values()]
        plaintext = json.dumps(records, ensure_ascii=False).encode("utf-8")
        atomic_write_json(self.vault_file, {
            "encryption": "fernet", "version": 1,
            "ciphertext": self._fernet.encrypt(plaintext).decode("ascii"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def store(self, name: str, cred_type: str, value: str, target: str = "",
              username: str = "", scope: str = "", expires_at: str = "",
              notes: str = "") -> Credential:
        credential = Credential(name=name, cred_type=cred_type, value=value,
            target=target, username=username, scope=scope, expires_at=expires_at, notes=notes)
        self._credentials[name] = credential
        self._save()
        return credential

    def get(self, name: str) -> Credential | None:
        return self._credentials.get(name)

    def get_for_target(self, target: str) -> list[Credential]:
        return [c for c in self._credentials.values() if c.target == target]

    def get_by_type(self, cred_type: str) -> list[Credential]:
        return [c for c in self._credentials.values() if c.cred_type == cred_type]

    def remove(self, name: str) -> bool:
        if name not in self._credentials:
            return False
        del self._credentials[name]
        self._save()
        return True

    def list_names(self) -> list[str]:
        return list(self._credentials.keys())

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for credential in self._credentials.values():
            by_type[credential.cred_type] = by_type.get(credential.cred_type, 0) + 1
        return {"total": len(self._credentials), "by_type": by_type,
                "targets": list({c.target for c in self._credentials.values() if c.target}),
                "encryption": "fernet", "external_key": bool(os.environ.get("PENTEST_VAULT_KEY"))}
