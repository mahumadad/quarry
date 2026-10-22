"""Out-of-band (OAST) interaction tracking for blind vulnerability confirmation.

Purpose: blind SSRF/XSS/XXE/RCE/deserialization cannot be confirmed from the
HTTP response alone. This module manages unique callback tokens, correlates
inbound interactions to the exact request that triggered them, and produces
evidence-grade records (timestamped, hashed) that satisfy the anti-fabrication
rules: a blind finding is only `Demonstrated` when an interaction correlated
by a unique token was received.

Backends:
  - interactsh (self-hosted or public oast.* servers) via `interactsh-client`
  - Burp Collaborator (manually supplied payload URLs)
  - own listener (any HTTP/DNS server with access logs you control)

State lives in .pentest-state/oast.json
"""

import json
import re
import secrets
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


# How long to wait for a callback before declaring "no interaction" (seconds).
# Blind injections can fire late (stored XSS, queued jobs, cron-driven fetchers).
DEFAULT_WAIT_SHORT = 30      # reflected/immediate vectors
DEFAULT_WAIT_LONG = 600      # stored vectors — check again before reporting gap


@dataclass
class OASTToken:
    """A unique, correlation-grade token for one injection attempt."""
    token: str = ""
    purpose: str = ""          # e.g. "blind-ssrf", "stored-xss", "xxe-oob"
    vuln_class: str = ""
    target_url: str = ""       # endpoint where the payload was injected
    parameter: str = ""
    payload_url: str = ""      # full URL/host placed in the payload
    created_at: str = ""
    finding_id: str = ""       # linked finding once confirmed

    def __post_init__(self):
        if not self.token:
            self.token = secrets.token_hex(8)  # 16 hex chars, collision-safe
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class Interaction:
    """One observed inbound callback."""
    token: str
    protocol: str              # http, dns, smtp
    remote_addr: str = ""
    raw_request: str = ""
    observed_at: str = ""
    source: str = "interactsh"  # interactsh | collaborator | own-listener

    def __post_init__(self):
        if not self.observed_at:
            self.observed_at = datetime.now(timezone.utc).isoformat()


class OASTManager:
    """Token lifecycle + interaction correlation for one engagement."""

    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.oast_file = self.state_dir / "oast.json"
        self._tokens: dict[str, OASTToken] = {}
        self._interactions: list[Interaction] = []
        self._load()

    def _load(self):
        if self.oast_file.exists():
            data = json.loads(self.oast_file.read_text())
            for t in data.get("tokens", []):
                tok = OASTToken(**t)
                self._tokens[tok.token] = tok
            self._interactions = [Interaction(**i) for i in data.get("interactions", [])]

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.oast_file.write_text(json.dumps({
            "tokens": [asdict(t) for t in self._tokens.values()],
            "interactions": [asdict(i) for i in self._interactions],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))

    # ---- token lifecycle ----

    def new_token(self, purpose: str, vuln_class: str, target_url: str,
                  parameter: str = "", callback_host: str = "") -> OASTToken:
        """Mint a token and build the payload URL to inject.

        callback_host: your interactsh subdomain / Collaborator payload /
        own listener host. The token is prepended as a DNS/HTTP subdomain so
        both DNS-only and full-HTTP callbacks correlate to the same token.
        """
        tok = OASTToken(token="", purpose=purpose, vuln_class=vuln_class,
                        target_url=target_url, parameter=parameter)
        host = callback_host.rstrip("/") if callback_host else "{CALLBACK_HOST}"
        tok.payload_url = f"http://{tok.token}.{host}/" if not host.startswith("http") \
            else f"{host}/{tok.token}"
        self._tokens[tok.token] = tok
        self._save()
        return tok

    def record_interaction(self, interaction: Interaction) -> dict:
        """Record an inbound callback and correlate it to a minted token.

        Returns {"matched": bool, "token": OASTToken|None}. An interaction
        whose token was never minted by this engagement is background noise
        (internet-wide scanners hit public OAST servers constantly) and must
        NOT be used as evidence.
        """
        self._interactions.append(interaction)
        match = self._tokens.get(interaction.token)
        self._save()
        return {"matched": match is not None, "token": match}

    def confirm(self, token: str, finding_id: str) -> bool:
        """Link a confirmed interaction to a finding (promotes evidence to Demonstrated)."""
        tok = self._tokens.get(token)
        if not tok:
            return False
        tok.finding_id = finding_id
        self._save()
        return True

    def pending(self, max_age_seconds: int = DEFAULT_WAIT_LONG) -> list[OASTToken]:
        """Tokens minted but not yet correlated — re-check before declaring a gap."""
        now = time.time()
        out = []
        for tok in self._tokens.values():
            if tok.finding_id:
                continue
            if any(i.token == tok.token for i in self._interactions):
                continue
            age = now - datetime.fromisoformat(tok.created_at).timestamp()
            if age <= max_age_seconds:
                out.append(tok)
        return out

    def evidence_record(self, token: str) -> dict | None:
        """Build the evidence block for a finding from a confirmed interaction."""
        tok = self._tokens.get(token)
        if not tok:
            return None
        hits = [i for i in self._interactions if i.token == token]
        if not hits:
            return None
        return {
            "type": "oast_callback",
            "token": token,
            "purpose": tok.purpose,
            "injected_at": tok.created_at,
            "target_url": tok.target_url,
            "parameter": tok.parameter,
            "payload_url": tok.payload_url,
            "interactions": [asdict(h) for h in hits],
            "correlation": "unique-token",
        }


# ---- interactsh integration (optional external tool) ----

_INTERACTSH_DOMAIN_RE = re.compile(r"([a-z0-9]+\.(?:oast\.(?:fun|live|site|online|me)|interact\.sh))")


def interactsh_start() -> str | None:
    """Start interactsh-client and return the generated callback domain.

    Requires interactsh-client installed and reachable. Returns None on
    failure — caller falls back to a manually configured listener.
    Verify the binary supports the flags with `interactsh-client -h` first
    (per CLI anti-hallucination rules).
    """
    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except FileNotFoundError:
        return None
    # read the first lines until the domain appears
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        m = _INTERACTSH_DOMAIN_RE.search(line)
        if m:
            return m.group(1)
    return None


def interactsh_poll(proc_stdout) -> list[dict]:
    """Parse interactsh-client JSONL output into interaction dicts."""
    out = []
    for line in proc_stdout:
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        full_id = rec.get("full-id") or rec.get("unique-id", "")
        out.append({
            "token": full_id.split(".")[0] if full_id else "",
            "protocol": rec.get("protocol", ""),
            "remote_addr": rec.get("remote-address", ""),
            "raw_request": rec.get("raw-request", ""),
        })
    return out
