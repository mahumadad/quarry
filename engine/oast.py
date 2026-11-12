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


# ---- CLI: session lifecycle for the hunting loop ----
#
#   python3 -m engine.oast start --audit-dir .     # launch client, print callback domain
#   python3 -m engine.oast token --audit-dir . --purpose blind-ssrf \
#       --vuln-class ssrf --target-url http://t/profile/image/url --parameter imageUrl
#   python3 -m engine.oast poll  --audit-dir .     # correlate new callbacks
#   python3 -m engine.oast evidence --audit-dir . --token <t>
#   python3 -m engine.oast stop  --audit-dir .
#
# `start` leaves an interactsh-client process running; `stop` MUST be called
# when the engagement (or benchmark run) ends — never leave listeners behind.

import argparse
import os
import shutil
import signal
import sys

_SESSION_FILE = "oast-session.json"


def _find_binary() -> str | None:
    return shutil.which("interactsh-client") or (
        str(Path.home() / ".local/bin/interactsh-client")
        if (Path.home() / ".local/bin/interactsh-client").exists() else None)


def _session_path(audit_dir: str) -> Path:
    return Path(audit_dir) / ".pentest-state" / _SESSION_FILE


def _load_session(audit_dir: str) -> dict:
    p = _session_path(audit_dir)
    return json.loads(p.read_text()) if p.exists() else {}


def _save_session(audit_dir: str, session: dict):
    p = _session_path(audit_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(session, indent=2))


def cli_start(audit_dir: str) -> dict:
    """Launch interactsh-client detached; capture domain + pid in a session file."""
    binary = _find_binary()
    if not binary:
        return {"ok": False, "error": "interactsh-client not found — install: "
                "https://github.com/projectdiscovery/interactsh/releases "
                "(expected in PATH or ~/.local/bin)"}
    existing = _load_session(audit_dir)
    if existing.get("pid"):
        try:
            os.kill(existing["pid"], 0)
            return {"ok": True, "domain": existing.get("domain"),
                    "pid": existing["pid"], "note": "already running"}
        except OSError:
            pass  # stale pid — relaunch
    log = Path(audit_dir) / ".pentest-state" / "oast-client.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    logf = open(log, "a")
    proc = subprocess.Popen([binary, "-json"], stdout=logf, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    domain = None
    deadline = time.time() + 20
    while time.time() < deadline and not domain:
        time.sleep(1)
        try:
            m = _INTERACTSH_DOMAIN_RE.search(log.read_text())
            if m:
                domain = m.group(1)
        except OSError:
            pass
    if not domain:
        proc.terminate()
        return {"ok": False, "error": "interactsh-client started but no callback "
                "domain appeared in 20s — check network / public oast.* reachability"}
    session = {"pid": proc.pid, "domain": domain, "log": str(log),
               "read_offset": 0,
               "started_at": datetime.now(timezone.utc).isoformat()}
    _save_session(audit_dir, session)
    return {"ok": True, "domain": domain, "pid": proc.pid}


def cli_token(audit_dir: str, purpose: str, vuln_class: str, target_url: str,
              parameter: str = "") -> dict:
    """Mint a correlation token bound to the running session's domain."""
    session = _load_session(audit_dir)
    domain = session.get("domain")
    if not domain:
        return {"ok": False, "error": "no active OAST session — run start first"}
    mgr = OASTManager(audit_dir)
    tok = mgr.new_token(purpose, vuln_class, target_url,
                        parameter=parameter, callback_host=domain)
    return {"ok": True, "token": tok.token, "payload_url": tok.payload_url}


def cli_poll(audit_dir: str) -> dict:
    """Read new client output, correlate against minted tokens, report matches."""
    session = _load_session(audit_dir)
    log = session.get("log")
    if not log or not Path(log).exists():
        return {"ok": False, "error": "no active OAST session — run start first"}
    offset = session.get("read_offset", 0)
    with open(log) as f:
        f.seek(offset)
        new_lines = f.readlines()
        session["read_offset"] = f.tell()
    _save_session(audit_dir, session)
    mgr = OASTManager(audit_dir)
    matched, noise = [], 0
    for rec in interactsh_poll(new_lines):
        if not rec["token"]:
            continue  # startup banner lines
        result = mgr.record_interaction(Interaction(**rec))
        if result["matched"]:
            matched.append({"token": rec["token"], "protocol": rec["protocol"],
                            "remote_addr": rec["remote_addr"],
                            "purpose": result["token"].purpose})
        else:
            noise += 1  # internet background — never evidence
    return {"ok": True, "matched": matched, "background_noise": noise,
            "pending_tokens": [t.token for t in mgr.pending()]}


def cli_evidence(audit_dir: str, token: str) -> dict:
    mgr = OASTManager(audit_dir)
    rec = mgr.evidence_record(token)
    return {"ok": rec is not None, "evidence": rec}


def cli_stop(audit_dir: str) -> dict:
    session = _load_session(audit_dir)
    pid = session.get("pid")
    if not pid:
        return {"ok": True, "note": "no active session"}
    try:
        os.killpg(pid, signal.SIGTERM)
        note = f"stopped pid {pid}"
    except OSError:
        note = "process already gone"
    _save_session(audit_dir, {})
    return {"ok": True, "note": note}


def main() -> int:
    ap = argparse.ArgumentParser(prog="engine.oast")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("start", "poll", "stop"):
        p = sub.add_parser(name)
        p.add_argument("--audit-dir", default=".")
    p = sub.add_parser("token")
    p.add_argument("--audit-dir", default=".")
    p.add_argument("--purpose", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--target-url", required=True)
    p.add_argument("--parameter", default="")
    p = sub.add_parser("evidence")
    p.add_argument("--audit-dir", default=".")
    p.add_argument("--token", required=True)
    args = ap.parse_args()

    if args.cmd == "start":
        r = cli_start(args.audit_dir)
    elif args.cmd == "token":
        r = cli_token(args.audit_dir, args.purpose, args.vuln_class,
                      args.target_url, args.parameter)
    elif args.cmd == "poll":
        r = cli_poll(args.audit_dir)
    elif args.cmd == "evidence":
        r = cli_evidence(args.audit_dir, args.token)
    else:
        r = cli_stop(args.audit_dir)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
