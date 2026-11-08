"""Fail-closed authorization policy shared by shell, HTTP and workflow runners."""
from __future__ import annotations

import hashlib
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .scope import Scope
    from .storage import atomic_write_json, engagement_lock, read_json
    from .timeguard import TimeWindowGuard
except ImportError:
    from scope import Scope
    from storage import atomic_write_json, engagement_lock, read_json
    from timeguard import TimeWindowGuard

NETWORK_TOOLS = {"curl", "wget", "nmap", "nc", "ncat", "nikto", "nuclei", "ffuf",
                 "gobuster", "dirsearch", "sqlmap", "hydra", "msfconsole", "wfuzz",
                 "masscan", "httpx", "whatweb", "wappalyzer", "amass", "subfinder",
                 "ssh", "openssl", "socat", "telnet", "netcat", "rustscan",
                 "feroxbuster", "ghauri", "katana", "gospider", "hakrawler"}
SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "env", "sudo", "xargs", "nice",
                  "nohup", "timeout", "strace", "ltrace", "time", "doas"}
SCRIPT_INTERPRETERS = {"python3", "python", "python2", "node", "ruby", "perl", "php"}
DANGEROUS_MARKERS = {"rm -rf", "rm -r", "rmdir", "drop table", "drop database",
                     "delete from", "truncate", "mkfs", "dd if=", "chmod 777",
                     "iptables -f", "iptables --flush", "sqlmap --os-shell",
                     "sqlmap --os-cmd", "msfconsole", "msfvenom", "hydra", "hashcat",
                     "john", "responder", "impacket-"}


class PolicyDenied(PermissionError):
    pass


def approval_digest(action: str, target: str) -> str:
    return hashlib.sha256(f"{action.strip()}\n{target.strip()}".encode()).hexdigest()


class PolicyEngine:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.state_dir = self.audit_dir / ".pentest-state"
        self.scope_file = self.state_dir / "scope.json"
        self.approvals_file = self.state_dir / "approvals.json"

    def load_scope(self) -> Scope:
        if not self.scope_file.exists():
            raise PolicyDenied(f"Scope not configured: {self.scope_file}")
        try:
            scope = Scope.load(self.scope_file)
        except Exception as exc:
            raise PolicyDenied(f"Scope is unreadable or corrupt: {exc}") from exc
        if not scope.authorization.strip() or not scope.in_scope:
            raise PolicyDenied("Scope requires authorization and at least one in-scope entry")
        return scope

    def authorize(self, action: str, targets: list[str], dangerous: bool = False,
                  approved_digest: str = "") -> dict:
        scope = self.load_scope()
        if not targets:
            raise PolicyDenied("No canonical target supplied; refusing ambiguous network action")
        for target in targets:
            if not scope.is_in_scope(target):
                raise PolicyDenied(f"OUT OF SCOPE: {target}")
        window = TimeWindowGuard(self.audit_dir)
        if not window.status()["configured"]:
            raise PolicyDenied("No testing window configured; refusing network action")
        allowed, reason = window.is_allowed()
        if not allowed:
            raise PolicyDenied(reason)
        if dangerous:
            if not approved_digest:
                raise PolicyDenied("Dangerous action requires a scoped, unexpired operator approval")
            digest = approval_digest(action, "\n".join(sorted(targets)))
            if digest != approved_digest or not self.valid_approval(approved_digest):
                raise PolicyDenied("Approval does not match this exact action/target or has expired")
        return {"allowed": True, "targets": targets, "dangerous": dangerous}

    def grant(self, action: str, targets: list[str], expires_at: str, actor: str = "operator") -> str:
        if actor != "operator":
            raise PolicyDenied("Only the operator can grant an approval")
        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        digest = approval_digest(action, "\n".join(sorted(targets)))
        with engagement_lock(self.audit_dir):
            data = read_json(self.approvals_file, {"approvals": []})
            data.setdefault("approvals", []).append({"digest": digest, "action": action,
                "targets": targets, "expires_at": expires_at, "actor": actor,
                "created_at": datetime.now(timezone.utc).isoformat(), "used_at": None})
            atomic_write_json(self.approvals_file, data)
        return digest

    def valid_approval(self, digest: str) -> bool:
        data = read_json(self.approvals_file, {"approvals": []})
        now = datetime.now(timezone.utc)
        for item in data.get("approvals", []):
            if item.get("digest") != digest or item.get("used_at"):
                continue
            expiry = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry > now:
                return True
        return False

    def consume(self, digest: str) -> None:
        with engagement_lock(self.audit_dir):
            data = read_json(self.approvals_file, {"approvals": []})
            for item in data.get("approvals", []):
                if item.get("digest") == digest and not item.get("used_at"):
                    item["used_at"] = datetime.now(timezone.utc).isoformat()
            atomic_write_json(self.approvals_file, data)


def _extract_executables(command: str) -> set[str]:
    """Extract all executable names from a command, unwrapping shells and wrappers."""
    found: set[str] = set()
    try:
        argv = shlex.split(command)
    except ValueError:
        return found
    if not argv:
        return found

    i = 0
    while i < len(argv):
        name = Path(argv[i]).name
        if name in SHELL_WRAPPERS:
            if name in {"bash", "sh", "zsh", "dash"} and i + 2 < len(argv) and argv[i + 1] == "-c":
                found.update(_extract_executables(argv[i + 2]))
                i += 3
                continue
            if name == "env":
                i += 1
                while i < len(argv) and "=" in argv[i]:
                    i += 1
                continue
            if name in {"sudo", "doas"}:
                i += 1
                while i < len(argv) and argv[i].startswith("-"):
                    if argv[i] in ("-u", "-g", "-C", "-D"):
                        i += 1
                    i += 1
                continue
            i += 1
            continue
        if name in SCRIPT_INTERPRETERS:
            found.add(name)
            if i + 2 < len(argv) and argv[i + 1] == "-c":
                found.update(_extract_executables(argv[i + 2]))
        else:
            found.add(name)
        break

    for token in argv:
        if token == "|" or token == "&&" or token == "||" or token == ";":
            continue
        name = Path(token).name
        if name in NETWORK_TOOLS:
            found.add(name)

    return found


def command_policy(command: str, audit_dir: str | Path, approved_digest: str = "") -> dict:
    """Validate network-looking commands; local non-network commands remain usable.

    Inspects the full command — not just argv[0] — to catch wrappers like
    'bash -c "nmap ..."', 'env curl ...', 'sudo nmap ...', and pipelines.
    This is a tripwire, not a sandbox: a determined attacker can bypass it.
    """
    executables = _extract_executables(command)
    dangerous = any(marker in command.lower() for marker in DANGEROUS_MARKERS)
    network_hits = executables & NETWORK_TOOLS
    interpreter_hits = executables & SCRIPT_INTERPRETERS
    network = bool(network_hits) or dangerous or bool(interpreter_hits)
    if not network:
        return {"allowed": True, "targets": [], "dangerous": False}
    targets = Scope._extract_targets(command)
    return PolicyEngine(audit_dir).authorize(command, targets, dangerous, approved_digest)


def canonical_url_target(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise PolicyDenied("Only canonical HTTP(S) targets without userinfo/fragments are allowed")
    return url
