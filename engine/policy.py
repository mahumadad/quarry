"""Fail-closed authorization policy shared by shell, HTTP and workflow runners."""
from __future__ import annotations

import hashlib
import json
import re
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


# Shell metacharacters that separate or embed commands. Normalizing them to
# spaces defeats adjacency bypasses like 'true;curl', '$(curl ...)' and backticks.
_METACHAR_RE = re.compile(r"\$\(|\)|`|<\(|>\(|[;|&<>]")
# Flags whose argument is inline code to be scanned recursively.
_INLINE_CODE_FLAGS = {"-c", "-lc", "-ic", "-e", "--eval", "--command"}


def _find_engagement_dir(audit_dir: str | Path) -> Path | None:
    """Return the nearest ancestor (inclusive) holding a `.pentest-state/` dir, else None.

    Quarry only polices directories that are actual engagements. Elsewhere the
    guard is a no-op so the plugin can be installed without blocking ordinary
    shell use (curl, pip, python -c) in unrelated projects.
    """
    try:
        start = Path(audit_dir).resolve()
    except (OSError, RuntimeError):
        return None
    for cand in (start, *start.parents):
        if (cand / ".pentest-state").is_dir():
            return cand
    return None


def _extract_executables(command: str, _depth: int = 0) -> set[str]:
    """Collect network-tool and interpreter names from a command.

    Robust against adjacency (`true;curl`), command substitution (`$(curl)`,
    backticks), pipelines without spaces and inline shell/interpreter code
    (`bash -lc '... curl ...'`). Fails closed: a token that cannot be parsed
    is scanned as whitespace-split text rather than silently skipped.
    """
    found: set[str] = set()
    if _depth > 5:
        return found
    normalized = _METACHAR_RE.sub(" ", command)
    for variant in {command, normalized}:
        try:
            tokens = shlex.split(variant)
        except ValueError:
            tokens = variant.split()
        for j, token in enumerate(tokens):
            name = Path(token).name
            if name in NETWORK_TOOLS or name in SCRIPT_INTERPRETERS:
                found.add(name)
            if name in SHELL_WRAPPERS or name in SCRIPT_INTERPRETERS:
                for k in range(j + 1, len(tokens)):
                    if tokens[k] in _INLINE_CODE_FLAGS:
                        if k + 1 < len(tokens):
                            found.update(_extract_executables(tokens[k + 1], _depth + 1))
                    elif not tokens[k].startswith("-"):
                        break
    return found


def command_policy(command: str, audit_dir: str | Path, approved_digest: str = "") -> dict:
    """Validate network-looking commands; local non-network commands remain usable.

    Inspects the full command — not just argv[0] — to catch wrappers like
    'bash -c "nmap ..."', 'env curl ...', 'sudo nmap ...', pipelines and
    command substitution. This is a tripwire, not a sandbox: a determined
    attacker can bypass it. Outside an engagement the guard does not act.
    """
    if _find_engagement_dir(audit_dir) is None:
        return {"allowed": True, "targets": [], "dangerous": False}
    executables = _extract_executables(command)
    network_hits = executables & NETWORK_TOOLS
    interpreter_hits = executables & SCRIPT_INTERPRETERS
    network_channel = "/dev/tcp/" in command or "/dev/udp/" in command
    network = bool(network_hits) or bool(interpreter_hits) or network_channel
    if not network:
        # A purely local command (even a destructive one like `rm -rf`) is not a
        # scope matter; host safety is handled outside this scope tripwire.
        return {"allowed": True, "targets": [], "dangerous": False}
    dangerous = any(marker in command.lower() for marker in DANGEROUS_MARKERS)
    targets = Scope._extract_targets(command)
    return PolicyEngine(audit_dir).authorize(command, targets, dangerous, approved_digest)


def url_policy(url: str, audit_dir: str | Path) -> dict:
    """Validate a URL against the engagement scope before browser navigation or HTTP request.

    Used by browser_loop, browser_verify, and mcp_client to ensure all
    network access — not just CLI commands — respects the scope boundary.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", ""}:
        raise PolicyDenied(f"Unsupported URL scheme: {parsed.scheme}")
    target = parsed.hostname or url
    if not target:
        raise PolicyDenied("URL has no hostname")
    return PolicyEngine(audit_dir).authorize(f"navigate {url}", [url], dangerous=False)


def canonical_url_target(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise PolicyDenied("Only canonical HTTP(S) targets without userinfo/fragments are allowed")
    return url
