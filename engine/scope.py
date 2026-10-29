"""Scope tracking and validation.

Tracks in-scope and out-of-scope targets, and validates commands against scope.
"""

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    from .storage import atomic_write_json
except ImportError:
    from storage import atomic_write_json


@dataclass
class ScopeEntry:
    pattern: str
    type: str  # domain, ip, cidr, url, wildcard
    notes: str = ""


@dataclass
class Scope:
    in_scope: list[ScopeEntry] = field(default_factory=list)
    out_of_scope: list[ScopeEntry] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    authorization: str = ""

    def add_in_scope(self, pattern: str, type: str, notes: str = ""):
        self.in_scope.append(ScopeEntry(pattern=pattern, type=type, notes=notes))

    def add_out_of_scope(self, pattern: str, type: str, notes: str = ""):
        self.out_of_scope.append(ScopeEntry(pattern=pattern, type=type, notes=notes))

    def is_in_scope(self, target: str) -> bool:
        for entry in self.out_of_scope:
            if self._matches(target, entry):
                return False
        for entry in self.in_scope:
            if self._matches(target, entry):
                return True
        return False

    def _matches(self, target: str, entry: ScopeEntry) -> bool:
        from urllib.parse import urlsplit
        pattern = entry.pattern.rstrip("/")
        parsed = urlsplit(target if "://" in target else f"//{target}")
        host = (parsed.hostname or target).lower().rstrip(".")
        normalized_url = target.lower().rstrip("/")
        if entry.type == "wildcard":
            regex = re.escape(pattern).replace(r"\*", ".*")
            return bool(re.fullmatch(regex, target, re.IGNORECASE) or
                        re.fullmatch(regex, host, re.IGNORECASE))
        if entry.type == "domain":
            domain = pattern.lower().rstrip(".")
            return host == domain or host.endswith("." + domain)
        if entry.type == "cidr":
            return self._ip_in_cidr(host, pattern)
        if entry.type == "ip":
            return host == pattern.lower()
        if entry.type == "url":
            return normalized_url == pattern.lower() or normalized_url.startswith(pattern.lower() + "/")
        return normalized_url == pattern.lower()

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def validate_command(self, command: str) -> tuple[bool, str]:
        """Check if a command targets something in scope.

        Returns (is_valid, reason).
        """
        targets = self._extract_targets(command)
        if not targets:
            return True, "no targets detected in command"
        for t in targets:
            if not self.is_in_scope(t):
                return False, f"target {t!r} is not in scope"
        return True, "all targets in scope"

    @staticmethod
    def _extract_targets(command: str) -> list[str]:
        """Extract network targets without treating local filenames as domains."""
        import shlex

        targets = re.findall(r"https?://[^\s'\"<>]+", command, flags=re.IGNORECASE)
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        file_suffixes = {".yaml", ".yml", ".json", ".jsonl", ".txt", ".xml",
                         ".csv", ".sarif", ".html", ".js", ".map", ".lock"}
        searchable = command
        for token in tokens:
            if token.startswith(("http://", "https://")):
                continue
            path = Path(token)
            if path.suffix.lower() in file_suffixes or ("/" in token and path.suffix):
                searchable = searchable.replace(token, " ")
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        targets.extend(ip_re.findall(searchable))
        domain_re = re.compile(
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
            r"\.[a-zA-Z]{2,})\b"
        )
        for m in domain_re.finditer(searchable):
            d = m.group(1)
            if d not in targets and not d.startswith("0.") and "." in d:
                targets.append(d)
        return targets

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, {
            "in_scope": [asdict(e) for e in self.in_scope],
            "out_of_scope": [asdict(e) for e in self.out_of_scope],
            "rules": self.rules,
            "authorization": self.authorization,
        })

    @classmethod
    def load(cls, path: Path) -> "Scope":
        data = json.loads(path.read_text())
        scope = cls(authorization=data.get("authorization", ""), rules=data.get("rules", []))
        for e in data.get("in_scope", []):
            scope.add_in_scope(**e)
        for e in data.get("out_of_scope", []):
            scope.add_out_of_scope(**e)
        return scope
