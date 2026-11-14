"""Scope tracking and validation.

Tracks in-scope and out-of-scope targets, and validates commands against scope.
"""

import ipaddress
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .storage import atomic_write_json
except ImportError:
    from storage import atomic_write_json

# Last labels that mark a token as a local file, never a network host. A remote
# host carrying one of these in its *path* (evil.com/x.php) is still caught,
# because the path is split off before this check.
FILE_EXTENSIONS = frozenset({
    "yaml", "yml", "json", "jsonl", "txt", "xml", "csv", "sarif", "html", "htm",
    "js", "map", "lock", "py", "env", "sh", "md", "log", "conf", "ini", "cfg",
    "toml", "sql", "bak", "pem", "key", "crt", "rb", "pl", "php", "go", "rs",
    "ts", "tsx", "jsx", "css", "scss", "png", "jpg", "jpeg", "gif", "svg", "pdf",
    "zip", "tar", "gz", "tgz",
})


def _parse_ip(text: str) -> str | None:
    """Return a canonical IP string for dotted, IPv6 or 0x-hex forms, else None.

    Plain decimal integers are deliberately NOT parsed as IPs: treating every
    numeric argument (ports, counts, timeouts) as a host causes false blocks.
    """
    s = text.strip().rstrip(".")
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        try:
            return str(ipaddress.ip_address(int(s, 16)))
        except ValueError:
            return None
    return None


def _strip_port(host: str) -> str:
    """Drop a :port suffix (host-only scope), leaving bare IPv6 untouched."""
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if host.count(":") == 1:
        h, p = host.split(":", 1)
        if p.isdigit():
            return h
    return host


def _ip_interval(text: str) -> tuple[int, int, int] | None:
    """Parse an IP, CIDR or range into (version, lo_int, hi_int), else None."""
    s = text.strip()
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
        return (net.version, int(net.network_address), int(net.broadcast_address))
    if "-" in s and ":" not in s:
        lo_s, hi_s = s.split("-", 1)
        lo = _parse_ip(lo_s)
        if lo is None:
            return None
        lo_ip = ipaddress.ip_address(lo)
        if "." in hi_s:
            hi = _parse_ip(hi_s)
            hi_ip = ipaddress.ip_address(hi) if hi else None
        elif hi_s.isdigit():
            base = str(lo_ip).rsplit(".", 1)[0]
            try:
                hi_ip = ipaddress.ip_address(f"{base}.{hi_s}")
            except ValueError:
                hi_ip = None
        else:
            hi_ip = None
        if hi_ip is None or hi_ip.version != lo_ip.version or int(hi_ip) < int(lo_ip):
            return None
        return (lo_ip.version, int(lo_ip), int(hi_ip))
    ip = _parse_ip(s)
    if ip is None:
        return None
    n = ipaddress.ip_address(ip)
    return (n.version, int(n), int(n))


def _contains(outer: tuple[int, int, int], inner: tuple[int, int, int]) -> bool:
    return outer[0] == inner[0] and outer[1] <= inner[1] and inner[2] <= outer[2]


def _overlaps(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    return a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2]


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
        tgt_int = _ip_interval(target) if "://" not in target else None
        # Out-of-scope wins: any overlap (networks) or host/url match blocks.
        for entry in self.out_of_scope:
            if self._entry_hit(target, tgt_int, entry, allow=False):
                return False
        # In-scope: a network target must be *fully contained*; host/url must match.
        for entry in self.in_scope:
            if self._entry_hit(target, tgt_int, entry, allow=True):
                return True
        return False

    @staticmethod
    def _host_of(target: str) -> str:
        if "://" in target:
            host = urlsplit(target).hostname or ""
        else:
            host = _strip_port(target.split("/", 1)[0])
        return host.lower().rstrip(".")

    def _entry_hit(self, target: str, tgt_int, entry: ScopeEntry, allow: bool) -> bool:
        if entry.type in ("ip", "cidr"):
            e_int = _ip_interval(entry.pattern)
            if e_int is None:
                return False
            if tgt_int is not None:
                return _contains(e_int, tgt_int) if allow else _overlaps(e_int, tgt_int)
            host_ip = _parse_ip(self._host_of(target))
            if host_ip is None:
                return False
            h = _ip_interval(host_ip)
            return _contains(e_int, h) if allow else _overlaps(e_int, h)
        # domain / wildcard / url entries never match a pure IP/CIDR/range target.
        if tgt_int is not None:
            return False
        host = self._host_of(target)
        pattern = entry.pattern.rstrip("/")
        if entry.type == "domain":
            d = pattern.lower().rstrip(".")
            return host == d or host.endswith("." + d)
        if entry.type == "wildcard":
            regex = re.escape(pattern.lower()).replace(r"\*", "[^.]+")
            return bool(re.fullmatch(regex, host))
        if entry.type == "url":
            # A url entry is path-specific; a bare host (no scheme/path) can't be
            # judged against it, so it neither matches nor blocks.
            if "://" not in target:
                return False
            p = urlsplit(pattern if "://" in pattern else f"//{pattern}")
            if host != (p.hostname or "").lower().rstrip("."):
                return False
            import posixpath
            tgt_path = posixpath.normpath(urlsplit(target).path or "/")
            pat_path = (p.path or "/").rstrip("/") or "/"
            return tgt_path == pat_path or tgt_path.startswith(pat_path.rstrip("/") + "/")
        return target.lower().rstrip("/") == pattern.lower()

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
    def _token_to_target(token: str) -> str | None:
        """Map one shell token to a network target (host/IP/CIDR/range) or None.

        Fail-closed on things that look like hosts; local file args and flags
        return None. Userinfo, socat-style PROTO: prefixes, paths and ports are
        stripped so a remote host carrying a web extension (evil.com/x.php) or
        wrapped in tool syntax (TCP:host:port, user@host) is still caught.
        """
        tok = token.strip()
        if not tok or tok[0] in "-@=~" or tok.startswith(("/", "./", "../")):
            return None
        if "://" in tok:  # non-http scheme (e.g. socks5://proxy) — take the host
            host = urlsplit(tok).hostname
            return host.lower() if host else None
        proto = re.match(r"^[A-Za-z]{2,10}:(?!/)(.+)", tok)  # socat TCP:host:port
        if proto and "." in proto.group(1):
            tok = proto.group(1)
        if ("/" in tok or "-" in tok) and _ip_interval(tok) is not None:
            return tok  # CIDR or range; is_in_scope parses it
        hostpart = tok.split("/", 1)[0]
        if "@" in hostpart:  # user@host
            hostpart = hostpart.rsplit("@", 1)[1]
        hostpart = _strip_port(hostpart)
        if not hostpart:
            return None
        ip = _parse_ip(hostpart)
        if ip is not None:
            return ip
        if "." in hostpart:
            last = hostpart.rsplit(".", 1)[1].lower()
            if last in FILE_EXTENSIONS:
                return None
            if re.fullmatch(r"[A-Za-z0-9.-]+", hostpart) and re.search(r"[A-Za-z]", last):
                return hostpart.lower().rstrip(".")
        return None

    # Shells whose `-c` argument is itself a command to recurse into. Script
    # interpreters (python/node/…) are excluded: their network targets appear as
    # URL string literals (caught separately), while their module paths like
    # `urllib.request` must not be mistaken for hosts.
    _RECURSE_SHELLS = frozenset({"bash", "sh", "zsh", "dash"})

    @staticmethod
    def _extract_targets(command: str, _depth: int = 0) -> list[str]:
        """Extract network targets without treating local filenames as domains."""
        import shlex

        targets: list[str] = []
        url_re = re.compile(r"https?://[^\s'\"<>`()|]+", flags=re.IGNORECASE)
        searchable = command
        for url in url_re.findall(command):
            clean = url.rstrip(".,;)]}'\"")
            targets.append(clean.lower())
            searchable = searchable.replace(url, " ")
        # Normalize shell metacharacters so substitutions/adjacency separate.
        normalized = re.sub(r"\$\(|\)|`|<\(|>\(|[;|&<>]", " ", searchable)
        try:
            tokens = shlex.split(normalized)
        except ValueError:
            tokens = normalized.split()
        for i, token in enumerate(tokens):
            name = Path(token).name
            if _depth < 5 and name in Scope._RECURSE_SHELLS:
                for k in range(i + 1, len(tokens)):
                    if tokens[k] in ("-c", "-lc", "-ic") and k + 1 < len(tokens):
                        targets.extend(Scope._extract_targets(tokens[k + 1], _depth + 1))
                    elif not tokens[k].startswith("-"):
                        break
            t = Scope._token_to_target(token)
            if t:
                targets.append(t)
        return list(dict.fromkeys(targets))

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
