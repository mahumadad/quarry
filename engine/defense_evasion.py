"""Defense evasion support — WAF fingerprinting, bypass, rate-limit backoff
and client fingerprint rotation.

Support infrastructure for the bridge: it does not generate findings on its
own, it keeps scans from dying at the WAF. Everything here is deterministic
and offline where possible:

  - WAFFingerprinter: passive + active probe classification for 8 vendors.
  - WAFBypassEngine: ordered bypass strategies (encoding chains, header
    manipulation, chunked transfer, HTTP/2 smuggling notes) with per-WAF
    ordering.
  - AdaptiveThrottle: exponential backoff with jitter and budget, driven by
    observed 429/503/403 signals instead of fixed sleeps.
  - FingerprintRotator: TLS/JA3/JA4/UA rotation plans. The engine cannot
    change the process TLS stack, so it PLANS rotations (which header/UA/cipher
    set to use next) and logs them — execution stays with the caller's HTTP
    client.

Every network-touching method takes a `policy` (engine.policy.PolicyEngine)
and authorizes the target first, fail-closed. No network calls are performed
by this module directly: probes are declarative and executed by the caller
via the provided `send` callable, keeping the module testable offline.

Module: defense_evasion
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

try:
    from .policy import PolicyEngine, PolicyDenied
    from .graph import EngagementGraph
except ImportError:
    from policy import PolicyEngine, PolicyDenied
    from graph import EngagementGraph


MODULE_SOURCE = "defense_evasion"

# ---------------------------------------------------------------------------
# WAF fingerprinting — 8 vendors, passive signals + active probes
# ---------------------------------------------------------------------------

WAF_VENDORS: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "passive_signals": [
            (r"cloudflare", "server_header"),
            (r"cf-ray", "header"),
            (r"__cfduid", "cookie"),
            (r"cloudflare-nginx", "server_header"),
        ],
        "block_status": [403, 429, 503],
        "block_markers": [r"cloudflare", r"Attention Required! \| Cloudflare",
                          r"cf-error-details"],
        "active_probes": [
            {"path": "/cdn-cgi/trace", "expect": r"fl=", "description":
             "Cloudflare trace endpoint"},
        ],
        "bypass_order": ["case_folding", "encoding_chain", "header_spoof",
                         "chunked_transfer"],
    },
    "akamai": {
        "passive_signals": [
            (r"akamaighost", "server_header"),
            (r"x-akamai", "header"),
            (r"akamai", "server_header"),
        ],
        "block_status": [403, 429],
        "block_markers": [r"Access Denied", r"akamai reference",
                          r"#[0-9a-f]{7}\.", r"Reference #"],
        "active_probes": [],
        "bypass_order": ["encoding_chain", "header_spoof", "chunked_transfer",
                         "case_folding"],
    },
    "aws-waf": {
        "passive_signals": [
            (r"awswaf", "header"),
            (r"x-amzn-requestid", "header"),
            (r"awselb", "server_header"),
        ],
        "block_status": [403],
        "block_markers": [r"Request blocked\.", r"aws-waf",
                          r"Request too large"],
        "active_probes": [],
        "bypass_order": ["encoding_chain", "header_spoof", "case_folding"],
    },
    "imperva": {
        "passive_signals": [
            (r"imperva", "header"),
            (r"incapsula", "header"),
            (r"visid_incap_", "cookie"),
            (r"_incap_", "cookie"),
        ],
        "block_status": [403, 429, 503],
        "block_markers": [r"Request unsuccessful\. Incapsula",
                          r"incident id", r"imperva"],
        "active_probes": [],
        "bypass_order": ["encoding_chain", "header_spoof", "case_folding",
                         "chunked_transfer"],
    },
    "f5-bigip": {
        "passive_signals": [
            (r"bigipserver", "cookie"),
            (r"f5", "server_header"),
            (r"ts=", "cookie"),
            (r"x-waf", "header"),
        ],
        "block_status": [403, 200],  # 200 with block page body
        "block_markers": [r"The requested URL was rejected",
                          r"bigip", r"support id"],
        "active_probes": [],
        "bypass_order": ["header_spoof", "encoding_chain", "case_folding"],
    },
    "modsecurity": {
        "passive_signals": [
            (r"mod_security", "server_header"),
            (r"modsecurity", "server_header"),
            # ModSecurity is frequently identified ONLY by its block page.
            (r"mod_security|modsecurity", "body"),
        ],
        "block_status": [403, 406, 500],
        "block_markers": [r"ModSecurity", r"not acceptable",
                          r"internal server error.*mod"],
        "active_probes": [],
        "bypass_order": ["case_folding", "encoding_chain", "comment_split",
                         "whitespace_padding"],
    },
    "sucuri": {
        "passive_signals": [
            (r"sucuri", "server_header"),
            (r"cloudproxy", "server_header"),
            (r"sucuri-cloudproxy", "server_header"),
        ],
        "block_status": [403],
        "block_markers": [r"Sucuri", r"cloudproxy", r"blocked by sucuri"],
        "active_probes": [],
        "bypass_order": ["encoding_chain", "case_folding", "header_spoof"],
    },
    "fastly": {
        "passive_signals": [
            (r"fastly", "header"),
            (r"via:.*varnish", "header"),
            (r"x-served-by", "header"),
        ],
        "block_status": [403, 429],
        "block_markers": [r"fastly", r"rate limit exceeded"],
        "active_probes": [],
        "bypass_order": ["header_spoof", "encoding_chain", "case_folding"],
    },
    "generic": {
        "passive_signals": [],
        "block_status": [403, 429, 503],
        "block_markers": [r"blocked", r"forbidden", r"rate limit",
                          r"security"],
        "active_probes": [],
        "bypass_order": ["case_folding", "encoding_chain", "header_spoof",
                         "chunked_transfer", "comment_split",
                         "whitespace_padding"],
    },
}


@dataclass
class WAFMatch:
    vendor: str
    confidence: float
    signals: list[dict[str, str]] = field(default_factory=list)
    method: str = "passive"  # passive, active, combined


class WAFFingerprinter:

    def fingerprint(self, response: dict[str, Any]) -> WAFMatch | None:
        """Passive classification from one response dict.

        response: {"status": int, "headers": {str: str},
                   "body": str, "cookies": {str: str}}
        """
        best: tuple[str, float, list[dict[str, str]]] | None = None
        for vendor, spec in WAF_VENDORS.items():
            if vendor == "generic":
                continue
            hits: list[dict[str, str]] = []
            for pattern, where in spec["passive_signals"]:
                target = self._search_space(response, where)
                if target and re.search(pattern, target, re.I):
                    hits.append({"pattern": pattern, "where": where})
            # A block-body marker only double-confirms a vendor that already
            # showed a vendor-specific passive signal. Generic phrases like
            # "rate limit exceeded" must never classify a vendor alone.
            if hits:
                status = response.get("status", 0)
                body = response.get("body", "") or ""
                if status in spec["block_status"]:
                    for pattern in spec["block_markers"]:
                        if re.search(pattern, body, re.I):
                            hits.append({"pattern": pattern,
                                         "where": "block_body"})
                            break
            if hits:
                confidence = min(0.95, 0.4 + 0.15 * len(hits))
                if best is None or confidence > best[1]:
                    best = (vendor, round(confidence, 2), hits)
        if best:
            return WAFMatch(vendor=best[0], confidence=best[1],
                            signals=best[2], method="passive")
        # Generic fallback: blocking status + generic markers, low confidence.
        status = response.get("status", 0)
        body = (response.get("body", "") or "").lower()
        if status in (403, 429, 503):
            if any(m in body for m in ("blocked", "forbidden",
                                       "rate limit", "security")):
                return WAFMatch(
                    vendor="generic", confidence=0.3,
                    signals=[{"pattern": "status+generic-marker",
                              "where": "block_body"}],
                    method="passive")
        return None

    @staticmethod
    def _search_space(response: dict[str, Any], where: str) -> str:
        if where == "server_header":
            return response.get("headers", {}).get("Server", "")
        if where == "header":
            return " ".join("{}: {}".format(k, v) for k, v in
                            response.get("headers", {}).items())
        if where == "cookie":
            return "; ".join(response.get("cookies", {}).keys())
        return response.get("body", "") or ""

    def active_probe(self, vendor: str,
                     send: Callable[[str], dict[str, Any]]) -> WAFMatch | None:
        """Send vendor-specific probes (e.g. /cdn-cgi/trace for Cloudflare).

        `send` is a callable executed by the CALLER (already policy-checked);
        it receives a path and returns a response dict.
        """
        spec = WAF_VENDORS.get(vendor)
        if not spec or not spec["active_probes"]:
            return None
        for probe in spec["active_probes"]:
            resp = send(probe["path"])
            body = resp.get("body", "") or ""
            if re.search(probe["expect"], body):
                return WAFMatch(
                    vendor=vendor, confidence=0.9,
                    signals=[{"pattern": probe["expect"],
                              "where": probe["path"]}],
                    method="active")
        return None


# ---------------------------------------------------------------------------
# Bypass engine — ordered strategies per WAF
# ---------------------------------------------------------------------------

def case_folding(payload: str) -> str:
    return payload.replace("select", "SeLeCt").replace(
        "union", "UnIoN").replace("or 1=1", "Or 1=1")


def encoding_chain(payload: str) -> str:
    """Double URL-encoding of the most telling keywords."""
    once = quote(quote(payload, safe=""), safe="")
    return once


def comment_split(payload: str) -> str:
    return re.sub(r"\b(select|union|insert|update|delete)\b",
                  r"\g<1>/**/", payload, flags=re.I)


def whitespace_padding(payload: str) -> str:
    return payload.replace(" ", "\t").replace("=", " =")


def double_url_encode(payload: str) -> str:
    """Double URL-encode: %253C -> %3C -> <. Bypasses single-decode WAFs."""
    first = quote(payload, safe="")
    return quote(first, safe="")


def unicode_fullwidth(payload: str) -> str:
    """Replace ASCII with fullwidth equivalents (U+FF01..U+FF5E)."""
    return "".join(
        chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
        for c in payload)


def html_entities(payload: str) -> str:
    return "".join("&#{};".format(ord(c)) for c in payload)


def hex_encode(payload: str) -> str:
    return "".join("\\x{:02x}".format(ord(c)) for c in payload)


def null_byte_inject(payload: str) -> str:
    return payload + "%00"


def mixed_encoding_chain(payload: str) -> str:
    """Mix URL + case alternation — multiple encoding layers."""
    mc = "".join(c.upper() if i % 2 else c.lower()
                 for i, c in enumerate(payload))
    return quote(mc, safe="")


def parameter_pollution(payload: str) -> str:
    """HPP: duplicate parameter with clean then dirty value."""
    return "{}&{}".format(quote(payload[:4], safe=""), quote(payload, safe=""))


def path_normalization(path: str) -> list[str]:
    """Generate path variants for directory traversal bypass."""
    variants = [
        path,
        path.replace("/", "//"),
        "/." + path,
        path.rstrip("/") + "/.",
        path.replace("/", "/%2e/"),
    ]
    if "/" in path.strip("/"):
        parts = path.strip("/").split("/")
        if len(parts) >= 2:
            variants.append("/{}/..%2f{}/{}".format(
                parts[0], parts[0], "/".join(parts[1:])))
    return list(dict.fromkeys(variants))


def header_spoof(headers: dict[str, str]) -> dict[str, str]:
    out = dict(headers)
    out["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/126.0.0.0 Safari/537.36")
    out["X-Forwarded-For"] = "127.0.0.1"
    out["Accept"] = ("text/html,application/xhtml+xml,application/xml;"
                     "q=0.9,*/*;q=0.8")
    return out


# Chunked transfer and HTTP/2 smuggling are protocol-level: the engine
# emits a PLAN (headers/notes) because the transport is the caller's.
CHUNKED_TRANSFER_PLAN = {
    "strategy": "chunked_transfer",
    "instructions": [
        "Send the request body with Transfer-Encoding: chunked and split "
        "the payload across chunks so no single chunk contains the full "
        "signature (e.g. one byte per chunk for the keyword).",
        "Only over raw sockets / HTTP client with chunk control; verify the "
        "origin reassembles correctly with a benign marker first.",
    ],
    "headers": {"Transfer-Encoding": "chunked"},
}

HTTP2_SMUGGLING_PLAN = {
    "strategy": "h2_smuggling_note",
    "instructions": [
        "CL.TE / TE.TE smuggling requires an h2 frontend with an h1 backend "
        "and a desync; test ONLY with a benign canary GET (no payloads) to "
        "avoid poisoning shared caches.",
        "If the canary request reaches the origin bypassing the WAF, record "
        "the desync; do not run active payloads through it without operator "
        "approval (dangerous action).",
    ],
    "headers": {"Content-Length": "", "Transfer-Encoding": "chunked"},
}


BYPASS_TECHNIQUES: dict[str, list[dict[str, str]]] = {
    "encoding": [
        {"name": "double_url_encode", "description": "Double URL-encode special characters"},
        {"name": "unicode_fullwidth", "description": "Unicode fullwidth normalization bypass"},
        {"name": "hex_encode", "description": "Hex-encode payload characters"},
        {"name": "html_entities", "description": "HTML entity encoding"},
        {"name": "mixed_encoding_chain", "description": "Mix URL + case encodings"},
        {"name": "encoding_chain", "description": "Double URL-encode the full payload"},
    ],
    "request_structure": [
        {"name": "parameter_pollution", "description": "HPP — duplicate parameters"},
        {"name": "path_normalization", "description": "Path traversal in URL"},
        {"name": "case_folding", "description": "SQL/keyword case alternation"},
        {"name": "null_byte_inject", "description": "Null byte injection"},
        {"name": "comment_split", "description": "SQL comment insertion between keywords"},
        {"name": "whitespace_padding", "description": "Tab/space substitution"},
    ],
    "header_manipulation": [
        {"name": "header_spoof", "description": "IP spoof headers + UA + Content-Type"},
    ],
    "protocol": [
        {"name": "chunked_transfer", "description": "Chunked Transfer-Encoding split"},
        {"name": "h2_smuggling", "description": "HTTP/2 to HTTP/1.1 request smuggling"},
    ],
}

EXTRA_STRATEGIES: dict[str, Callable[[str], str]] = {
    "double_url_encode": double_url_encode,
    "unicode_fullwidth": unicode_fullwidth,
    "html_entities": html_entities,
    "hex_encode": hex_encode,
    "null_byte_inject": null_byte_inject,
    "mixed_encoding_chain": mixed_encoding_chain,
}


class WAFBypassEngine:

    def __init__(self, fingerprint: WAFMatch | None = None):
        self.fingerprint = fingerprint
        self.attempts: list[dict[str, Any]] = []

    def strategy_order(self) -> list[str]:
        if self.fingerprint:
            return list(WAF_VENDORS[self.fingerprint.vendor]["bypass_order"])
        return list(WAF_VENDORS["generic"]["bypass_order"])

    def next_request_plan(self, payload: str,
                          headers: dict[str, str] | None = None,
                          body: str = "") -> dict[str, Any]:
        """Build the next request plan (transformed payload + headers +
        transport notes) following the vendor-ordered strategies.

        Deterministic rotation by attempt count (no RNG): attempt N uses
        strategy N mod len(order).
        """
        order = self.strategy_order()
        idx = len(self.attempts) % len(order)
        strategy = order[idx]
        plan: dict[str, Any] = {
            "attempt": len(self.attempts) + 1,
            "strategy": strategy,
            "vendor": self.fingerprint.vendor if self.fingerprint else "generic",
        }
        new_payload = payload
        new_headers = dict(headers or {})
        if strategy in ("case_folding", "encoding_chain", "comment_split",
                        "whitespace_padding"):
            new_payload = {
                "case_folding": case_folding,
                "encoding_chain": encoding_chain,
                "comment_split": comment_split,
                "whitespace_padding": whitespace_padding,
            }[strategy](payload)
        elif strategy == "header_spoof":
            new_headers = header_spoof(new_headers)
        elif strategy == "chunked_transfer":
            plan["transport"] = CHUNKED_TRANSFER_PLAN
        plan["payload"] = new_payload
        plan["headers"] = new_headers
        plan["body"] = body
        self.attempts.append({
            "attempt": plan["attempt"], "strategy": strategy,
            "payload_sha": hashlib.sha256(
                new_payload.encode()).hexdigest()[:12],
            "at": datetime.now(timezone.utc).isoformat(),
        })
        return plan

    def record_result(self, blocked: bool) -> None:
        """Record the result of the oldest plan without a result yet.

        Plans are generated ahead of execution; execution is FIFO, so the
        result attaches to the first attempt that has no 'blocked' key.
        """
        for attempt in self.attempts:
            if "blocked" not in attempt:
                attempt["blocked"] = blocked
                return
        if self.attempts:
            self.attempts[-1]["blocked"] = blocked

    def generate_bypass_variants(self, payload: str,
                                 max_variants: int = 15) -> list[dict[str, str]]:
        """Generate multiple bypass variants using ALL available encoding
        techniques (not just the vendor-ordered rotation).

        Returns [{"technique": name, "payload": transformed}, ...].
        """
        variants: list[dict[str, str]] = []
        all_transforms: dict[str, Callable] = {
            "case_folding": case_folding,
            "encoding_chain": encoding_chain,
            "comment_split": comment_split,
            "whitespace_padding": whitespace_padding,
            **EXTRA_STRATEGIES,
        }
        for name, fn in all_transforms.items():
            try:
                result = fn(payload)
                if result != payload:
                    variants.append({"technique": name, "payload": result})
            except Exception:
                continue
        return variants[:max_variants]

    def generate_header_bypasses(self) -> list[dict[str, str]]:
        """Generate header-based bypass attempts (IP spoof, method override)."""
        bypasses = []
        for ip in ["127.0.0.1", "10.0.0.1", "::1", "localhost"]:
            bypasses.append({"X-Forwarded-For": ip})
            bypasses.append({"X-Real-IP": ip})
            bypasses.append({"X-Client-IP": ip})
        bypasses.append({"X-HTTP-Method-Override": "PUT"})
        bypasses.append({"X-HTTP-Method-Override": "PATCH"})
        bypasses.append({"Content-Type": "text/plain"})
        bypasses.append({"Content-Type": "application/xml"})
        bypasses.append({"Transfer-Encoding": "chunked"})
        return bypasses

    def exhausted(self) -> bool:
        """True when every strategy has been tried once and blocked."""
        if len(self.attempts) < len(self.strategy_order()):
            return False
        return all(a.get("blocked") for a in self.attempts)


# ---------------------------------------------------------------------------
# Adaptive rate-limit throttle
# ---------------------------------------------------------------------------

class AdaptiveThrottle:
    """Exponential backoff driven by observed responses, with budget.

    The caller reports each response; the throttle advises wait seconds.
    429/503 with Retry-After is honored; 403-WAF-blocks trigger slower
    growth; 2xx resets. No sleeps are performed here (testability).
    """

    BASE_DELAY = 1.0
    MAX_DELAY = 120.0
    MULTIPLIER = 2.0

    def __init__(self, budget_seconds: float = 600.0, seed: int = 0):
        self._delay = self.BASE_DELAY
        self._consecutive_blocks = 0
        self._spent = 0.0
        self._budget = budget_seconds
        # Seeded jitter: deterministic per instance for reproducibility.
        self._rng = random.Random(seed or 20261117)

    def advise(self, status: int, retry_after: float | None = None) -> float:
        """Advise how long to wait before the next request."""
        if status in (429, 503):
            self._consecutive_blocks += 1
            if retry_after is not None and retry_after > 0:
                self._delay = min(float(retry_after), self.MAX_DELAY)
            else:
                self._delay = min(self._delay * self.MULTIPLIER, self.MAX_DELAY)
        elif status == 403:
            # WAF block without explicit rate signal: mild growth.
            self._consecutive_blocks += 1
            self._delay = min(self._delay * 1.3, self.MAX_DELAY)
        elif 200 <= status < 400:
            # Success: decay back toward the base delay.
            self._consecutive_blocks = 0
            self._delay = max(self.BASE_DELAY, self._delay / self.MULTIPLIER)
        # Jitter: +/- 15%, deterministic from the seeded rng.
        jitter = 1.0 + self._rng.uniform(-0.15, 0.15)
        wait = round(self._delay * jitter, 2)
        self._spent += wait
        return wait

    def budget_exhausted(self) -> bool:
        return self._spent >= self._budget

    def stats(self) -> dict[str, float]:
        return {"consecutive_blocks": self._consecutive_blocks,
                "current_delay": round(self._delay, 2),
                "spent_waiting": round(self._spent, 2),
                "budget": self._budget}


# ---------------------------------------------------------------------------
# Client fingerprint rotation (planner)
# ---------------------------------------------------------------------------

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 "
    "Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

# JA3/JA4 rotation is planned, not executed: changing the TLS stack is the
# HTTP client's job. We emit ordered rotation plans with stable pseudo-
# random selection seeded per engagement for reproducibility.
CIPHER_SUITES = [
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384",
    "AES128-GCM-SHA256:AES256-GCM-SHA384",
]
TLS_VERSIONS = ["1.2", "1.3"]


class FingerprintRotator:
    """Plan UA/TLS/JA3/JA4 rotations deterministically.

    ja4_note: JA4 fingerprints sort ciphers and add extension counts; a
    real JA3 change requires an actual TLS re-handshake, so the plan marks
    WHICH properties to change and the caller applies them.
    """

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed or 20261117)
        self._rotations = 0

    def next_profile(self) -> dict[str, str]:
        profile = {
            "user_agent": self._rng.choice(UA_POOL),
            "tls_version": self._rng.choice(TLS_VERSIONS),
            "ciphers": self._rng.choice(CIPHER_SUITES),
        }
        # JA4-style digest of the planned handshake profile (stable hash).
        digest = hashlib.sha256(
            "|".join(profile.values()).encode()).hexdigest()[:12]
        profile["profile_digest"] = digest
        self._rotations += 1
        return profile

    def should_rotate(self, blocked_streak: int) -> bool:
        """Rotate after 3 consecutive blocks (WAF fingerprinting the client)."""
        return blocked_streak >= 3

    def generate_headers(self) -> dict[str, str]:
        """Generate a consistent set of browser-like headers for the
        current rotation profile."""
        profile = self.next_profile()
        ua = profile["user_agent"]
        headers: dict[str, str] = {
            "User-Agent": ua,
            "Accept": ("text/html,application/xhtml+xml,application/xml;"
                       "q=0.9,*/*;q=0.8"),
            "Accept-Language": self._rng.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.9",
                "es-ES,es;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if "Chrome" in ua and "Safari" in ua and "Edg" not in ua:
            headers["Sec-Ch-Ua"] = '"Chromium";v="126", "Not_A Brand";v="24"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = self._rng.choice(
                ['"Windows"', '"macOS"', '"Linux"'])
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"
        return headers

    @property
    def rotations(self) -> int:
        return self._rotations


# ---------------------------------------------------------------------------
# Facade with policy enforcement
# ---------------------------------------------------------------------------

class DefenseEvader:
    """Bundles fingerprinter, bypass engine, throttle and rotator with
    fail-closed policy checks on every target the caller wants to probe."""

    def __init__(self, policy: PolicyEngine | None = None,
                 graph: EngagementGraph | None = None):
        self.policy = policy
        self.graph = graph
        self.fingerprinter = WAFFingerprinter()
        self.bypass: WAFBypassEngine | None = None
        self.throttle = AdaptiveThrottle()
        self.rotator = FingerprintRotator()

    def authorize_target(self, target: str) -> dict[str, Any]:
        if self.policy is None:
            raise PolicyDenied(
                "DefenseEvader requires a PolicyEngine (fail-closed); pass "
                "policy=PolicyEngine(audit_dir)")
        return self.policy.authorize("defense_evasion_probe", [target])

    def identify_waf(self, response: dict[str, Any]) -> WAFMatch | None:
        match = self.fingerprinter.fingerprint(response)
        if match:
            self.bypass = WAFBypassEngine(match)
            self._record_waf(match)
        return match

    def _record_waf(self, match: WAFMatch) -> None:
        if self.graph is None:
            return
        self.graph.add_node(
            type="capability",
            label="WAF: {}".format(match.vendor),
            properties={
                "waf_vendor": match.vendor,
                "confidence": match.confidence,
                "signals": match.signals,
                "method": match.method,
                "source": MODULE_SOURCE,
            },
            source=MODULE_SOURCE,
        )

    def next_plan(self, payload: str, headers: dict[str, str] | None = None,
                  body: str = "") -> dict[str, Any]:
        if self.bypass is None:
            self.bypass = WAFBypassEngine(None)
        return self.bypass.next_request_plan(payload, headers, body)
