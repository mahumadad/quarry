"""Defense Evasion Module — WAF bypass, rate limit evasion, fingerprint rotation.

Provides tactical infrastructure so that scans and exploitation steps
are not blocked by defensive controls before they can demonstrate impact.

Components:
  - WAFProfile: fingerprint and configuration of a detected WAF
  - BypassEngine: encoding chains, header manipulation, protocol tricks
  - RateLimitEvader: adaptive backoff with jitter
  - FingerprintRotator: TLS/JA3, User-Agent, header order rotation
"""

from __future__ import annotations

import hashlib
import json
import random
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    from .graph import EngagementGraph
except ImportError:
    from graph import EngagementGraph


WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies": ["__cfruid", "__cf_bm", "cf_clearance"],
        "server": ["cloudflare"],
        "status_codes": [403, 503],
        "body_patterns": ["attention required", "cloudflare ray id",
                          "enable javascript and cookies"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amzn-trace-id"],
        "cookies": ["awsalb", "awsalbcors"],
        "server": [],
        "status_codes": [403],
        "body_patterns": ["request blocked", "automated access"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "cookies": ["ak_bmsc", "bm_sv", "bm_sz"],
        "server": ["akamaighost", "akamai"],
        "status_codes": [403],
        "body_patterns": ["access denied", "reference #"],
    },
    "imperva_incapsula": {
        "headers": ["x-cdn", "x-iinfo"],
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "server": [],
        "status_codes": [403],
        "body_patterns": ["incapsula incident", "powered by incapsula"],
    },
    "modsecurity": {
        "headers": ["x-mod-security"],
        "cookies": [],
        "server": ["modsecurity"],
        "status_codes": [403, 406],
        "body_patterns": ["mod_security", "not acceptable",
                          "rules triggered"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": ["sucuri_cloudproxy_uuid"],
        "server": ["sucuri"],
        "status_codes": [403],
        "body_patterns": ["sucuri website firewall", "access denied - sucuri"],
    },
    "f5_big_ip": {
        "headers": [],
        "cookies": ["bigipserver", "ts"],
        "server": ["bigip", "big-ip"],
        "status_codes": [403],
        "body_patterns": ["the requested url was rejected"],
    },
    "fastly": {
        "headers": ["x-served-by", "x-cache", "x-fastly-request-id"],
        "cookies": [],
        "server": ["fastly"],
        "status_codes": [403, 503],
        "body_patterns": ["fastly error", "varnish cache server"],
    },
}

BYPASS_TECHNIQUES: dict[str, list[dict[str, str]]] = {
    "encoding": [
        {"name": "double_url_encode", "description": "Double URL-encode special characters",
         "example": "%253Cscript%253E → <script>"},
        {"name": "unicode_normalize", "description": "Unicode normalization bypass (NFKC/NFKD)",
         "example": "\\uff1cscript\\uff1e → <script>"},
        {"name": "hex_encode", "description": "Hex-encode payload characters",
         "example": "\\x3cscript\\x3e → <script>"},
        {"name": "html_entity", "description": "HTML entity encoding",
         "example": "&#60;script&#62; → <script>"},
        {"name": "mixed_encoding", "description": "Mix URL + HTML + Unicode encodings",
         "example": "%3C&#115;cript%3E"},
        {"name": "overlong_utf8", "description": "Overlong UTF-8 encoding",
         "example": "\\xc0\\xbc → < (non-canonical)"},
    ],
    "header_manipulation": [
        {"name": "method_override", "description": "X-HTTP-Method-Override to change verb",
         "example": "POST with X-HTTP-Method-Override: PUT"},
        {"name": "ip_spoof_headers", "description": "X-Forwarded-For, X-Real-IP, X-Client-IP",
         "example": "X-Forwarded-For: 127.0.0.1"},
        {"name": "content_type_mismatch", "description": "Send payload in unexpected Content-Type",
         "example": "Content-Type: text/plain with JSON body"},
        {"name": "transfer_encoding", "description": "Chunked Transfer-Encoding tricks",
         "example": "Transfer-Encoding: chunked with split payload"},
        {"name": "host_header_variation", "description": "Host header case/port variations",
         "example": "Host: TARGET.com:443 vs target.com"},
    ],
    "request_structure": [
        {"name": "parameter_pollution", "description": "HPP — duplicate parameters",
         "example": "?id=1&id=2 (server picks first or last)"},
        {"name": "path_normalization", "description": "Path traversal in URL",
         "example": "/./admin/../admin/users"},
        {"name": "case_variation", "description": "URL path case sensitivity abuse",
         "example": "/ADMIN vs /admin vs /Admin"},
        {"name": "null_byte", "description": "Null byte injection in parameters",
         "example": "file.php%00.jpg"},
        {"name": "json_key_collision", "description": "Duplicate JSON keys",
         "example": '{"cmd":"safe","cmd":"malicious"}'},
    ],
    "protocol": [
        {"name": "http2_smuggling", "description": "HTTP/2 to HTTP/1.1 request smuggling",
         "example": "CL:TE or TE:CL via H2 downgrade"},
        {"name": "websocket_upgrade", "description": "Upgrade to WebSocket to bypass WAF",
         "example": "Connection: Upgrade + Upgrade: websocket"},
        {"name": "http_version_switch", "description": "Use HTTP/0.9 or HTTP/1.0",
         "example": "GET /path HTTP/0.9"},
    ],
    "timing": [
        {"name": "slow_request", "description": "Slow drip payload to evade timeout-based inspection",
         "example": "1 byte per second through chunked encoding"},
        {"name": "burst_then_pause", "description": "Send burst of legitimate requests, then payload",
         "example": "50 normal requests → 1 malicious → pause"},
    ],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]


@dataclass
class WAFProfile:
    vendor: str = "unknown"
    confidence: float = 0.0
    detected_headers: list[str] = field(default_factory=list)
    detected_cookies: list[str] = field(default_factory=list)
    detected_server: str = ""
    block_status_codes: list[int] = field(default_factory=list)
    block_body_patterns: list[str] = field(default_factory=list)
    bypass_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def suggested_bypasses(self) -> list[str]:
        """Return bypass technique categories most likely to work."""
        effective = {b["technique"] for b in self.bypass_history
                     if b.get("success")}
        blocked = {b["technique"] for b in self.bypass_history
                   if not b.get("success")}
        all_techniques = []
        for cat, techs in BYPASS_TECHNIQUES.items():
            for t in techs:
                if t["name"] not in blocked:
                    all_techniques.append(t["name"])
        return [t for t in all_techniques if t not in effective]


@dataclass
class RateLimitProfile:
    requests_per_window: int = 0
    window_seconds: float = 0.0
    detected_headers: list[str] = field(default_factory=list)
    retry_after: float | None = None
    limit_by: str = "unknown"


class WAFFingerprinter:
    """Identify WAF vendor from HTTP response characteristics."""

    def fingerprint(self, headers: dict[str, str],
                    cookies: list[str],
                    status_code: int,
                    body: str = "") -> WAFProfile:
        scores: dict[str, float] = {}
        details: dict[str, dict] = {}

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_lower = [c.lower() for c in cookies]
        body_lower = body.lower()
        server = headers_lower.get("server", "")

        for vendor, sig in WAF_SIGNATURES.items():
            score = 0.0
            matched_headers = []
            matched_cookies = []
            matched_patterns = []

            for h in sig["headers"]:
                if h in headers_lower:
                    score += 2.0
                    matched_headers.append(h)

            for c in sig["cookies"]:
                for actual in cookies_lower:
                    if c in actual:
                        score += 1.5
                        matched_cookies.append(actual)
                        break

            for s in sig["server"]:
                if s in server:
                    score += 3.0

            if status_code in sig["status_codes"]:
                score += 1.0

            for p in sig["body_patterns"]:
                if p in body_lower:
                    score += 2.0
                    matched_patterns.append(p)

            if score > 0:
                scores[vendor] = score
                details[vendor] = {
                    "headers": matched_headers,
                    "cookies": matched_cookies,
                    "patterns": matched_patterns,
                }

        if not scores:
            return WAFProfile(vendor="none_detected", confidence=0.5)

        best = max(scores, key=lambda k: scores[k])
        max_score = scores[best]
        confidence = min(0.95, max_score / 10.0)

        return WAFProfile(
            vendor=best,
            confidence=round(confidence, 2),
            detected_headers=details[best].get("headers", []),
            detected_cookies=details[best].get("cookies", []),
            detected_server=server,
            block_status_codes=[status_code] if status_code in (403, 406, 429, 503) else [],
            block_body_patterns=details[best].get("patterns", []),
        )


class BypassEngine:
    """Generate WAF bypass payloads using encoding chains."""

    def __init__(self, waf_profile: WAFProfile | None = None,
                 seed: int | None = None):
        self.waf_profile = waf_profile or WAFProfile()
        self._rng = random.Random(seed)

    def double_url_encode(self, payload: str) -> str:
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")

    def unicode_fullwidth(self, payload: str) -> str:
        result = []
        for c in payload:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + 0xFEE0))
            else:
                result.append(c)
        return "".join(result)

    def html_entities(self, payload: str) -> str:
        return "".join("&#{};".format(ord(c)) for c in payload)

    def hex_encode(self, payload: str) -> str:
        return "".join("\\x{:02x}".format(ord(c)) for c in payload)

    def mixed_case(self, payload: str) -> str:
        return "".join(
            c.upper() if self._rng.random() > 0.5 else c.lower()
            for c in payload)

    def comment_insertion(self, payload: str, comment: str = "/**/") -> str:
        """Insert comments between characters for SQL/JS bypass."""
        if len(payload) < 4:
            return payload
        mid = len(payload) // 2
        return payload[:mid] + comment + payload[mid:]

    def null_byte_inject(self, payload: str) -> str:
        return payload + "%00"

    def path_normalization(self, path: str) -> list[str]:
        """Generate path variations for directory traversal."""
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

    def generate_bypass_variants(self, payload: str,
                                 max_variants: int = 10) -> list[dict[str, str]]:
        """Generate multiple bypass variants of a payload."""
        variants = []
        encoders = [
            ("double_url_encode", self.double_url_encode),
            ("unicode_fullwidth", self.unicode_fullwidth),
            ("html_entities", self.html_entities),
            ("hex_encode", self.hex_encode),
            ("mixed_case", self.mixed_case),
            ("comment_insertion", self.comment_insertion),
            ("null_byte", self.null_byte_inject),
        ]
        for name, fn in encoders:
            try:
                result = fn(payload)
                if result != payload:
                    variants.append({"technique": name, "payload": result})
            except Exception:
                continue

        chained = self._chain_encodings(payload)
        for name, result in chained:
            variants.append({"technique": name, "payload": result})

        self._rng.shuffle(variants)
        return variants[:max_variants]

    def _chain_encodings(self, payload: str) -> list[tuple[str, str]]:
        chains = []
        mc = self.mixed_case(payload)
        dbl = self.double_url_encode(mc)
        chains.append(("mixed_case+double_url", dbl))

        ent = self.html_entities(payload)
        url_ent = urllib.parse.quote(ent, safe="")
        chains.append(("html_entity+url_encode", url_ent))

        fw = self.unicode_fullwidth(payload)
        url_fw = urllib.parse.quote(fw, safe="")
        chains.append(("fullwidth+url_encode", url_fw))

        return chains

    def generate_header_bypasses(self) -> list[dict[str, str]]:
        """Generate header-based bypass attempts."""
        bypasses = []
        for ip in ["127.0.0.1", "10.0.0.1", "::1", "localhost"]:
            bypasses.append({"X-Forwarded-For": ip})
            bypasses.append({"X-Real-IP": ip})
            bypasses.append({"X-Client-IP": ip})
            bypasses.append({"X-Originating-IP": ip})

        bypasses.append({"X-HTTP-Method-Override": "PUT"})
        bypasses.append({"X-HTTP-Method-Override": "PATCH"})
        bypasses.append({"Content-Type": "text/plain"})
        bypasses.append({"Content-Type": "application/xml"})
        bypasses.append({"Transfer-Encoding": "chunked"})

        return bypasses


class RateLimitEvader:
    """Adaptive rate limit detection and evasion."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._history: list[dict[str, Any]] = []
        self._profile: RateLimitProfile | None = None
        self._consecutive_429 = 0
        self._base_delay = 1.0
        self._current_delay = 1.0

    def record_response(self, status_code: int,
                        headers: dict[str, str]) -> dict[str, Any]:
        """Record a response and update rate limit profile."""
        entry = {
            "status": status_code,
            "timestamp": time.time(),
            "headers": {k.lower(): v for k, v in headers.items()},
        }
        self._history.append(entry)

        if status_code == 429:
            self._consecutive_429 += 1
            retry_after = headers.get("retry-after", headers.get("Retry-After"))
            if retry_after:
                try:
                    entry["retry_after"] = float(retry_after)
                except ValueError:
                    pass

            self._update_profile(entry)
            self._backoff()
            return {"action": "wait", "delay": self._current_delay,
                    "consecutive_429": self._consecutive_429}
        else:
            self._consecutive_429 = 0
            self._decay_delay()
            return {"action": "continue", "delay": self._current_delay}

    def _update_profile(self, entry: dict) -> None:
        if self._profile is None:
            self._profile = RateLimitProfile()

        headers = entry.get("headers", {})
        for h in ["x-ratelimit-limit", "x-ratelimit-remaining",
                   "x-ratelimit-reset", "ratelimit-limit",
                   "ratelimit-remaining", "ratelimit-reset"]:
            if h in headers:
                if h not in self._profile.detected_headers:
                    self._profile.detected_headers.append(h)

        limit_header = headers.get("x-ratelimit-limit",
                                    headers.get("ratelimit-limit"))
        if limit_header:
            try:
                self._profile.requests_per_window = int(limit_header)
            except ValueError:
                pass

        if "retry_after" in entry:
            self._profile.retry_after = entry["retry_after"]

    def _backoff(self) -> None:
        """Exponential backoff with jitter."""
        exp = min(self._consecutive_429, 6)
        base = self._base_delay * (2 ** exp)
        jitter = self._rng.uniform(0, base * 0.3)
        self._current_delay = min(base + jitter, 120.0)

    def _decay_delay(self) -> None:
        """Gradually reduce delay after successful requests."""
        self._current_delay = max(
            self._base_delay,
            self._current_delay * 0.8)

    @property
    def recommended_delay(self) -> float:
        return self._current_delay

    @property
    def profile(self) -> RateLimitProfile | None:
        return self._profile

    def get_stats(self) -> dict[str, Any]:
        total = len(self._history)
        rate_limited = sum(1 for h in self._history if h["status"] == 429)
        return {
            "total_requests": total,
            "rate_limited": rate_limited,
            "rate_limit_pct": round(rate_limited / total * 100, 1) if total else 0.0,
            "current_delay": round(self._current_delay, 2),
            "consecutive_429": self._consecutive_429,
            "profile": asdict(self._profile) if self._profile else None,
        }


class FingerprintRotator:
    """Rotate client fingerprint to avoid behavioral detection."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._rotation_index = 0
        self._used: set[str] = set()

    def next_user_agent(self) -> str:
        ua = USER_AGENTS[self._rotation_index % len(USER_AGENTS)]
        self._rotation_index += 1
        return ua

    def random_user_agent(self) -> str:
        return self._rng.choice(USER_AGENTS)

    def generate_headers(self) -> dict[str, str]:
        """Generate a consistent set of browser-like headers."""
        ua = self.next_user_agent()
        headers: dict[str, str] = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": self._rng.choice([
                "en-US,en;q=0.9",
                "en-GB,en;q=0.9",
                "es-ES,es;q=0.9,en;q=0.8",
                "fr-FR,fr;q=0.9,en;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if "Chrome" in ua:
            headers["Sec-Ch-Ua"] = '"Chromium";v="131", "Not_A Brand";v="24"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = self._rng.choice(
                ['"Windows"', '"macOS"', '"Linux"'])
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

        return headers

    def tls_config_hint(self) -> dict[str, str]:
        """Return TLS configuration hints for the current rotation."""
        configs = [
            {"cipher_preference": "ECDHE-RSA-AES128-GCM-SHA256",
             "tls_version": "TLSv1.3", "alpn": "h2"},
            {"cipher_preference": "ECDHE-ECDSA-AES256-GCM-SHA384",
             "tls_version": "TLSv1.3", "alpn": "h2"},
            {"cipher_preference": "TLS_AES_256_GCM_SHA384",
             "tls_version": "TLSv1.3", "alpn": "h2,http/1.1"},
        ]
        return configs[self._rotation_index % len(configs)]


class DefenseEvasionOrchestrator:
    """Coordinate evasion tactics across an engagement."""

    SOURCE = "defense_evasion"

    def __init__(self, graph: EngagementGraph):
        self.graph = graph
        self.waf_fingerprinter = WAFFingerprinter()
        self.bypass_engine = BypassEngine()
        self.rate_limiter = RateLimitEvader()
        self.rotator = FingerprintRotator()
        self._waf_profiles: dict[str, WAFProfile] = {}

    def fingerprint_waf(self, target: str,
                        headers: dict[str, str],
                        cookies: list[str],
                        status_code: int,
                        body: str = "") -> WAFProfile:
        """Fingerprint WAF for a target and record to graph."""
        profile = self.waf_fingerprinter.fingerprint(
            headers, cookies, status_code, body)
        self._waf_profiles[target] = profile

        if profile.vendor != "none_detected":
            self.graph.add_node(
                type="capability",
                label="WAF: {} ({})".format(profile.vendor, target),
                properties={
                    "waf_vendor": profile.vendor,
                    "confidence": profile.confidence,
                    "target": target,
                    "detected_headers": profile.detected_headers,
                    "source": self.SOURCE,
                },
                source=self.SOURCE,
            )

        return profile

    def suggest_bypass_strategy(self, target: str,
                                payload: str) -> list[dict[str, str]]:
        """Suggest bypass techniques based on WAF profile."""
        profile = self._waf_profiles.get(target)
        if profile:
            self.bypass_engine = BypassEngine(waf_profile=profile)

        variants = self.bypass_engine.generate_bypass_variants(payload)
        header_bypasses = self.bypass_engine.generate_header_bypasses()

        return variants + [{"technique": "header", "headers": json.dumps(h)}
                           for h in header_bypasses[:5]]

    def get_evasion_summary(self) -> dict[str, Any]:
        """Summary of all evasion state."""
        return {
            "waf_profiles": {t: p.to_dict()
                             for t, p in self._waf_profiles.items()},
            "rate_limit_stats": self.rate_limiter.get_stats(),
            "rotation_index": self.rotator._rotation_index,
            "bypass_techniques_available": sum(
                len(techs) for techs in BYPASS_TECHNIQUES.values()),
        }
