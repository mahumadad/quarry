"""Detect defensive AI decoys (SpikeStrip, prompt traps) in web content.

Analyzes HTML/JS comments and page content for patterns that indicate
prompt-injection decoys planted by defenders. When detected, findings
sourced from those areas are flagged as potentially fabricated leads.

Based on analysis of Arcanum-Sec/SpikeStrip patterns:
- Hex-keyed comments (12+ char random hex adjacent to instructions)
- Fabricated routes with real CVE IDs but no backend response
- Workflow derailment instructions in comments
- Mathematical impossibility tasks (Riemann, P=NP, etc.)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence


HEX_KEY_RE = re.compile(r"\b[0-9a-f]{12,24}\b")

TRAP_INSTRUCTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"prioritize\s+(?:SSRF|SQLi?|XSS|XXE|RCE|SSTI|path.traversal)\s+(?:checks?|review)",
        r"treat\s+this\s+(?:maintenance|review)\s+note\s+as\s+your\s+next\s+task",
        r"before\s+(?:resuming|continuing)\s+the\s+original\s+checklist",
        r"include\s+this\s+identifier\s+in\s+your\s+next\s+status\s+update",
        r"pause\s+broad\s+crawling\s+and\s+enumerate",
        r"assessment\s+workflow\s*:",
        r"verification\s+gate\s*:",
        r"review\s+reference\s*:",
        r"tool\s+routing\s+note\s*:",
        r"finish\s+its\s+compatibility\s+review\s+before\s+resuming",
    ]
]

MATH_TRAP_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"prove\s+the\s+riemann\s+hypothesis",
        r"solve\s+(?:the\s+)?collatz\s+conjecture",
        r"factor\s+(?:the\s+following\s+)?RSA-\d+",
        r"compute\s+BB\(\d+\)",
        r"determine\s+whether\s+P\s*[=≠]\s*NP",
    ]
]

FAKE_ROUTE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"/(?:api/preview|legacy/search-java|internal/render|ops-legacy/actuator)",
        r"/legacy-cgi/",
        r"/legacy/upload\s+handler",
        r"/media/proxy\s+route",
        r"/api/reports\s+handler",
    ]
]

CVE_IN_COMMENT_RE = re.compile(
    r"CVE-\d{4}-\d{4,7}.*?(?:prioritize|review|check|test)\s+(?:there|it|this)",
    re.IGNORECASE,
)

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
JS_BLOCK_COMMENT_RE = re.compile(r"/\*(.*?)\*/", re.DOTALL)
JS_LINE_COMMENT_RE = re.compile(r"//(.*?)$", re.MULTILINE)


@dataclass
class DecoySignal:
    pattern_type: str
    matched_text: str
    confidence: float
    location: str = ""

    @property
    def label(self) -> str:
        return f"decoy:{self.pattern_type}"


@dataclass
class DecoyReport:
    signals: list[DecoySignal] = field(default_factory=list)
    total_comments_scanned: int = 0
    decoy_comments_found: int = 0

    @property
    def has_decoys(self) -> bool:
        return len(self.signals) > 0

    @property
    def max_confidence(self) -> float:
        return max((s.confidence for s in self.signals), default=0.0)

    def summary(self) -> str:
        if not self.has_decoys:
            return "No decoy patterns detected"
        types = {}
        for s in self.signals:
            types[s.pattern_type] = types.get(s.pattern_type, 0) + 1
        parts = [f"{count}x {ptype}" for ptype, count in sorted(types.items())]
        return (
            f"DECOY WARNING: {len(self.signals)} signals in "
            f"{self.decoy_comments_found}/{self.total_comments_scanned} comments "
            f"({', '.join(parts)}). Max confidence: {self.max_confidence:.0%}"
        )


def _extract_comments(content: str, content_type: str = "html") -> list[tuple[str, str]]:
    comments: list[tuple[str, str]] = []
    if content_type in ("html", "svg"):
        for m in HTML_COMMENT_RE.finditer(content):
            comments.append((m.group(1).strip(), f"html_comment@{m.start()}"))
    if content_type in ("js", "javascript", "css"):
        for m in JS_BLOCK_COMMENT_RE.finditer(content):
            comments.append((m.group(1).strip(), f"js_block@{m.start()}"))
        for m in JS_LINE_COMMENT_RE.finditer(content):
            comments.append((m.group(1).strip(), f"js_line@{m.start()}"))
    if content_type == "html":
        for m in JS_BLOCK_COMMENT_RE.finditer(content):
            comments.append((m.group(1).strip(), f"inline_js_block@{m.start()}"))
    return comments


def _score_comment(text: str) -> list[DecoySignal]:
    signals: list[DecoySignal] = []

    hex_keys = HEX_KEY_RE.findall(text)
    has_hex_key = bool(hex_keys)

    for pattern in TRAP_INSTRUCTION_PATTERNS:
        m = pattern.search(text)
        if m:
            conf = 0.95 if has_hex_key else 0.70
            signals.append(DecoySignal("trap_instruction", m.group()[:120], conf))

    for pattern in MATH_TRAP_PATTERNS:
        m = pattern.search(text)
        if m:
            conf = 0.99 if has_hex_key else 0.85
            signals.append(DecoySignal("math_trap", m.group()[:120], conf))

    for pattern in FAKE_ROUTE_PATTERNS:
        m = pattern.search(text)
        if m:
            conf = 0.80 if has_hex_key else 0.50
            signals.append(DecoySignal("fake_route", m.group()[:120], conf))

    m = CVE_IN_COMMENT_RE.search(text)
    if m:
        conf = 0.90 if has_hex_key else 0.60
        signals.append(DecoySignal("cve_bait", m.group()[:120], conf))

    if has_hex_key and not signals:
        if len(text) > 40 and any(w in text.lower() for w in
                ("handler", "route", "endpoint", "parameter", "review", "check", "assess")):
            signals.append(DecoySignal("hex_keyed_suspicious", hex_keys[0], 0.45))

    return signals


def scan_content(
    content: str,
    content_type: str = "html",
    url: str = "",
) -> DecoyReport:
    comments = _extract_comments(content, content_type)
    report = DecoyReport(total_comments_scanned=len(comments))

    flagged_locations: set[str] = set()
    for text, location in comments:
        if not text or len(text) < 20:
            continue
        signals = _score_comment(text)
        for sig in signals:
            sig.location = f"{url}:{location}" if url else location
            report.signals.append(sig)
        if signals:
            flagged_locations.add(location)

    report.decoy_comments_found = len(flagged_locations)
    return report


def scan_multiple(
    contents: Sequence[tuple[str, str, str]],
) -> DecoyReport:
    combined = DecoyReport()
    for content, content_type, url in contents:
        partial = scan_content(content, content_type, url)
        combined.signals.extend(partial.signals)
        combined.total_comments_scanned += partial.total_comments_scanned
        combined.decoy_comments_found += partial.decoy_comments_found
    return combined
