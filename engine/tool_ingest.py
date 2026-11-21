"""Normalize external tool output into LEADS, never into findings.

A tool hit (nuclei match, sqlmap injection point, ...) is a hypothesis, not a
demonstrated finding: it enters the engagement as an OPEN lead that still has
to pass a real oracle (3-gate / the matching hunt skill) before it becomes a
finding. This keeps the anti-fabrication rule intact while getting tool output
into the graph as structured state instead of free text the agent re-types.

Supported tools: ``nuclei`` (JSONL), ``sqlmap`` (console/log text), ``burp``
(Scanner issue XML export), ``nmap`` (``-oX`` XML), ``httpx`` (``-json``
JSONL), ``ffuf`` (``-o json``) and ``bbot`` (output NDJSON, scope-distance
filtered). Recon tools surface attack surface (open ports, live hosts, found
paths, events) as OPEN leads to investigate — never as findings. Add a parser
to INGESTORS to support another.
"""
from __future__ import annotations

import json
import re
from typing import Callable

try:
    from .leads import Lead, LeadsStore
except ImportError:  # top-level script mode
    from leads import Lead, LeadsStore


_NUCLEI_SEVERITY = {
    "critical": "high", "high": "high", "medium": "medium",
    "low": "low", "info": "low", "unknown": "low",
}


def parse_nuclei_jsonl(text: str) -> list[Lead]:
    """One lead per nuclei JSONL result line. Malformed lines are skipped."""
    leads: list[Lead] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
        template = rec.get("template-id") or rec.get("templateID") or ""
        name = info.get("name") or template or "nuclei match"
        severity = str(info.get("severity", "unknown")).lower()
        matched = rec.get("matched-at") or rec.get("host") or rec.get("url") or ""
        leads.append(Lead(
            title=name,
            source="nuclei",
            vuln_class_hint=template,
            target_asset=matched,
            priority=_NUCLEI_SEVERITY.get(severity, "low"),
            notes="nuclei template {} (severity {})".format(template, severity),
        ))
    return leads


_SQLMAP_PARAM = re.compile(r"^Parameter:\s*(.+?)\s*\(([^)]*)\)", re.M)


def parse_sqlmap(text: str) -> list[Lead]:
    """One lead per sqlmap 'Parameter:' injection block."""
    leads: list[Lead] = []
    target = ""
    m_url = re.search(r"https?://[^\s'\"]+", text)
    if m_url:
        target = m_url.group(0)
    for m in _SQLMAP_PARAM.finditer(text):
        param, method = m.group(1).strip(), m.group(2).strip()
        # Capture the injection types listed under this parameter block.
        tail = text[m.end():]
        types = re.findall(r"^\s*Type:\s*(.+)$", tail.split("Parameter:")[0], re.M)
        leads.append(Lead(
            title="SQL injection in '{}' ({})".format(param, method or "param"),
            source="sqlmap",
            vuln_class_hint="sqli",
            target_asset=target,
            priority="high",
            notes="sqlmap types: {}".format(", ".join(t.strip() for t in types)
                                            or "unspecified"),
        ))
    return leads


_BURP_SEVERITY = {
    "high": "high", "medium": "medium", "low": "low",
    "information": "low", "info": "low",
}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def parse_burp(text: str) -> list[Lead]:
    """One lead per Burp *Scanner* issue (XML export).

    Burp proxy history is raw traffic, not a hypothesis, so it is not ingested;
    only Scanner issues become leads (like a nuclei match). Each issue stays an
    OPEN lead until a real oracle promotes it.
    """
    import xml.etree.ElementTree as ET

    # Burp's export carries a DOCTYPE declaring HTML entities. Strip it so a
    # crafted file cannot smuggle an entity-expansion bomb; issue text is CDATA,
    # so the entity definitions are not needed to read the data.
    cleaned = re.sub(r"<!DOCTYPE[^\[>]*(\[.*?\])?\s*>", "", text, flags=re.S)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return []
    leads: list[Lead] = []
    for issue in root.iter("issue"):
        name = (issue.findtext("name") or "").strip() or "Burp issue"
        host = (issue.findtext("host") or "").strip()
        location = (issue.findtext("location")
                    or issue.findtext("path") or "").strip()
        severity = (issue.findtext("severity") or "").strip().lower()
        confidence = (issue.findtext("confidence") or "").strip()
        leads.append(Lead(
            title=name,
            source="burp",
            vuln_class_hint=_slug(name),
            target_asset=(host + location) if host else location,
            priority=_BURP_SEVERITY.get(severity, "low"),
            notes="burp scanner issue (severity {}, confidence {})".format(
                severity or "n/a", confidence or "n/a"),
        ))
    return leads


def _iter_jsonl(text: str):
    """Yield dict records from JSONL, skipping blanks and malformed lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(rec, dict):
            yield rec


# Only open ports become leads; closed/filtered are not surface.
def parse_nmap(text: str) -> list[Lead]:
    """One lead per *open* port in an nmap ``-oX`` XML report.

    An open port is attack surface to investigate, not a finding. The host
    prefers its PTR/hostname over the raw IP so downstream hunts hit the vhost.
    """
    import xml.etree.ElementTree as ET

    # Strip any DOCTYPE defensively (same rationale as the Burp parser: a
    # crafted report must not smuggle an entity-expansion bomb).
    cleaned = re.sub(r"<!DOCTYPE[^\[>]*(\[.*?\])?\s*>", "", text, flags=re.S)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return []
    leads: list[Lead] = []
    for host in root.iter("host"):
        addr = ""
        for a in host.iter("address"):
            if a.get("addrtype", "ipv4") in ("ipv4", "ipv6"):
                addr = a.get("addr", "") or addr
        hostname = ""
        hn = host.find("./hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        who = hostname or addr
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(p for p in (product, version) if p)
            leads.append(Lead(
                title="Open {}/{} {}".format(proto, portid, name or "unknown"),
                source="nmap",
                vuln_class_hint="",
                target_asset="{}:{}".format(who, portid) if who else portid,
                priority="low",
                notes="nmap: {} {}".format(name or "service",
                                           banner or "no banner").strip(),
            ))
    return leads


def parse_httpx(text: str) -> list[Lead]:
    """One lead per live host in httpx ``-json`` JSONL output."""
    leads: list[Lead] = []
    for rec in _iter_jsonl(text):
        url = rec.get("url") or rec.get("input") or rec.get("host") or ""
        if not url:
            continue
        status = rec.get("status_code", rec.get("status", ""))
        title = rec.get("title", "") or ""
        tech = rec.get("tech") or rec.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        server = rec.get("webserver", "") or rec.get("server", "")
        bits = []
        if server:
            bits.append(server)
        bits.extend(t for t in tech if t and t != server)
        leads.append(Lead(
            title="Live {} [{}]{}".format(url, status,
                                          " " + title if title else ""),
            source="httpx",
            vuln_class_hint="",
            target_asset=url,
            priority="low",
            notes="httpx: status {} tech {}".format(
                status or "n/a", ", ".join(bits) or "unknown"),
        ))
    return leads


def parse_ffuf(text: str) -> list[Lead]:
    """One lead per ffuf ``-o json`` result (discovered path/content)."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    results = doc.get("results") if isinstance(doc, dict) else doc
    if not isinstance(results, list):
        return []
    leads: list[Lead] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url", "")
        if not url:
            continue
        status = r.get("status", "")
        length = r.get("length", "")
        word = ""
        inp = r.get("input")
        if isinstance(inp, dict):
            word = inp.get("FUZZ", "") or next(iter(inp.values()), "")
        # A 2xx hit is live content worth a look; redirects/forbidden are
        # lower-signal but still surface.
        priority = "medium" if isinstance(status, int) and 200 <= status < 300 \
            else "low"
        leads.append(Lead(
            title="ffuf {} [{}]".format(word or url, status),
            source="ffuf",
            vuln_class_hint="",
            target_asset=url,
            priority=priority,
            notes="ffuf: status {} length {}".format(status, length),
        ))
    return leads


# bbot event types worth turning into leads. Noise (DNS resolution chatter,
# raw protocol events) is left out; these carry investigable surface.
_BBOT_TYPES = {
    "URL", "URL_UNVERIFIED", "VULNERABILITY", "FINDING", "OPEN_TCP_PORT",
    "DNS_NAME", "TECHNOLOGY", "STORAGE_BUCKET", "SOCIAL", "CODE_REPOSITORY",
    "WEB_PARAMETER", "AZURE_TENANT",
}
_BBOT_SEVERITY = {
    "CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "low",
}


def parse_bbot(text: str, max_scope_distance: int = 0) -> list[Lead]:
    """One lead per in-scope bbot event (NDJSON output).

    ``max_scope_distance`` gates how far out of scope to pull events in: the
    default (0) keeps only directly in-scope assets, matching the scope
    discipline. VULNERABILITY events carry a severity; everything else is
    surface to investigate.
    """
    leads: list[Lead] = []
    for rec in _iter_jsonl(text):
        etype = rec.get("type", "")
        if etype not in _BBOT_TYPES:
            continue
        try:
            distance = int(rec.get("scope_distance", 0))
        except (TypeError, ValueError):
            distance = 0
        if distance > max_scope_distance:
            continue
        data = rec.get("data", "")
        if isinstance(data, dict):
            asset = (data.get("url") or data.get("host")
                     or data.get("name") or "")
            description = data.get("description", "")
            severity = str(data.get("severity", "")).upper()
        else:
            asset = str(data)
            description = ""
            severity = ""
        if etype == "VULNERABILITY":
            priority = _BBOT_SEVERITY.get(severity, "medium")
            hint = "bbot-vuln"
        elif etype == "FINDING":
            priority = "medium"
            hint = ""
        else:
            priority = "low"
            hint = ""
        leads.append(Lead(
            title="bbot {}: {}".format(etype, description or asset or "event"),
            source="bbot",
            vuln_class_hint=hint,
            target_asset=asset,
            priority=priority,
            notes="bbot {} (scope_distance {}){}".format(
                etype, distance,
                " severity " + severity if severity else ""),
        ))
    return leads


INGESTORS: dict[str, Callable[[str], list[Lead]]] = {
    "nuclei": parse_nuclei_jsonl,
    "sqlmap": parse_sqlmap,
    "burp": parse_burp,
    "nmap": parse_nmap,
    "httpx": parse_httpx,
    "ffuf": parse_ffuf,
    "bbot": parse_bbot,
}


def ingest(tool: str, text: str, audit_dir: str | None = None,
           store: bool = False) -> list[Lead]:
    """Parse ``text`` from ``tool`` into leads; optionally persist them.

    Persisted leads are OPEN — a hypothesis to verify, not a finding. Promotion
    to a finding happens only through a real oracle elsewhere.
    """
    parser = INGESTORS.get(tool)
    if parser is None:
        raise ValueError("unknown tool {!r}; known: {}".format(
            tool, sorted(INGESTORS)))
    leads = parser(text)
    if store and audit_dir:
        leads_store = LeadsStore(audit_dir)
        for lead in leads:
            leads_store.add(lead)
    return leads


def main() -> int:
    import argparse
    from dataclasses import asdict
    from pathlib import Path

    ap = argparse.ArgumentParser(
        prog="engine.tool_ingest",
        description="Normalize scanner/recon tool output into OPEN leads.")
    ap.add_argument("--tool", required=True, choices=sorted(INGESTORS))
    ap.add_argument("--file", required=True, help="tool output file")
    ap.add_argument("--audit-dir", default=".")
    ap.add_argument("--store", action="store_true",
                    help="persist the leads to the engagement's leads store")
    args = ap.parse_args()
    text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    leads = ingest(args.tool, text, audit_dir=args.audit_dir, store=args.store)
    print(json.dumps([asdict(l) for l in leads], indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
