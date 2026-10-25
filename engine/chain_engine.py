"""Chain engine — the differentiator.

Two modes:
  1. Matrix mode (Syncfonía-style): combinatorial analysis of finding pairs
  2. Graph mode (kill chain): directed pivot graph from initial access to crown jewels

Uses references/chains/chain-matrix.md as a lookup of known patterns, and
dynamically discovers new chains from the finding set.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path


KNOWN_CHAINS: list[dict] = [
    {"a": "idor", "b": "rate-limiting", "result": "mass-data-exfiltration", "severity": "critical"},
    {"a": "xss-stored", "b": "csrf", "result": "account-takeover", "severity": "critical"},
    {"a": "ssrf", "b": "cloud-metadata", "result": "credential-theft", "severity": "critical"},
    {"a": "info-disclosure", "b": "auth-bypass", "result": "privilege-escalation", "severity": "high"},
    {"a": "open-redirect", "b": "oauth-misconfiguration", "result": "token-theft", "severity": "high"},
    {"a": "sqli", "b": "no-waf", "result": "full-db-dump", "severity": "critical"},
    {"a": "file-upload", "b": "path-traversal", "result": "rce-via-webshell", "severity": "critical"},
    {"a": "jwt-none-algo", "b": "idor", "result": "admin-impersonation", "severity": "critical"},
    {"a": "xss-reflected", "b": "open-redirect", "result": "phishing-chain", "severity": "high"},
    {"a": "ssrf", "b": "internal-service", "result": "internal-network-access", "severity": "critical"},
    {"a": "deserialization", "b": "file-upload", "result": "rce-via-deserialization", "severity": "critical"},
    {"a": "race-condition", "b": "business-logic", "result": "financial-manipulation", "severity": "critical"},
    {"a": "cors-misconfiguration", "b": "session-token-exposure", "result": "cross-origin-data-theft", "severity": "high"},
    {"a": "crlf-injection", "b": "xss", "result": "response-splitting-to-xss", "severity": "high"},
    {"a": "host-header-injection", "b": "password-reset", "result": "password-reset-poisoning", "severity": "critical"},
    {"a": "parameter-pollution", "b": "auth-bypass", "result": "access-control-bypass", "severity": "high"},
    {"a": "mass-assignment", "b": "role-field", "result": "privilege-escalation-via-mass-assign", "severity": "critical"},
    {"a": "graphql-introspection", "b": "idor", "result": "schema-guided-data-theft", "severity": "high"},
    {"a": "jwt-weak-secret", "b": "privilege-field", "result": "token-forgery-escalation", "severity": "critical"},
    {"a": "ssti", "b": "sandbox-escape", "result": "rce-via-template-engine", "severity": "critical"},
    {"a": "xxe", "b": "internal-file-read", "result": "credential-file-theft", "severity": "critical"},
    {"a": "websocket-no-auth", "b": "sensitive-action", "result": "unauthorized-actions-via-ws", "severity": "high"},
    {"a": "2fa-bypass", "b": "credential-stuffing", "result": "mass-account-compromise", "severity": "critical"},
    {"a": "session-fixation", "b": "xss", "result": "authenticated-session-hijack", "severity": "critical"},
    {"a": "email-injection", "b": "password-reset", "result": "account-takeover-via-email", "severity": "critical"},
    {"a": "prototype-pollution", "b": "xss", "result": "client-side-rce", "severity": "critical"},
    {"a": "cache-poisoning", "b": "xss", "result": "stored-xss-via-cache", "severity": "critical"},
    {"a": "http-smuggling", "b": "auth-bypass", "result": "request-smuggling-bypass", "severity": "critical"},
    {"a": "subdomain-takeover", "b": "cookie-scope", "result": "session-hijack-via-subdomain", "severity": "critical"},
    {"a": "clickjacking", "b": "sensitive-action", "result": "action-hijacking", "severity": "medium"},
    {"a": "csrf", "b": "xss-stored", "result": "persistent-xss-via-csrf", "severity": "critical"},
    {"a": "csrf", "b": "email-change", "result": "account-takeover-via-email-reset-chain", "severity": "critical"},
    {"a": "info-disclosure", "b": "uuid-leak", "result": "idor-via-leaked-identifiers", "severity": "high"},
    {"a": "open-redirect", "b": "oauth-callback", "result": "oauth-token-theft-via-redirect", "severity": "critical"},
    {"a": "file-upload", "b": "imagemagick", "result": "ssrf-rce-via-image-processing", "severity": "critical"},
    {"a": "lfi", "b": "log-poisoning", "result": "rce-via-log-inclusion", "severity": "critical"},
    {"a": "idor", "b": "payment-endpoint", "result": "financial-data-theft", "severity": "critical"},
    {"a": "api-key-leak", "b": "payment-gateway", "result": "payment-fraud-via-leaked-keys", "severity": "critical"},
]

ENABLES_MAP: dict[str, list[str]] = {
    "info-disclosure": ["auth-bypass", "idor", "ssrf", "sqli"],
    "ssrf": ["cloud-metadata", "internal-service", "port-scan-internal"],
    "xss-stored": ["csrf", "session-hijack", "phishing"],
    "xss-reflected": ["open-redirect", "session-hijack"],
    "sqli": ["data-exfiltration", "auth-bypass", "rce"],
    "auth-bypass": ["privilege-escalation", "idor", "admin-access"],
    "file-upload": ["rce", "path-traversal", "deserialization"],
    "idor": ["data-exfiltration", "privilege-escalation"],
    "open-redirect": ["oauth-token-theft", "phishing"],
    "lfi": ["credential-file-read", "rce-via-log-poisoning"],
    "rce": ["pivot-internal", "persistence", "data-exfiltration"],
    "ssti": ["rce", "file-read"],
    "xxe": ["file-read", "ssrf", "dos"],
    "deserialization": ["rce", "file-operations"],
    "csrf": ["stored-xss", "email-change", "password-change", "account-settings-change"],
    "lfi": ["credential-file-read", "rce-via-log-poisoning", "source-code-read"],
    "file-upload": ["rce-via-webshell", "xss-via-svg", "ssrf-via-imagemagick", "path-traversal"],
    "open-redirect": ["oauth-token-theft", "phishing", "ssrf"],
    "cors-misconfiguration": ["cross-origin-data-theft", "session-token-theft"],
    "api-key-leak": ["payment-fraud", "cloud-resource-abuse", "data-exfiltration"],
}


@dataclass
class Chain:
    id: str = ""
    name: str = ""
    findings: list[str] = field(default_factory=list)  # finding IDs
    vuln_classes: list[str] = field(default_factory=list)
    description: str = ""
    combined_impact: str = ""
    combined_severity: str = ""
    combined_cvss: float = 0.0
    status: str = "candidate"  # candidate, verified, killed
    evidence_tag: str = "inferred"
    pivot_path: list[dict] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.id:
            import uuid
            self.id = f"C-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


class ChainEngine:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.chains_file = self.state_dir / "chains.json"
        self._chains: dict[str, Chain] = {}
        self._load()

    def _load(self):
        if self.chains_file.exists():
            data = json.loads(self.chains_file.read_text())
            for cd in data.get("chains", []):
                c = Chain(**cd)
                self._chains[c.id] = c

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.chains_file.write_text(json.dumps({
            "chains": [asdict(c) for c in self._chains.values()],
            "count": len(self._chains),
        }, indent=2))

    def analyze_matrix(self, findings: list[dict]) -> list[Chain]:
        """Matrix mode: find all viable combinations among confirmed findings.

        For each pair (Fi, Fj):
          - Does Fi provide access/info that enables Fj?
          - Does the combination produce impact > max(impact_i, impact_j)?
          - If yes → generate candidate chain with combined CVSS
        """
        candidates = []
        classes = {f["id"]: f.get("vuln_class", "").lower() for f in findings}
        severities = {f["id"]: f.get("severity", "info") for f in findings}

        for fa, fb in combinations(findings, 2):
            ca, cb = classes[fa["id"]], classes[fb["id"]]

            for known in KNOWN_CHAINS:
                if self._class_matches(ca, known["a"]) and self._class_matches(cb, known["b"]):
                    chain = Chain(
                        name=known["result"],
                        findings=[fa["id"], fb["id"]],
                        vuln_classes=[ca, cb],
                        description=f"{ca} + {cb} → {known['result']}",
                        combined_severity=known["severity"],
                        combined_impact=known["result"],
                    )
                    candidates.append(chain)
                if self._class_matches(cb, known["a"]) and self._class_matches(ca, known["b"]):
                    chain = Chain(
                        name=known["result"],
                        findings=[fb["id"], fa["id"]],
                        vuln_classes=[cb, ca],
                        description=f"{cb} + {ca} → {known['result']}",
                        combined_severity=known["severity"],
                        combined_impact=known["result"],
                    )
                    candidates.append(chain)

            if ca in ENABLES_MAP:
                for enabled in ENABLES_MAP[ca]:
                    if self._class_matches(cb, enabled):
                        chain = Chain(
                            name=f"{ca}-enables-{cb}",
                            findings=[fa["id"], fb["id"]],
                            vuln_classes=[ca, cb],
                            description=f"{ca} enables exploitation of {cb}",
                            combined_severity=self._escalate_severity(severities[fa["id"]], severities[fb["id"]]),
                        )
                        candidates.append(chain)

        seen = set()
        unique = []
        for c in candidates:
            key = (frozenset(c.findings), c.name)
            if key not in seen:
                seen.add(key)
                unique.append(c)

        for c in unique:
            self._chains[c.id] = c
        self._save()
        return unique

    def build_pivot_graph(self, findings: list[dict], assets: list[str]) -> dict:
        """Graph mode: build directed graph for kill chain pivoting.

        Nodes = assets + accesses obtained
        Edges = findings/techniques that enable the jump
        Returns the graph as adjacency list + all paths from initial access to crown jewels.
        """
        nodes = set(assets)
        edges = []

        for f in findings:
            src = f.get("target_asset", "unknown")
            vuln = f.get("vuln_class", "")
            nodes.add(src)

            if vuln in ENABLES_MAP:
                for capability in ENABLES_MAP[vuln]:
                    dest = f"{src}:{capability}"
                    nodes.add(dest)
                    edges.append({
                        "from": src,
                        "to": dest,
                        "via": f["id"],
                        "technique": vuln,
                        "capability": capability,
                    })

        return {
            "nodes": sorted(nodes),
            "edges": edges,
            "finding_count": len(findings),
            "asset_count": len(assets),
        }

    def find_paths(self, graph: dict, start: str, goal_keywords: list[str]) -> list[list[dict]]:
        """BFS to find all paths from start to nodes matching goal keywords."""
        adj: dict[str, list[dict]] = {}
        for e in graph["edges"]:
            adj.setdefault(e["from"], []).append(e)

        paths = []
        queue = [(start, [start], [])]
        visited_per_path: set[str] = set()

        while queue:
            node, path_nodes, path_edges = queue.pop(0)
            for goal in goal_keywords:
                if goal.lower() in node.lower() and len(path_edges) > 0:
                    paths.append(path_edges[:])
            for edge in adj.get(node, []):
                next_node = edge["to"]
                if next_node not in path_nodes:
                    queue.append((
                        next_node,
                        path_nodes + [next_node],
                        path_edges + [edge],
                    ))
            if len(paths) >= 50:
                break
        return paths

    def get_chain(self, chain_id: str) -> Chain | None:
        return self._chains.get(chain_id)

    def list_chains(self, status: str | None = None) -> list[Chain]:
        if status:
            return [c for c in self._chains.values() if c.status == status]
        return list(self._chains.values())

    def analyze_capabilities(self, findings: list[dict], brain) -> list[Chain]:
        """Capability-graph mode: model chains as gives/needs relationships.

        Uses Brain's FINDING_CAPABILITIES to find findings whose 'gives'
        satisfy another finding's 'needs', producing multi-step chains
        with trust-boundary crossings scored higher.
        """
        from .brain import FINDING_CAPABILITIES, TRUST_BOUNDARIES

        capabilities_by_finding: dict[str, set[str]] = {}
        needs_by_finding: dict[str, set[str]] = {}

        for f in findings:
            fid = f["id"]
            vc = f.get("vuln_class", "").lower()
            caps = FINDING_CAPABILITIES.get(vc, {})
            capabilities_by_finding[fid] = set(caps.get("gives", []))
            needs_by_finding[fid] = set(caps.get("needs", []))

        chains = []
        for consumer in findings:
            cid = consumer["id"]
            needed = needs_by_finding.get(cid, set())
            if not needed:
                continue
            for provider in findings:
                pid = provider["id"]
                if pid == cid:
                    continue
                provided = capabilities_by_finding.get(pid, set())
                satisfied = needed & provided
                if satisfied:
                    chain = Chain(
                        name=f"capability-chain-{provider.get('vuln_class','?')}-enables-{consumer.get('vuln_class','?')}",
                        findings=[pid, cid],
                        vuln_classes=[
                            provider.get("vuln_class", ""),
                            consumer.get("vuln_class", ""),
                        ],
                        description=(
                            f"{provider.get('vuln_class','')} provides "
                            f"{', '.join(sorted(satisfied))} needed by "
                            f"{consumer.get('vuln_class','')}"
                        ),
                        combined_severity=self._escalate_severity(
                            provider.get("severity", "info"),
                            consumer.get("severity", "info"),
                        ),
                        combined_impact=f"chain via {', '.join(sorted(satisfied))}",
                        evidence_tag="inferred",
                    )
                    chains.append(chain)
                    self._chains[chain.id] = chain

        self._save()
        return chains

    def suggest_next_from_capabilities(self, findings: list[dict], brain) -> list[dict]:
        """Given current capabilities, suggest vuln classes worth hunting."""
        from .brain import FINDING_CAPABILITIES

        current_caps = {c["capability"] for c in brain.get_capabilities()}
        already_found = {f.get("vuln_class", "").lower() for f in findings}
        suggestions = []

        for vc, caps in FINDING_CAPABILITIES.items():
            if vc in already_found:
                continue
            needed = set(caps.get("needs", []))
            if needed and needed.issubset(current_caps):
                suggestions.append({
                    "vuln_class": vc,
                    "reason": f"We have {', '.join(needed)} — {vc} needs exactly that",
                    "potential_gives": caps.get("gives", []),
                    "priority": len(caps.get("gives", [])),
                })

        suggestions.sort(key=lambda s: s["priority"], reverse=True)
        return suggestions

    @staticmethod
    def _class_matches(finding_class: str, pattern: str) -> bool:
        fc = finding_class.lower().replace("_", "-").replace(" ", "-")
        pt = pattern.lower().replace("_", "-").replace(" ", "-")
        return pt in fc or fc in pt

    @staticmethod
    def _escalate_severity(sev_a: str, sev_b: str) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        ia = order.index(sev_a) if sev_a in order else 0
        ib = order.index(sev_b) if sev_b in order else 0
        combined = min(ia + ib + 1, len(order) - 1)
        return order[combined]
