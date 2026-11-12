"""Curated tool capabilities with deterministic, evidence-safe fallback.

This is a capability registry, not another installer or an unbounded list of
security tools. Missing tools are reported as coverage gaps, never as clean
results. Actual execution remains behind ToolRunner and the common policy.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from .redaction import redact
    from .storage import atomic_write_json, read_json
    from .toolrunner import ToolRunner
except ImportError:
    from redaction import redact
    from storage import atomic_write_json, read_json
    from toolrunner import ToolRunner


TOOL_FALLBACKS: dict[str, list[dict]] = {
    "nmap": [
        {"tool": "rustscan", "params": {"ports": "--range 1-65535"}, "notes": "Wraps nmap, faster SYN scan"},
        {"tool": "masscan", "params": {"rate": "--rate 1000"}, "notes": "SYN-only, no service detection"},
    ],
    "ffuf": [
        {"tool": "feroxbuster", "params": {}, "notes": "Built-in recursion, Rust-based"},
        {"tool": "gobuster", "params": {}, "notes": "Go-based, simpler"},
        {"tool": "dirsearch", "params": {}, "notes": "Python, smart wordlist"},
    ],
    "nuclei": [
        {"tool": "nikto", "params": {}, "notes": "Less precise, more noise, broader checks"},
    ],
    "sqlmap": [
        {"tool": "ghauri", "params": {}, "notes": "Python-native, fewer deps"},
    ],
    "subfinder": [
        {"tool": "amass", "params": {"mode": "enum"}, "notes": "Slower but deeper"},
        {"tool": "assetfinder", "params": {}, "notes": "Fast, fewer sources"},
    ],
    "httpx": [
        {"tool": "curl", "params": {}, "notes": "Always available, manual parsing"},
        {"tool": "httprobe", "params": {}, "notes": "Just alive check"},
    ],
    "katana": [
        {"tool": "gospider", "params": {}, "notes": "Go-based crawler"},
        {"tool": "hakrawler", "params": {}, "notes": "Simpler, stdin-based"},
    ],
    "gitleaks": [
        {"tool": "trufflehog", "params": {}, "notes": "Verified secrets"},
    ],
    "whatweb": [
        {"tool": "httpx", "params": {"flags": "-tech-detect"}, "notes": "Lightweight"},
    ],
    "gowitness": [
        {"tool": "aquatone", "params": {}, "notes": "Requires chromium"},
        {"tool": "eyewitness", "params": {}, "notes": "Python-based"},
    ],
    "wfuzz": [
        {"tool": "ffuf", "params": {}, "notes": "Faster, Go-based"},
    ],
    "dig": [
        {"tool": "nslookup", "params": {}, "notes": "Basic queries only"},
        {"tool": "host", "params": {}, "notes": "Simpler output"},
    ],
    "testssl.sh": [
        {"tool": "sslyze", "params": {}, "notes": "Python-based TLS scanner"},
        {"tool": "nmap", "params": {"script": "--script ssl-enum-ciphers"}, "notes": "Nmap NSE script"},
    ],
    "wpscan": [
        {"tool": "nuclei", "params": {"templates": "-t wordpress/"}, "notes": "Template-based WP scanning"},
    ],
    "jwt_tool": [],
    "graphql-cop": [],
    "interactsh-client": [],
}


CAPABILITY_BACKENDS: dict[str, tuple[str, ...]] = {
    "passive-dns": ("dig", "host", "nslookup"),
    "subdomain-discovery": ("subfinder", "amass", "assetfinder"),
    "url-history": ("gau", "waybackurls"),
    "http-probe": ("httpx", "curl"),
    "web-crawl": ("katana", "gospider", "hakrawler"),
    "javascript-discovery": ("linkfinder", "subjs", "katana"),
    "content-discovery": ("ffuf", "feroxbuster", "gobuster", "dirsearch"),
    "http-fuzzing": ("ffuf", "wfuzz"),
    "template-scan": ("nuclei",),
    "port-scan": ("nmap", "masscan"),
    "service-fingerprint": ("nmap",),
    "tech-fingerprint": ("whatweb", "wappalyzer", "httpx"),
    "screenshot": ("gowitness", "aquatone", "eyewitness"),
    "secret-scan": ("gitleaks", "trufflehog"),
    "oast": ("interactsh-client",),
}


class ToolRegistry:
    def __init__(self, audit_dir: str | Path, runner: ToolRunner | None = None,
                 version_detector: Callable[[str], str] | None = None):
        self.audit_dir = Path(audit_dir)
        self.state_file = self.audit_dir / ".pentest-state" / "tool-registry.json"
        self.runner = runner or ToolRunner(str(audit_dir))
        self.version_detector = version_detector or self._detect_version
        self._probes: dict[str, dict] = {}

    def _detect_version(self, tool: str) -> str:
        if self.runner.backend != "local":
            return "unverified-on-remote-backend"
        executable = shutil.which(tool)
        if not executable:
            return ""
        try:
            proc = subprocess.run([executable, "--version"], capture_output=True,
                                  text=True, timeout=5)
            output = (proc.stdout or proc.stderr).strip().splitlines()
            return output[0][:300] if output else "version-not-reported"
        except (OSError, subprocess.TimeoutExpired):
            return "version-check-failed"

    def probe(self, tool: str, refresh: bool = False) -> dict:
        if tool in self._probes and not refresh:
            return dict(self._probes[tool])
        available = self.runner.is_available(tool)
        path = shutil.which(tool) if self.runner.backend == "local" else ""
        record = {
            "tool": tool,
            "available": available,
            "path": path or "",
            "backend": self.runner.backend,
            "version": self.version_detector(tool) if available else "",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        self._probes[tool] = record
        return dict(record)

    def select(self, capability: str, persist: bool = True) -> dict:
        if capability not in CAPABILITY_BACKENDS:
            raise KeyError(f"Unknown tool capability: {capability}")
        candidates = list(CAPABILITY_BACKENDS[capability])
        probes = [self.probe(tool) for tool in candidates]
        selected = next((item for item in probes if item["available"]), None)
        result = {
            "capability": capability,
            "status": "available" if selected else "tool_unavailable",
            "selected": selected,
            "candidates": probes,
            "coverage_instruction": (
                "Use the selected backend through ToolRunner and persist its version with task output."
                if selected else
                "Record a tool_unavailable coverage gap; do not claim the capability was tested clean."
            ),
        }
        if persist:
            data = self.load()
            data.setdefault("capabilities", {})[capability] = {
                "selected": selected["tool"] if selected else "",
                "status": result["status"],
                "candidates": probes,
            }
            data["unavailable"] = sorted(name for name, item in data["capabilities"].items()
                                         if item["status"] == "tool_unavailable")
            data["generated_at"] = datetime.now(timezone.utc).isoformat()
            atomic_write_json(self.state_file, redact(data))
        return result

    def snapshot(self, persist: bool = True) -> dict:
        capabilities = {}
        for capability, candidates in CAPABILITY_BACKENDS.items():
            probes = [self.probe(tool) for tool in candidates]
            selected = next((item["tool"] for item in probes if item["available"]), "")
            capabilities[capability] = {
                "selected": selected,
                "status": "available" if selected else "tool_unavailable",
                "candidates": probes,
            }
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "capabilities": capabilities,
            "unavailable": sorted(name for name, item in capabilities.items()
                                  if item["status"] == "tool_unavailable"),
        }
        if persist:
            atomic_write_json(self.state_file, redact(result))
        return result

    def fallback_for(self, failed_tool: str) -> dict:
        """Given a tool that failed at runtime, return the next available alternative."""
        from .loop_detector import TOOL_ALTERNATIVES

        alternatives = TOOL_ALTERNATIVES.get(failed_tool, [])
        for alt in alternatives:
            probe = self.probe(alt)
            if probe["available"]:
                return {
                    "failed": failed_tool,
                    "fallback": alt,
                    "probe": probe,
                    "source": "tool_alternatives",
                }

        for cap, candidates in CAPABILITY_BACKENDS.items():
            if failed_tool in candidates:
                for candidate in candidates:
                    if candidate == failed_tool:
                        continue
                    probe = self.probe(candidate)
                    if probe["available"]:
                        return {
                            "failed": failed_tool,
                            "fallback": candidate,
                            "probe": probe,
                            "source": f"capability:{cap}",
                        }

        return {
            "failed": failed_tool,
            "fallback": "",
            "probe": {},
            "source": "none",
            "coverage_gap": f"No fallback available for {failed_tool}",
        }

    def fallback_for(self, tool: str) -> dict | None:
        """When a specific tool fails, return the first available fallback."""
        fallbacks = TOOL_FALLBACKS.get(tool, [])
        for fb in fallbacks:
            probe = self.probe(fb["tool"])
            if probe["available"]:
                return {
                    "original": tool,
                    "fallback": fb["tool"],
                    "params": fb.get("params", {}),
                    "notes": fb.get("notes", ""),
                    "probe": probe,
                }
        return None

    def fallback_chain(self, tool: str) -> list[dict]:
        """Return all available fallbacks for a tool, ordered by preference."""
        fallbacks = TOOL_FALLBACKS.get(tool, [])
        available = []
        for fb in fallbacks:
            probe = self.probe(fb["tool"])
            if probe["available"]:
                available.append({
                    "tool": fb["tool"],
                    "params": fb.get("params", {}),
                    "notes": fb.get("notes", ""),
                })
        return available

    def load(self) -> dict:
        return read_json(self.state_file, {"capabilities": {}, "unavailable": []})
