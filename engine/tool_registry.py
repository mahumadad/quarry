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

    def load(self) -> dict:
        return read_json(self.state_file, {"capabilities": {}, "unavailable": []})
