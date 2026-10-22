"""Tool execution backend abstraction.

Skills reference 25+ external tools (nmap, sqlmap, nuclei, ffuf, msfconsole,
interactsh-client...). This module makes WHERE they run explicit and
reproducible instead of assuming whatever happens to be on local $PATH:

  local   — direct subprocess on this machine (default)
  kali    — remote Kali Linux REST API (MCP-Kali-Server style):
            tools run on a dedicated attack box; results return over HTTP
  docker  — pinned container image with declared tool versions
  anonlab — Docker+Tor anonymous lab (kali container sharing torgw netns,
            all traffic routed through Tor; see references/anon-lab.md)

It also enforces the CLI anti-hallucination rules mechanically:
  - verify_tool() runs `--help` before first use in an engagement
  - run() applies default timeout (120s) and hard limit (20 min)
  - availability is probed once and cached, so skills can branch on
    "tool missing" instead of burning retries

Config: .pentest-state/toolrunner.json (per engagement) — see
references/tool-backends.md for Kali/Docker setup.
"""

import json
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_TIMEOUT = 120          # seconds — matches CLAUDE.md
HARD_LIMIT = 20 * 60           # 20 minutes — matches CLAUDE.md
MAX_IDENTICAL_RETRIES = 3      # matches CLAUDE.md

DOCKER_IMAGE = "pentest-plugin/toolkit:1.0"   # see references/tool-backends.md
ANONLAB_CONTAINER = "kali"                     # see references/anon-lab.md
TOR_CHECK_URL = "https://check.torproject.org/api/ip"


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    backend: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    ran_at: str = ""

    def __post_init__(self):
        if not self.ran_at:
            self.ran_at = datetime.now(timezone.utc).isoformat()


class ToolRunner:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.config_file = self.state_dir / "toolrunner.json"
        self.backend = "local"
        self.kali_url = ""           # e.g. http://kali-box:5000  (MCP-Kali-Server)
        self.docker_image = DOCKER_IMAGE
        self.anonlab_container = ANONLAB_CONTAINER
        self._verified: set[str] = set()     # tools whose --help ran this engagement
        self._cmd_counts: dict[str, int] = {}
        self._available: dict[str, bool] = {}
        self._load()

    def _load(self):
        if self.config_file.exists():
            cfg = json.loads(self.config_file.read_text())
            self.backend = cfg.get("backend", "local")
            self.kali_url = cfg.get("kali_url", "")
            self.docker_image = cfg.get("docker_image", DOCKER_IMAGE)
            self.anonlab_container = cfg.get("anonlab_container", ANONLAB_CONTAINER)
            self._verified = set(cfg.get("verified_tools", []))

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(json.dumps({
            "backend": self.backend,
            "kali_url": self.kali_url,
            "docker_image": self.docker_image,
            "anonlab_container": self.anonlab_container,
            "verified_tools": sorted(self._verified),
        }, indent=2))

    # ---- availability & verification (anti-hallucination) ----

    def is_available(self, tool: str) -> bool:
        if tool in self._available:
            return self._available[tool]
        ok = False
        if self.backend == "local":
            ok = shutil.which(tool) is not None
        elif self.backend == "docker":
            ok = shutil.which("docker") is not None  # image assumed to carry the tool
        elif self.backend == "kali":
            ok = self._kali_health() is not None
        elif self.backend == "anonlab":
            ok = self._anonlab_health() is not None
        self._available[tool] = ok
        return ok

    def verify_tool(self, tool: str, help_flag: str = "--help") -> bool:
        """Run `tool --help` once per engagement before real use (CLAUDE.md rule).
        Returns True if the tool responded; False means pick another tool."""
        if tool in self._verified:
            return True
        if not self.is_available(tool):
            return False
        res = self.run([tool, help_flag], timeout=30, is_verification=True)
        if res.exit_code == 0 or res.stdout or res.stderr:
            self._verified.add(tool)
            self._save()
            return True
        return False

    # ---- execution ----

    def run(self, argv: list[str], timeout: int = DEFAULT_TIMEOUT,
            is_verification: bool = False) -> ToolResult:
        tool = argv[0]
        timeout = min(timeout, HARD_LIMIT)

        if not is_verification and tool not in self._verified:
            self.verify_tool(tool)

        sig = " ".join(argv)
        self._cmd_counts[sig] = self._cmd_counts.get(sig, 0) + 1
        if self._cmd_counts[sig] > MAX_IDENTICAL_RETRIES:
            return ToolResult(tool=tool, argv=argv, backend=self.backend,
                              stderr=f"refused: identical command already ran "
                                     f"{MAX_IDENTICAL_RETRIES}x — change approach (CLAUDE.md)",
                              exit_code=126)

        if self.backend == "kali":
            return self._run_kali(argv, timeout)
        if self.backend == "anonlab":
            return self._run_anonlab(argv, timeout)
        if self.backend == "docker":
            argv = ["docker", "run", "--rm", "--network", "host",
                    self.docker_image] + argv
        return self._run_local(argv, timeout, tool)

    def _run_local(self, argv: list[str], timeout: int, tool: str) -> ToolResult:
        res = ToolResult(tool=tool, argv=argv, backend="local")
        start = time.time()
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            res.exit_code = proc.returncode
            res.stdout = proc.stdout
            res.stderr = proc.stderr
        except subprocess.TimeoutExpired as e:
            res.timed_out = True
            res.stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
            res.stderr = f"timeout after {timeout}s"
        except FileNotFoundError:
            res.stderr = f"tool not found: {argv[0]}"
            res.exit_code = 127
        res.duration_s = round(time.time() - start, 2)
        return res

    def _kali_health(self) -> dict | None:
        try:
            with urllib.request.urlopen(f"{self.kali_url}/health", timeout=10) as r:
                return json.loads(r.read().decode())
        except Exception:
            return None

    def _run_kali(self, argv: list[str], timeout: int) -> ToolResult:
        """MCP-Kali-Server style: POST /api/command {"command": "..."} → {stdout, stderr}.
        See references/tool-backends.md for the expected server contract."""
        res = ToolResult(tool=argv[0], argv=argv, backend="kali")
        start = time.time()
        body = json.dumps({"command": " ".join(argv), "timeout": timeout}).encode()
        req = urllib.request.Request(
            f"{self.kali_url}/api/command", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout + 10) as r:
                data = json.loads(r.read().decode())
            res.exit_code = data.get("return_code", 0)
            res.stdout = data.get("stdout", "")
            res.stderr = data.get("stderr", "")
        except Exception as e:
            res.stderr = f"kali backend error: {e}"
            res.exit_code = 125
        res.duration_s = round(time.time() - start, 2)
        return res

    # ---- anonlab backend (Docker+Tor anonymous lab) ----

    def _anonlab_health(self) -> dict | None:
        """Check kali container is running and Tor circuit is active."""
        try:
            proc = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}",
                 self.anonlab_container],
                capture_output=True, text=True, timeout=10)
            if proc.returncode != 0 or "true" not in proc.stdout.lower():
                return None
            proc = subprocess.run(
                ["docker", "exec", self.anonlab_container,
                 "curl", "-s", "--max-time", "15", TOR_CHECK_URL],
                capture_output=True, text=True, timeout=20)
            if proc.returncode != 0:
                return None
            data = json.loads(proc.stdout)
            if not data.get("IsTor"):
                return None
            return {"status": "ok", "tor_exit_ip": data.get("IP", "unknown"),
                    "is_tor": True}
        except Exception:
            return None

    def _run_anonlab(self, argv: list[str], timeout: int) -> ToolResult:
        """Run inside the kali container (shared netns with torgw, all traffic via Tor).
        See references/anon-lab.md for the architecture."""
        tool = argv[0]
        res = ToolResult(tool=tool, argv=argv, backend="anonlab")
        docker_argv = ["docker", "exec", self.anonlab_container] + argv
        start = time.time()
        try:
            proc = subprocess.run(
                docker_argv, capture_output=True, text=True, timeout=timeout)
            res.exit_code = proc.returncode
            res.stdout = proc.stdout
            res.stderr = proc.stderr
        except subprocess.TimeoutExpired as e:
            res.timed_out = True
            res.stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
            res.stderr = f"timeout after {timeout}s"
        except FileNotFoundError:
            res.stderr = "docker not found on host"
            res.exit_code = 127
        res.duration_s = round(time.time() - start, 2)
        return res

    def anonlab_status(self) -> dict:
        """Public health check for UI/status display."""
        health = self._anonlab_health()
        if health is None:
            return {"running": False, "tor": False}
        return {"running": True, "tor": True,
                "exit_ip": health.get("tor_exit_ip", "unknown")}

    def summary(self) -> dict:
        base = {
            "backend": self.backend,
            "verified_tools": sorted(self._verified),
            "unique_commands": len(self._cmd_counts),
            "availability_cache": dict(self._available),
        }
        if self.backend == "anonlab":
            base["anonlab"] = self.anonlab_status()
        return base
