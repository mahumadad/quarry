"""Anti-loop detection.

Detects when an agent is stuck in a loop (repeating the same actions)
and forces a strategy change or escalation.
"""

import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


MAX_IDENTICAL_CONSECUTIVE = 3
MAX_SIMILAR_WINDOW = 10
SIMILARITY_THRESHOLD = 0.8
STALL_THRESHOLD_ACTIONS = 10  # actions without progress = stall
HIGH_ERROR_RATIO = 0.5  # >50% errors in window = struggling

TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "nmap": ["rustscan", "masscan"],
    "gobuster": ["feroxbuster", "dirsearch", "ffuf"],
    "feroxbuster": ["gobuster", "dirsearch", "ffuf"],
    "sqlmap": ["ghauri", "nosqlmap"],
    "ffuf": ["wfuzz", "gobuster"],
    "subfinder": ["amass", "assetfinder"],
    "amass": ["subfinder", "assetfinder"],
    "httpx": ["curl", "wget"],
    "nuclei": ["nikto"],
    "katana": ["gospider", "hakrawler"],
    "gospider": ["katana", "hakrawler"],
    "gitleaks": ["trufflehog"],
    "trufflehog": ["gitleaks"],
    "whatweb": ["wappalyzer", "httpx"],
    "dig": ["nslookup", "host"],
    "curl": ["httpx", "wget"],
    "wfuzz": ["ffuf"],
}

STRATEGY_ALTERNATIVES: dict[str, list[str]] = {
    "content-discovery": [
        "Try different wordlist (e.g., raft-large, directory-list-2.3-big)",
        "Switch to recursive mode with depth limit",
        "Try extension fuzzing (.bak, .old, .conf, .env)",
        "Use tech-specific wordlist for detected stack",
    ],
    "sqli": [
        "Switch to time-based blind if error-based fails",
        "Try JSON/XML content-type bypass",
        "Test different injection points (headers, cookies)",
        "Try WAF bypass encoding (unicode, hex, double-url)",
    ],
    "xss": [
        "Switch from reflected to DOM-based testing",
        "Try mutation XSS payloads for the specific browser",
        "Test in different parameter positions (path, fragment, header)",
        "Use polyglot payloads that work across contexts",
    ],
    "auth-bypass": [
        "Try verb tampering (HEAD, OPTIONS, PATCH)",
        "Test path traversal bypass (../, %2e%2e/)",
        "Try case manipulation on path segments",
        "Test HTTP/2 pseudo-header manipulation",
    ],
    "ssrf": [
        "Switch from IP-based to DNS rebinding",
        "Try URL parser differential (backslash, @, #)",
        "Test different protocols (gopher://, dict://, file://)",
        "Use decimal/octal/hex IP encoding",
    ],
    "recon": [
        "Try passive sources instead of active scanning",
        "Search for JS files and extract endpoints",
        "Check web archive (Wayback Machine) for historical endpoints",
        "Try certificate transparency logs for subdomain discovery",
    ],
}


@dataclass
class ExecutionMonitor:
    """Tracks execution quality (inspired by PentAGI).

    Detects when an agent is struggling: high error rates, no progress
    (new findings/leads), or excessive token usage without results.
    """
    actions_since_progress: int = 0
    total_errors: int = 0
    total_actions: int = 0
    findings_at_start: int = 0
    leads_at_start: int = 0

    def record(self, action: str, success: bool, new_findings: int = 0,
               new_leads: int = 0) -> dict | None:
        self.total_actions += 1
        if not success:
            self.total_errors += 1
        if new_findings > 0 or new_leads > 0:
            self.actions_since_progress = 0
        else:
            self.actions_since_progress += 1

        if (self.total_actions >= STALL_THRESHOLD_ACTIONS
                and self.actions_since_progress >= STALL_THRESHOLD_ACTIONS):
            return {
                "type": "stall",
                "actions_without_progress": self.actions_since_progress,
                "recommendation": (
                    "No new findings or leads in "
                    f"{self.actions_since_progress} actions. "
                    "Consider: escalate to operator, switch strategy, "
                    "or try a more capable model for this phase."
                ),
            }

        if self.total_actions >= 6:
            error_ratio = self.total_errors / self.total_actions
            if error_ratio > HIGH_ERROR_RATIO:
                return {
                    "type": "high_error_rate",
                    "error_ratio": round(error_ratio, 2),
                    "recommendation": (
                        f"Error rate {error_ratio:.0%} over {self.total_actions} actions. "
                        "The model may be struggling with this task. "
                        "Consider: switch to a more capable model, simplify the "
                        "task, or provide more context via operator hint."
                    ),
                }
        return None

    def reset_progress(self):
        self.actions_since_progress = 0


@dataclass
class LoopDetector:
    window_size: int = 20
    history: deque = field(default_factory=lambda: deque(maxlen=20))
    loop_count: int = 0
    interventions: list[dict] = field(default_factory=list)
    exec_monitor: ExecutionMonitor = field(default_factory=ExecutionMonitor)

    def _check_identical_consecutive(self, action: str) -> int:
        count = 0
        for entry in reversed(self.history):
            if entry["action"] == action[:500]:
                count += 1
            else:
                break
        return count if count >= MAX_IDENTICAL_CONSECUTIVE else 0

    def _check_similar_pattern(self) -> bool:
        if len(self.history) < MAX_SIMILAR_WINDOW:
            return False
        recent = [e["action"] for e in list(self.history)[-MAX_SIMILAR_WINDOW:]]
        unique = set(recent)
        if len(unique) <= 2 and len(recent) >= MAX_SIMILAR_WINDOW:
            return True
        return False

    def suggest_alternative(self, action: str, context: str = "") -> dict:
        tool = self._extract_tool(action)
        alternatives = TOOL_ALTERNATIVES.get(tool, [])
        category = self._infer_category(action, context)
        strategies = STRATEGY_ALTERNATIVES.get(category, [])

        return {
            "stuck_tool": tool,
            "tool_alternatives": alternatives,
            "category": category,
            "strategy_alternatives": strategies,
            "recommendation": (
                f"Tool alternatives: {', '.join(alternatives)}. "
                if alternatives else ""
            ) + (
                f"Strategy shift: {strategies[0]}"
                if strategies else "Escalate to operator with findings so far."
            ),
        }

    def _extract_tool(self, action: str) -> str:
        for tool in TOOL_ALTERNATIVES:
            if tool in action.split()[:3]:
                return tool
        parts = action.strip().split()
        return parts[0] if parts else ""

    def _infer_category(self, action: str, context: str) -> str:
        combined = (action + " " + context).lower()
        if any(w in combined for w in ("gobuster", "ffuf", "ferox", "dirsearch", "dirb", "wordlist")):
            return "content-discovery"
        if any(w in combined for w in ("sqlmap", "sqli", "sql injection", "union select")):
            return "sqli"
        if any(w in combined for w in ("xss", "script", "alert(", "onerror")):
            return "xss"
        if any(w in combined for w in ("auth", "login", "bypass", "401", "403")):
            return "auth-bypass"
        if any(w in combined for w in ("ssrf", "request forgery", "metadata", "169.254")):
            return "ssrf"
        if any(w in combined for w in ("recon", "subfinder", "amass", "nmap", "scan")):
            return "recon"
        return ""

    def record_action(self, action: str, context: str = "",
                       success: bool = True, new_findings: int = 0,
                       new_leads: int = 0) -> dict:
        entry = {"action": action[:500], "context": context[:200],
                 "at": datetime.now(timezone.utc).isoformat()}
        self.history.append(entry)

        identical = self._check_identical_consecutive(action)
        if identical:
            self.loop_count += 1
            advice = self.suggest_alternative(action, context)
            result = {
                "loop_detected": True,
                "type": "identical_consecutive",
                "count": identical,
                "recommendation": (
                    f"Same action repeated {identical} times. STOP. "
                    f"{advice['recommendation']}"
                ),
                "alternatives": advice,
            }
            self.interventions.append(result)
            return result

        similar = self._check_similar_pattern()
        if similar:
            self.loop_count += 1
            advice = self.suggest_alternative(action, context)
            result = {
                "loop_detected": True,
                "type": "similar_pattern",
                "recommendation": (
                    f"Similar actions looping. {advice['recommendation']}"
                ),
                "alternatives": advice,
            }
            self.interventions.append(result)
            return result

        exec_alert = self.exec_monitor.record(
            action, success, new_findings, new_leads)
        if exec_alert:
            self.interventions.append(exec_alert)
            return {"loop_detected": False, "exec_alert": exec_alert}

        return {"loop_detected": False}

    def reset(self):
        self.history.clear()
        self.loop_count = 0

    def summary(self) -> dict:
        return {
            "total_actions": len(self.history),
            "loop_count": self.loop_count,
            "interventions": len(self.interventions),
            "exec_monitor": {
                "actions_since_progress": self.exec_monitor.actions_since_progress,
                "error_ratio": (
                    round(self.exec_monitor.total_errors / self.exec_monitor.total_actions, 2)
                    if self.exec_monitor.total_actions > 0 else 0.0
                ),
            },
        }
