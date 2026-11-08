"""Playwright browser loop for headless exploitation steps.

Wraps Playwright to execute multi-step browser-based exploit chains
(XSS verification, CSRF PoC, auth flow testing, DOM extraction).
Playwright is a soft dependency — graceful fallback if not installed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .custody import CustodyLog
    from .policy import url_policy, PolicyDenied
except ImportError:
    from custody import CustodyLog
    from policy import url_policy, PolicyDenied


PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ExploitStep:
    action: str  # navigate, click, fill, submit, wait, extract, screenshot, execute_js
    selector: str = ""
    value: str = ""
    timeout_ms: int = 5000
    description: str = ""


@dataclass
class BrowserState:
    url: str = ""
    title: str = ""
    cookies: list[dict] = field(default_factory=list)
    console_logs: list[str] = field(default_factory=list)
    network_requests: list[dict] = field(default_factory=list)
    dom_snapshot: str = ""
    screenshot_path: str = ""
    captured_at: str = ""

    def __post_init__(self):
        if not self.captured_at:
            self.captured_at = datetime.now(timezone.utc).isoformat()


class BrowserLoopError(RuntimeError):
    pass


class BrowserSession:
    """Headless browser session for exploit verification."""

    def __init__(self, audit_dir: str):
        if not PLAYWRIGHT_AVAILABLE:
            raise BrowserLoopError(
                "playwright not installed. Run: pip install playwright && playwright install chromium")
        self.audit_dir = Path(audit_dir)
        self.state_dir = self.audit_dir / ".pentest-state" / "browser"
        self._custody = CustodyLog(str(self.audit_dir))
        self._playwright = None
        self._browser: Browser | None = None
        self._page: Page | None = None
        self._console_logs: list[str] = []
        self._network_requests: list[dict] = []

    def start(self, headless: bool = True) -> None:
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=headless)
        context = self._browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (quarry browser-loop)",
        )
        self._page = context.new_page()
        self._page.on("console", lambda msg: self._console_logs.append(
            f"[{msg.type}] {msg.text}"))
        self._page.on("request", lambda req: self._network_requests.append({
            "method": req.method, "url": req.url,
            "at": datetime.now(timezone.utc).isoformat(),
        }))
        self._custody.append("browser_session_started", {
            "headless": headless,
        })

    def navigate(self, url: str) -> dict:
        self._require_page()
        try:
            url_policy(url, str(self.audit_dir))
        except PolicyDenied as exc:
            return {"url": url, "status": None, "title": None,
                    "error": f"Scope violation: {exc}"}
        response = self._page.goto(url, wait_until="domcontentloaded", timeout=15000)
        result = {
            "url": self._page.url,
            "status": response.status if response else None,
            "title": self._page.title(),
        }
        self._custody.append("browser_navigate", {"url": url, "status": result["status"]})
        return result

    def execute_exploit_step(self, step: ExploitStep) -> dict:
        self._require_page()
        result: dict[str, Any] = {"action": step.action, "success": False}

        try:
            if step.action == "navigate":
                nav = self.navigate(step.value)
                result.update(nav)
                result["success"] = True

            elif step.action == "click":
                self._page.click(step.selector, timeout=step.timeout_ms)
                result["success"] = True

            elif step.action == "fill":
                self._page.fill(step.selector, step.value, timeout=step.timeout_ms)
                result["success"] = True

            elif step.action == "submit":
                if step.selector:
                    self._page.click(step.selector, timeout=step.timeout_ms)
                else:
                    self._page.keyboard.press("Enter")
                self._page.wait_for_load_state("domcontentloaded", timeout=step.timeout_ms)
                result["success"] = True

            elif step.action == "wait":
                if step.selector:
                    self._page.wait_for_selector(step.selector, timeout=step.timeout_ms)
                else:
                    self._page.wait_for_timeout(step.timeout_ms)
                result["success"] = True

            elif step.action == "extract":
                content = self._page.inner_text(step.selector, timeout=step.timeout_ms)
                result["extracted"] = content
                result["success"] = True

            elif step.action == "screenshot":
                path = self._screenshot_path()
                self._page.screenshot(path=path, full_page=True)
                result["screenshot_path"] = str(path)
                result["success"] = True

            elif step.action == "execute_js":
                js_result = self._page.evaluate(step.value)
                result["js_result"] = js_result
                result["success"] = True

        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"

        self._custody.append("browser_exploit_step", {
            "action": step.action,
            "selector": step.selector[:100],
            "success": result["success"],
        })
        return result

    def capture_state(self) -> BrowserState:
        self._require_page()
        screenshot_path = self._screenshot_path()
        self._page.screenshot(path=screenshot_path, full_page=True)

        cookies = self._page.context.cookies()
        dom = self._page.content()[:50000]

        state = BrowserState(
            url=self._page.url,
            title=self._page.title(),
            cookies=[{"name": c["name"], "domain": c["domain"],
                      "httpOnly": c.get("httpOnly", False),
                      "secure": c.get("secure", False)} for c in cookies],
            console_logs=list(self._console_logs[-50:]),
            network_requests=list(self._network_requests[-100:]),
            dom_snapshot=dom,
            screenshot_path=str(screenshot_path),
        )
        return state

    def extract_tokens(self) -> dict:
        """Find auth tokens, cookies, CSRF tokens in the current page."""
        self._require_page()
        tokens: dict[str, Any] = {"cookies": {}, "csrf": [], "jwt": [], "api_keys": []}

        cookies = self._page.context.cookies()
        for c in cookies:
            name_lower = c["name"].lower()
            if any(k in name_lower for k in ("session", "token", "auth", "jwt", "csrf", "xsrf")):
                tokens["cookies"][c["name"]] = {
                    "domain": c["domain"],
                    "httpOnly": c.get("httpOnly", False),
                    "secure": c.get("secure", False),
                    "sameSite": c.get("sameSite", ""),
                    "value_preview": c["value"][:20] + "..." if len(c["value"]) > 20 else c["value"],
                }

        page_content = self._page.content()

        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
        ]
        for pattern in csrf_patterns:
            for match in re.findall(pattern, page_content, re.IGNORECASE):
                tokens["csrf"].append(match[:40] + "..." if len(match) > 40 else match)

        jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        for match in re.findall(jwt_pattern, page_content):
            tokens["jwt"].append(match[:60] + "...")

        return tokens

    def close(self):
        if self._page:
            try:
                self._page.close()
            except Exception:
                pass
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
        self._custody.append("browser_session_closed", {
            "requests_captured": len(self._network_requests),
        })
        self._page = None
        self._browser = None
        self._playwright = None

    def _require_page(self):
        if not self._page:
            raise BrowserLoopError("No browser page — call start() first")

    def _screenshot_path(self) -> Path:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return self.state_dir / f"screenshot_{ts}.png"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()
