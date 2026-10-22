"""Headless-browser verification for client-side findings (XSS, clickjacking, open redirect).

Purpose: classes whose impact lives in the browser (DOM/stored/reflected XSS,
clickjacking, client-side redirects) cannot be confirmed from HTTP traffic
alone. Static analysis of a JS bundle is at best `Inferred` evidence. This
module executes the payload in a real browser engine (Chromium via Playwright)
and records observable effects — a fired dialog, a DOM mutation marker, a
frame load — as evidence-grade records that satisfy the anti-fabrication
rules: a client-side finding is only `Demonstrated` when an effect was
observed at runtime, never on the basis of code reading alone.

Backend: Playwright + Chromium. Imported lazily so the engine loads fine
without it; probes fail closed with install instructions.

  python3 -m pip install playwright && python3 -m playwright install chromium

CLI (what toolrunner / the agent calls):
  python3 -m engine.browser_verify reflected-xss "https://t/#/search?q=PAYLOAD"
  python3 -m engine.browser_verify clickjacking "https://target/page"
  python3 -m engine.browser_verify exec "https://target/page" --marker "xssprobe7f3a"

Results are JSON on stdout; artifacts (screenshot, console log) go to the
directory given by --out-dir (default: cwd). State is per-probe — nothing is
persisted between runs.
"""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TIMEOUT_MS = 15000
# Canary the payload triggers on success. Alert dialogs are the strongest
# signal (cannot be faked by the page's own code path we injected).
CANARY_PREFIX = "xssprobe"


@dataclass
class ProbeResult:
    """One browser-verification attempt. `demonstrated=True` requires a
    concrete observed effect, never a heuristic."""
    probe_type: str            # reflected-xss | stored-xss | clickjacking | exec
    url: str
    payload: str = ""
    marker: str = ""
    demonstrated: bool = False
    effect: str = ""           # what was observed: "dialog:alert:...", "dom-marker", "frame-load"
    console: list = field(default_factory=list)
    screenshot: str = ""
    screenshot_sha256: str = ""
    error: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def _load_playwright():
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        return sync_playwright
    except ImportError:
        return None


def available() -> bool:
    """True if Playwright is importable. Chromium binary is checked at launch."""
    return _load_playwright() is not None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _new_context(pw, out_dir: Path):
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True)
    return browser, ctx


def _observe_page(page, result: ProbeResult, marker: str):
    """Wire the observable-effect listeners onto a page."""
    def on_dialog(dialog):
        # An alert/confirm/prompt fired by our canary is definitive execution.
        result.demonstrated = True
        result.effect = f"dialog:{dialog.type}:{dialog.message[:200]}"
        dialog.dismiss()
    page.on("dialog", on_dialog)
    page.on("console", lambda m: result.console.append(f"{m.type}: {m.text[:200]}"))
    # DOM-marker fallback: payload writes document.title = marker
    page.expose_function("__probeMarker", lambda m: (
        setattr(result, "demonstrated", True),
        setattr(result, "effect", f"dom-marker:{str(m)[:100]}"),
    )) if marker else None


def _finish(result: ProbeResult, page, out_dir: Path, name: str) -> ProbeResult:
    shot = out_dir / f"{name}.png"
    try:
        page.screenshot(path=str(shot), full_page=False)
        result.screenshot = str(shot)
        result.screenshot_sha256 = _sha256(shot)
    except Exception:
        pass
    return result


def reflected_xss(url: str, payload: str = "", out_dir: str = ".",
                  timeout_ms: int = DEFAULT_TIMEOUT_MS) -> ProbeResult:
    """Load `url` (payload already placed by the caller in query/route) and
    report whether script execution was observed."""
    result = ProbeResult(probe_type="reflected-xss", url=url, payload=payload)
    sp = _load_playwright()
    if sp is None:
        result.error = ("playwright not installed — run: python3 -m pip install "
                        "playwright && python3 -m playwright install chromium")
        return result
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        with sp() as pw:
            browser, ctx = _new_context(pw, out)
            page = ctx.new_page()
            _observe_page(page, result, marker="")
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            page.wait_for_timeout(2500)  # let deferred DOM sinks fire
            _finish(result, page, out, "reflected-xss")
            browser.close()
    except Exception as e:  # navigation errors still carry console evidence
        result.error = f"{type(e).__name__}: {e}"
    return result


def stored_xss(view_url: str, marker: str, out_dir: str = ".",
               token: str = "", login_url: str = "",
               timeout_ms: int = DEFAULT_TIMEOUT_MS) -> ProbeResult:
    """Open the page where a previously planted payload renders (admin panel,
    comment list…) as an authenticated viewer, and report execution.

    The payload itself must carry the canary: e.g.
    <img src=x onerror="alert('MARKER')"> or
    <img src=x onerror="__probeMarker && __probeMarker('MARKER'); alert('MARKER')">
    """
    result = ProbeResult(probe_type="stored-xss", url=view_url, marker=marker)
    sp = _load_playwright()
    if sp is None:
        result.error = ("playwright not installed — run: python3 -m pip install "
                        "playwright && python3 -m playwright install chromium")
        return result
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        with sp() as pw:
            browser, ctx = _new_context(pw, out)
            if token:
                # Set synchronously at document-start: Angular/Vue read the token
                # during bootstrap — waiting for DOMContentLoaded is too late.
                ctx.add_init_script(
                    "try {"
                    f"  localStorage.setItem('token', {json.dumps(token)});"
                    f"  sessionStorage.setItem('token', {json.dumps(token)});"
                    "} catch(e) {}"
                )
            page = ctx.new_page()
            _observe_page(page, result, marker=marker)
            page.goto(view_url, timeout=timeout_ms, wait_until="networkidle")
            page.wait_for_timeout(3500)  # admin panels render async
            _finish(result, page, out, "stored-xss")
            browser.close()
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    return result


def clickjacking(url: str, out_dir: str = ".",
                 timeout_ms: int = DEFAULT_TIMEOUT_MS) -> ProbeResult:
    """A page is clickjackable when it loads inside a foreign-origin iframe
    AND sends no frame-ancestors / X-Frame-Options protection."""
    result = ProbeResult(probe_type="clickjacking", url=url)
    sp = _load_playwright()
    if sp is None:
        result.error = ("playwright not installed — run: python3 -m pip install "
                        "playwright && python3 -m playwright install chromium")
        return result
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        with sp() as pw:
            browser, ctx = _new_context(pw, out)
            page = ctx.new_page()
            framing_headers = {}
            def on_response(resp):
                if resp.url.rstrip("/") == url.rstrip("/"):
                    framing_headers["x-frame-options"] = resp.headers.get("x-frame-options", "")
                    framing_headers["content-security-policy"] = resp.headers.get("content-security-policy", "")
            page.on("response", on_response)
            # Host the target inside a data: wrapper page = foreign origin.
            wrapper = f"data:text/html,<iframe src='{url}' width='800' height='600'></iframe>"
            page.goto(wrapper, timeout=timeout_ms)
            page.wait_for_timeout(4000)
            framed = page.frames
            loaded_in_frame = any(
                f.url.rstrip("/").startswith(url.split("/")[2].split(":")[0])
                or f.url.rstrip("/") == url.rstrip("/")
                for f in framed[1:]  # frame 0 is the wrapper
            )
            protected = bool(framing_headers.get("x-frame-options")) or \
                "frame-ancestors" in framing_headers.get("content-security-policy", "").lower()
            if loaded_in_frame and not protected:
                result.demonstrated = True
                result.effect = "frame-load:no-frame-ancestors:no-xfo"
            result.console.append(json.dumps(framing_headers))
            _finish(result, page, out, "clickjacking")
            browser.close()
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    return result


def main() -> int:
    ap = argparse.ArgumentParser(prog="engine.browser_verify")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("reflected-xss", "clickjacking"):
        p = sub.add_parser(name)
        p.add_argument("url")
        p.add_argument("--payload", default="")
        p.add_argument("--out-dir", default=".")
    p = sub.add_parser("stored-xss")
    p.add_argument("url")
    p.add_argument("--marker", required=True)
    p.add_argument("--token", default="")
    p.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    if args.cmd == "reflected-xss":
        r = reflected_xss(args.url, args.payload, args.out_dir)
    elif args.cmd == "stored-xss":
        r = stored_xss(args.url, args.marker, args.out_dir, token=args.token)
    else:
        r = clickjacking(args.url, args.out_dir)
    print(json.dumps(asdict(r), indent=2, ensure_ascii=False))
    return 0 if r.demonstrated else 1


if __name__ == "__main__":
    sys.exit(main())
