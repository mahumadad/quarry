"""Scope/time/approval enforcing HTTP client with complete evidence capture."""
from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from .artifacts import ArtifactStore
    from .policy import PolicyDenied, PolicyEngine, canonical_url_target
except ImportError:
    from artifacts import ArtifactStore
    from policy import PolicyDenied, PolicyEngine, canonical_url_target


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ProtectedHTTPClient:
    """No request leaves the process before policy validation; redirects are explicit."""
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method: str, url: str, headers: dict | None = None,
                body: bytes | None = None, timeout: float = 15, dangerous: bool = False,
                approved_digest: str = "", run_id: str = "manual", task_id: str = "http") -> dict[str, Any]:
        target = canonical_url_target(url)
        policy = PolicyEngine(self.audit_dir)
        policy.authorize(f"{method} {url} {body!r}", [target], dangerous, approved_digest)
        request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        response_body = b""
        status = 0
        response_headers: dict[str, str] = {}
        error = ""
        try:
            with self.opener.open(request, timeout=min(timeout, 120)) as response:
                status = response.status
                response_headers = dict(response.headers.items())
                response_body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            response_body = exc.read()
            if status in {301, 302, 303, 307, 308}:
                error = "redirect blocked; validate and authorize the new target explicitly"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            # A dangerous approval authorizes one network attempt, successful or not.
            if dangerous:
                policy.consume(approved_digest)
        store = ArtifactStore(self.audit_dir)
        metadata = {"method": method, "url": url, "status": status, "error": error}
        request_text = f"{method} {url}\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        request_text += "\n\n" + (body or b"").decode("utf-8", errors="replace")
        request_artifact = store.capture(run_id, task_id, "request.http", request_text, metadata=metadata)
        response_text = "\n".join(f"{k}: {v}" for k, v in response_headers.items()) + "\n\n"
        response_artifact = store.capture(run_id, task_id, "response.http",
            response_text.encode() + response_body, complete=not error, metadata=metadata)
        return {"status": status, "headers": response_headers, "body": response_body,
                "error": error, "request_artifact": request_artifact,
                "response_artifact": response_artifact}
