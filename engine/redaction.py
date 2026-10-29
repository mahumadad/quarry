"""Central secret redaction for human-facing output and exported evidence."""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization",
                  "x-api-key", "api_key", "apikey", "password", "passwd", "secret",
                  "token", "access_token", "refresh_token", "session", "sessionid"}
BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
KEY_VALUE_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|x-api-key|api[_-]?key|password|secret|"
    r"access[_-]?token|refresh[_-]?token|sessionid)(\s*[:=]\s*)([^\s,;&]+)")


def redact_text(text: str) -> str:
    text = BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    return KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
