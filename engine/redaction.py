"""Bidirectional secret redaction — output to humans AND input to LLM providers.

Redacts secrets in two directions:
- Output: findings, reports, exported evidence (original purpose)
- Input: prompts and context sent to external LLM providers via llm_gateway
  (prevents leaking target tokens/cookies/keys to DeepSeek, GLM, etc.)
"""
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
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
IP_PORT_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?\b")


def redact_text(text: str) -> str:
    text = BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = JWT_RE.sub("[JWT_REDACTED]", text)
    return KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


def redact_for_provider(text: str, anonymize_ips: bool = True) -> str:
    """Heavier redaction for text leaving to external LLM providers."""
    text = redact_text(text)
    if anonymize_ips:
        seen: dict[str, str] = {}
        counter = [0]

        def _replace_ip(m: re.Match) -> str:
            ip = m.group(1)
            if ip.startswith(("10.", "127.", "192.168.", "172.")) or ip == "0.0.0.0":
                return m.group(0)
            if ip not in seen:
                counter[0] += 1
                seen[ip] = f"[HOST_{counter[0]}]"
            port = m.group(2) or ""
            return f"{seen[ip]}{port}"

        text = IP_PORT_RE.sub(_replace_ip, text)
    return text


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
