"""Multi-provider LLM gateway via LiteLLM.

Routes queries to alternative providers (DeepSeek, GLM, Kimi, OpenRouter,
Ollama) for vector brainstorming, second opinions, and CVE deep-dives.
All traffic is redacted before leaving the process.

Provider config lives in .pentest-state/providers.json:

    {
      "providers": {
        "deepseek": {"api_key": "sk-...", "default_model": "deepseek-chat"},
        "glm":      {"api_key": "...",    "default_model": "glm-4-plus"},
        "kimi":     {"api_key": "...",    "default_model": "moonshot-v1-128k"},
        "openrouter": {"api_key": "...", "default_model": "deepseek/deepseek-chat"},
        "ollama":   {"base_url": "http://localhost:11434", "default_model": "llama3.1"}
      },
      "routing": {
        "vector_brainstorm": "deepseek",
        "second_opinion": "glm",
        "cve_deepdive": "kimi",
        "fallback": "openrouter"
      }
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .redaction import redact_for_provider
    from .storage import read_json
except ImportError:
    from redaction import redact_for_provider
    from storage import read_json


PROVIDER_MAP = {
    "deepseek": {"litellm_prefix": "deepseek", "base_url": "https://api.deepseek.com"},
    "glm": {"litellm_prefix": "zhipuai", "base_url": "https://open.bigmodel.cn/api/paas/v4"},
    "kimi": {"litellm_prefix": "openai", "base_url": "https://api.moonshot.cn/v1"},
    "openrouter": {"litellm_prefix": "openrouter", "base_url": "https://openrouter.ai/api/v1"},
    "ollama": {"litellm_prefix": "ollama", "base_url": "http://localhost:11434"},
    "zai": {"litellm_prefix": "openai", "base_url": "https://api.z.ai/v1"},
}

QUERY_TYPES = {"vector_brainstorm", "second_opinion", "cve_deepdive", "general"}


@dataclass
class ProviderConfig:
    api_key: str = ""
    base_url: str = ""
    default_model: str = ""


@dataclass
class GatewayConfig:
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    routing: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, audit_dir: str | Path) -> GatewayConfig:
        path = Path(audit_dir) / ".pentest-state" / "providers.json"
        raw = read_json(path, {})
        if not raw:
            return cls()
        providers = {}
        for name, cfg in raw.get("providers", {}).items():
            providers[name] = ProviderConfig(
                api_key=cfg.get("api_key", ""),
                base_url=cfg.get("base_url", PROVIDER_MAP.get(name, {}).get("base_url", "")),
                default_model=cfg.get("default_model", ""),
            )
        return cls(providers=providers, routing=raw.get("routing", {}))

    def available_providers(self) -> list[str]:
        return [name for name, cfg in self.providers.items()
                if cfg.api_key or name == "ollama"]

    def resolve_provider(self, query_type: str) -> str | None:
        explicit = self.routing.get(query_type)
        if explicit and explicit in self.available_providers():
            return explicit
        fallback = self.routing.get("fallback")
        if fallback and fallback in self.available_providers():
            return fallback
        available = self.available_providers()
        return available[0] if available else None


@dataclass
class LLMResponse:
    provider: str
    model: str
    content: str
    usage: dict[str, int] = field(default_factory=dict)
    timestamp: str = ""
    redacted_input: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class LLMGateway:
    """Unified interface to alternative LLM providers."""

    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.config = GatewayConfig.load(audit_dir)
        self._litellm = None

    def _get_litellm(self):
        if self._litellm is None:
            try:
                import litellm
                litellm.drop_params = True
                self._litellm = litellm
            except ImportError:
                raise RuntimeError(
                    "litellm not installed. Run: pip install litellm"
                )
        return self._litellm

    def is_available(self) -> bool:
        return bool(self.config.available_providers())

    def list_providers(self) -> list[dict[str, str]]:
        result = []
        for name in self.config.available_providers():
            cfg = self.config.providers[name]
            result.append({
                "name": name,
                "model": cfg.default_model,
                "base_url": cfg.base_url or PROVIDER_MAP.get(name, {}).get("base_url", ""),
            })
        return result

    def query(
        self,
        prompt: str,
        *,
        query_type: str = "general",
        provider: str | None = None,
        model: str | None = None,
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        redact_input: bool = True,
    ) -> LLMResponse:
        litellm = self._get_litellm()

        resolved_provider = provider or self.config.resolve_provider(query_type)
        if not resolved_provider:
            raise RuntimeError("No provider configured or available")

        cfg = self.config.providers.get(resolved_provider)
        if not cfg:
            raise RuntimeError(f"Provider '{resolved_provider}' not in config")

        resolved_model = model or cfg.default_model
        if not resolved_model:
            raise RuntimeError(f"No model specified for provider '{resolved_provider}'")

        safe_prompt = redact_for_provider(prompt) if redact_input else prompt
        safe_system = redact_for_provider(system_prompt) if redact_input and system_prompt else system_prompt

        provider_info = PROVIDER_MAP.get(resolved_provider, {})
        litellm_prefix = provider_info.get("litellm_prefix", "openai")
        base_url = cfg.base_url or provider_info.get("base_url", "")

        if litellm_prefix in ("openai", "ollama"):
            model_id = f"{litellm_prefix}/{resolved_model}"
        else:
            model_id = f"{litellm_prefix}/{resolved_model}"

        messages = []
        if safe_system:
            messages.append({"role": "system", "content": safe_system})
        messages.append({"role": "user", "content": safe_prompt})

        kwargs: dict[str, Any] = {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if base_url:
            kwargs["api_base"] = base_url
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key

        response = litellm.completion(**kwargs)

        usage = {}
        if hasattr(response, "usage") and response.usage:
            usage = {
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(response.usage, "completion_tokens", 0),
                "total_tokens": getattr(response.usage, "total_tokens", 0),
            }

        content = response.choices[0].message.content if response.choices else ""

        return LLMResponse(
            provider=resolved_provider,
            model=resolved_model,
            content=content,
            usage=usage,
            redacted_input=redact_input,
        )

    def vector_brainstorm(
        self,
        stack: list[str],
        exhausted_vectors: list[str],
        capabilities: list[str],
        findings_summary: str = "",
    ) -> LLMResponse:
        prompt = VECTOR_BRAINSTORM_PROMPT.format(
            stack=", ".join(stack),
            exhausted="\n".join(f"- {v}" for v in exhausted_vectors) or "None yet",
            capabilities="\n".join(f"- {c}" for c in capabilities) or "None gained",
            findings=findings_summary or "No findings yet",
        )
        return self.query(
            prompt,
            query_type="vector_brainstorm",
            system_prompt=VECTOR_SYSTEM_PROMPT,
        )

    def second_opinion(
        self,
        finding_summary: str,
        evidence: str,
    ) -> LLMResponse:
        prompt = SECOND_OPINION_PROMPT.format(
            finding=finding_summary,
            evidence=evidence,
        )
        return self.query(
            prompt,
            query_type="second_opinion",
            system_prompt=SECOND_OPINION_SYSTEM,
        )

    def cve_deepdive(
        self,
        service: str,
        version: str,
        context: str = "",
    ) -> LLMResponse:
        prompt = CVE_DEEPDIVE_PROMPT.format(
            service=service,
            version=version,
            context=context or "No additional context",
        )
        return self.query(
            prompt,
            query_type="cve_deepdive",
            system_prompt=CVE_DEEPDIVE_SYSTEM,
            max_tokens=8192,
        )


VECTOR_SYSTEM_PROMPT = """\
You are a senior penetration tester reviewing an engagement's coverage.
Your job is to identify attack vectors that have NOT been tried yet.
Be specific: name the technique, the target component, and why it's worth trying.
Prioritize by likelihood of success given the current stack and capabilities.
Do NOT suggest vectors already in the exhausted list.
Output as a JSON array of objects: [{"vector": "...", "target": "...", \
"rationale": "...", "priority": "high|medium|low", "vuln_class": "..."}]"""

VECTOR_BRAINSTORM_PROMPT = """\
## Engagement State

**Tech stack:** {stack}

**Exhausted vectors (tried, failed or dead):**
{exhausted}

**Capabilities gained so far:**
{capabilities}

**Findings summary:**
{findings}

## Task

List attack vectors NOT yet tried that are realistic for this stack.
Focus on:
1. Stack-specific weaknesses (known vuln patterns for these technologies)
2. Chain opportunities (combining existing capabilities with new vectors)
3. Business logic angles (auth flows, payment, state machines)
4. Infrastructure vectors (misconfig, exposed services, default creds)
5. Supply chain / dependency vectors

Return JSON array only, no markdown wrapping."""

SECOND_OPINION_SYSTEM = """\
You are an independent security reviewer. Evaluate the finding below for:
1. Validity — is the evidence sufficient to confirm this?
2. Severity — is the CVSS/impact assessment accurate?
3. Exploitability — are there easier or more impactful exploitation paths?
4. False positive risk — could this be a non-issue?
Be concise and direct. If you disagree with the assessment, say why."""

SECOND_OPINION_PROMPT = """\
## Finding Summary
{finding}

## Evidence
{evidence}

Provide your independent assessment."""

CVE_DEEPDIVE_SYSTEM = """\
You are a vulnerability researcher. Given a service and version, identify:
1. All known CVEs affecting this exact version
2. Whether public exploits exist
3. Preconditions for exploitation (auth required? specific config?)
4. Recommended verification steps (non-destructive)
Output as JSON: [{{"cve_id": "...", "cvss": ..., "exploitable": true/false, \
"preconditions": "...", "verify_steps": ["..."]}}]"""

CVE_DEEPDIVE_PROMPT = """\
**Service:** {service}
**Version:** {version}
**Context:** {context}

List all relevant CVEs with exploitation details. JSON array only."""
