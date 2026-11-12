"""Reviewed Nuclei template catalog, static policy and AppProfile selection.

Only local, explicitly reviewed HTTP templates are eligible. The manifest is a
hash-locked snapshot: changing YAML without deliberately refreshing and
reviewing the manifest makes execution fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

try:
    from .app_profile import AppProfile
    from .storage import atomic_write_json
except ImportError:
    from app_profile import AppProfile
    from storage import atomic_write_json


RISK_PROFILES = {
    "safe": {"safe"},
    "authenticated": {"safe", "authenticated"},
    "sensitive-data": {"safe", "authenticated", "sensitive-data"},
    "state-changing": {"safe", "authenticated", "sensitive-data", "state-changing"},
    "oast": {"safe", "authenticated", "sensitive-data", "state-changing", "oast"},
}
RISKS = set(RISK_PROFILES)
LANGUAGE_STACKS = {"python", "nodejs", "ruby", "java", "php", "dotnet"}
ALLOWED_REQUEST_KEYS = {
    "method", "path", "headers", "body", "matchers", "matchers-condition",
    "extractors", "stop-at-first-match", "cookie-reuse",
}
ALIASES = {
    "node": "nodejs", "node.js": "nodejs", "express.js": "express",
    "next": "nextjs", "next.js": "nextjs", "nuxt": "nuxtjs", "nuxt.js": "nuxtjs",
    "asp.net": "aspnet", "asp.net-core": "aspnet", "dotnet": "aspnet",
    ".net": "aspnet", "ruby-on-rails": "rails", "ruby_on_rails": "rails",
    "spring-boot": "spring", "springboot": "spring", "gql": "graphql",
    "fast-api": "fastapi", "django-rest-framework": "django", "drf": "django",
}


class TemplatePolicyError(ValueError):
    """A template or manifest violates the reviewed execution contract."""


def _tokens(value: Any) -> set[str]:
    if isinstance(value, str):
        values = re.split(r"[,\s]+", value.lower())
    elif isinstance(value, (list, tuple, set)):
        values = [str(item).lower() for item in value]
    else:
        values = []
    return {ALIASES.get(item.strip(), item.strip()) for item in values if item.strip()}


def _profile_tokens(profile: AppProfile | dict[str, Any]) -> tuple[set[str], set[str]]:
    data = asdict(profile) if isinstance(profile, AppProfile) else profile
    stack: set[str] = set()
    for values in data.get("tech_stack", {}).values():
        stack |= _tokens(values)
    stack |= _tokens(data.get("features", []))
    stack |= _tokens(data.get("api", {}).get("style", ""))
    for endpoint in data.get("entry_points", []):
        url = str(endpoint.get("url", "")).lower()
        if "graphql" in url:
            stack.add("graphql")
    if data.get("payment_processing"):
        stack.add("payment")
    architecture = _tokens(data.get("architecture", {}).get("style", ""))
    architecture |= _tokens(data.get("architecture", {}).get("deployment", []))
    architecture |= _tokens(data.get("architecture", {}).get("frontend_rendering", ""))
    architecture |= _tokens(data.get("architecture", {}).get("async_workers", []))
    for key in ("multi_tenant", "serverless", "mobile_backend"):
        if data.get("architecture", {}).get(key):
            architecture.add(key.replace("_", "-"))
    if data.get("architecture", {}).get("api_gateway"):
        architecture.add("api-gateway")
        architecture |= _tokens(data["architecture"]["api_gateway"])
    return stack, architecture


class NucleiTemplateCatalog:
    def __init__(self, root: str | Path | None = None):
        self.root = (Path(root) if root else
                     Path(__file__).resolve().parent.parent / "references" / "nuclei-templates")
        self.root = self.root.resolve()
        # Keep administrative JSON outside the directory passed to Nuclei.
        self.manifest_file = self.root.parent / "nuclei-manifest.json"

    def _path(self, relative: str) -> Path:
        if not relative or Path(relative).is_absolute():
            raise TemplatePolicyError(f"Invalid template path: {relative!r}")
        candidate = (self.root / relative).resolve()
        if self.root not in candidate.parents or candidate.suffix != ".yaml":
            raise TemplatePolicyError(f"Template escapes catalog or is not YAML: {relative}")
        if (self.root / relative).is_symlink():
            raise TemplatePolicyError(f"Symlinked templates are not allowed: {relative}")
        return candidate

    def audit(self, path: str | Path) -> dict[str, Any]:
        source = Path(path)
        if not source.is_absolute():
            source = self._path(str(source))
        source = source.resolve()
        if self.root not in source.parents:
            raise TemplatePolicyError(f"Template outside catalog: {source}")
        relative = source.relative_to(self.root).as_posix()
        raw = source.read_bytes()
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise TemplatePolicyError(f"Invalid YAML {relative}: {exc}") from exc
        if not isinstance(data, dict) or set(data) != {"id", "info", "http"}:
            raise TemplatePolicyError(f"{relative}: only id, info and http are allowed")
        template_id = data.get("id")
        if not isinstance(template_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]+", template_id):
            raise TemplatePolicyError(f"{relative}: invalid template id")
        info = data.get("info") or {}
        metadata = info.get("metadata") or {}
        risk = metadata.get("risk", "")
        if risk not in RISKS or metadata.get("reviewed") is not True:
            raise TemplatePolicyError(f"{relative}: reviewed=true and a valid risk are required")
        if info.get("severity") not in {"info", "low", "medium", "high", "critical"}:
            raise TemplatePolicyError(f"{relative}: invalid severity")
        stacks = _tokens(metadata.get("stacks"))
        if not stacks:
            raise TemplatePolicyError(f"{relative}: at least one stack selector is required")
        requests = data.get("http")
        if not isinstance(requests, list) or not requests:
            raise TemplatePolicyError(f"{relative}: HTTP request list is required")
        for request in requests:
            self._audit_request(relative, template_id, risk, request)
        return {
            "id": template_id,
            "path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "severity": info["severity"],
            "risk": risk,
            "auth": metadata.get("auth", "none"),
            "stacks": sorted(stacks),
            "protocols": sorted(_tokens(metadata.get("protocols", "http"))),
            "architectures": sorted(_tokens(metadata.get("architectures"))),
            "coverage": sorted(_tokens(metadata.get("coverage"))),
            "fixture": metadata.get("fixture", ""),
            "requests": sum(len(request.get("path", [])) for request in requests),
        }

    def _audit_request(self, relative: str, template_id: str, risk: str,
                       request: Any) -> None:
        if not isinstance(request, dict) or not set(request) <= ALLOWED_REQUEST_KEYS:
            raise TemplatePolicyError(f"{relative}: unsupported or unsafe HTTP request keys")
        if set(request) & {"raw", "redirects", "max-redirects", "self-contained"}:
            raise TemplatePolicyError(f"{relative}: redirects/raw/self-contained requests are forbidden")
        method = str(request.get("method", "GET")).upper()
        if method not in {"GET", "POST"}:
            raise TemplatePolicyError(f"{relative}: method {method} is not read-only")
        body = str(request.get("body", ""))
        headers = request.get("headers", {})
        if not isinstance(headers, dict):
            raise TemplatePolicyError(f"{relative}: headers must be a mapping")
        for name, value in headers.items():
            if str(name).lower() == "host":
                raise TemplatePolicyError(f"{relative}: Host header override is forbidden")
            if "{{" in str(value):
                raise TemplatePolicyError(f"{relative}: dynamic header values are forbidden")
        if "{{" in body:
            raise TemplatePolicyError(f"{relative}: dynamic body values are forbidden")
        if method == "POST":
            if risk not in {"safe", "authenticated"} or not template_id.startswith("graphql-"):
                raise TemplatePolicyError(f"{relative}: POST is restricted to reviewed read-only GraphQL checks")
            if re.search(r"\b(mutation|subscription)\b", body, re.IGNORECASE):
                raise TemplatePolicyError(f"{relative}: state-changing GraphQL operation rejected")
        paths = request.get("path")
        if not isinstance(paths, list) or not paths:
            raise TemplatePolicyError(f"{relative}: explicit path list required")
        for value in paths:
            if not isinstance(value, str) or not value.startswith("{{BaseURL}}/"):
                raise TemplatePolicyError(f"{relative}: paths must stay below BaseURL")
            suffix = value.removeprefix("{{BaseURL}}")
            if "{{" in suffix or "}}" in suffix or ".." in suffix or "\\" in suffix:
                raise TemplatePolicyError(f"{relative}: dynamic or traversing path rejected")
            if re.search(r"https?://", suffix, re.IGNORECASE):
                raise TemplatePolicyError(f"{relative}: external destination rejected")
        if request.get("matchers-condition") != "and":
            raise TemplatePolicyError(f"{relative}: matchers-condition must be and")
        matchers = request.get("matchers")
        if not isinstance(matchers, list):
            raise TemplatePolicyError(f"{relative}: matchers required")
        kinds = {item.get("type") for item in matchers if isinstance(item, dict)}
        if not kinds <= {"status", "word", "regex"}:
            raise TemplatePolicyError(f"{relative}: only status/word/regex matchers are reviewed")
        if "status" not in kinds or not kinds & {"word", "regex"}:
            raise TemplatePolicyError(f"{relative}: status plus content matchers required")

    def discover(self) -> dict[str, Any]:
        records = [self.audit(path) for path in sorted(self.root.rglob("*.yaml"))]
        ids = [record["id"] for record in records]
        if len(ids) != len(set(ids)):
            duplicates = sorted({item for item in ids if ids.count(item) > 1})
            raise TemplatePolicyError(f"Duplicate template ids: {duplicates}")
        return {"schema_version": 1, "templates": records}

    def refresh(self) -> dict[str, Any]:
        manifest = self.discover()
        atomic_write_json(self.manifest_file, manifest)
        return manifest

    def load(self, verify_hashes: bool = True) -> dict[str, Any]:
        if not self.manifest_file.exists():
            raise TemplatePolicyError("Missing manifest; review templates and refresh it first")
        try:
            manifest = json.loads(self.manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TemplatePolicyError(f"Unreadable manifest: {exc}") from exc
        if manifest.get("schema_version") != 1 or not isinstance(manifest.get("templates"), list):
            raise TemplatePolicyError("Unsupported manifest schema")
        expected = self.discover() if verify_hashes else None
        if expected is not None and manifest != expected:
            raise TemplatePolicyError(
                "Manifest mismatch: template content/metadata changed or an unreviewed file was added")
        ids = [item.get("id") for item in manifest["templates"]]
        if len(ids) != len(set(ids)) or any(not item for item in ids):
            raise TemplatePolicyError("Manifest contains duplicate or empty ids")
        return manifest

    def select(self, profile: AppProfile | dict[str, Any], risk: str = "safe") -> dict[str, Any]:
        if risk not in RISK_PROFILES:
            raise TemplatePolicyError(f"Unknown risk profile: {risk}")
        manifest = self.load()
        profile_data = asdict(profile) if isinstance(profile, AppProfile) else profile
        stack, architecture = _profile_tokens(profile)
        selected, skipped = [], []
        allowed = RISK_PROFILES[risk]
        for record in manifest["templates"]:
            reasons = []
            record_stacks = set(record["stacks"])
            specific_stacks = record_stacks - LANGUAGE_STACKS
            # A language is supporting evidence, never enough to select every
            # framework written in that language (python != django+flask+fastapi).
            overlap = stack & (specific_stacks or record_stacks)
            if not overlap:
                continue
            if record["risk"] not in allowed:
                reasons.append(f"risk {record['risk']} excluded by {risk} profile")
            if record["risk"] == "authenticated":
                mechanism = profile_data.get("auth", {}).get("mechanism", "")
                if not mechanism or mechanism == "none":
                    reasons.append("authenticated profile has no identity")
            required_arch = set(record["architectures"])
            if required_arch and not architecture & required_arch:
                reasons.append("architecture unconfirmed or not applicable")
            item = dict(record)
            item["selection_evidence"] = sorted(overlap)
            if reasons:
                item["skip_reasons"] = reasons
                skipped.append(item)
            else:
                selected.append(item)
        known_stacks = {value for record in manifest["templates"] for value in record["stacks"]}
        gaps = []
        if not stack:
            gaps.append({"type": "stack_unknown", "instruction": "Fingerprint before claiming coverage"})
        for value in sorted(stack - known_stacks - {"http", "rest", "api", "mixed", "payment"}):
            gaps.append({"type": "no_reviewed_custom_template", "stack": value})
        return {
            "schema_version": 1,
            "risk_profile": risk,
            "profile_target": profile_data.get("target", ""),
            "detected_stacks": sorted(stack),
            "detected_architecture": sorted(architecture),
            "selected": selected,
            "skipped": skipped,
            "coverage_gaps": gaps,
            "counts": {"selected": len(selected), "skipped": len(skipped), "gaps": len(gaps)},
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and inspect reviewed Nuclei templates")
    parser.add_argument("action", choices=("validate", "refresh", "select"))
    parser.add_argument("--root", default="")
    parser.add_argument("--profile", default="", help="AppProfile JSON for select")
    parser.add_argument("--risk", default="safe", choices=sorted(RISK_PROFILES))
    args = parser.parse_args()
    catalog = NucleiTemplateCatalog(args.root or None)
    if args.action == "refresh":
        result = catalog.refresh()
    elif args.action == "validate":
        result = catalog.load()
    else:
        if not args.profile:
            parser.error("select requires --profile")
        result = catalog.select(json.loads(Path(args.profile).read_text()), args.risk)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
