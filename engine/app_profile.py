"""Application profiling — mandatory pre-hunt target intelligence.

No agent fires a payload until an AppProfile exists for the target.
The profile captures: tech stack, auth mechanism, API style, user roles,
AI/LLM features, and crown jewels (high-value targets).

Persists to .pentest-state/app-profile.json.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AuthInfo:
    mechanism: str = ""  # session_cookie, jwt, oauth2, api_key, basic, saml, none
    mfa_present: bool = False
    password_reset: bool = False
    registration_open: bool = False
    sso_providers: list[str] = field(default_factory=list)
    token_storage: str = ""  # cookie, localStorage, header
    session_duration: str = ""


@dataclass
class APIInfo:
    style: str = ""  # rest, graphql, grpc, soap, websocket, mixed
    auth_method: str = ""  # bearer, api_key, cookie, none
    documentation_exposed: bool = False
    documentation_url: str = ""
    versioning: str = ""  # url_path, header, query
    rate_limiting: bool = False
    pagination: str = ""


@dataclass
class AppProfile:
    target: str = ""
    profiled_at: str = ""
    tech_stack: dict = field(default_factory=lambda: {
        "frontend": [],
        "backend": [],
        "server": [],
        "cdn_waf": [],
        "database": [],
        "cloud_provider": "",
        "languages": [],
        "frameworks": [],
    })
    auth: AuthInfo = field(default_factory=AuthInfo)
    api: APIInfo = field(default_factory=APIInfo)
    architecture: dict = field(default_factory=lambda: {
        "style": "",  # monolith, microservices, modular-monolith, unknown
        "deployment": [],  # traditional, containers, kubernetes, serverless, edge
        "frontend_rendering": "",  # spa, ssr, ssg, mpa, hybrid
        "api_gateway": "",
        "async_workers": [],
        "multi_tenant": False,
        "serverless": False,
        "mobile_backend": False,
    })
    user_roles: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    ai_features: list[str] = field(default_factory=list)
    file_upload: bool = False
    payment_processing: bool = False
    admin_panel: str = ""
    crown_jewels: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.profiled_at:
            self.profiled_at = datetime.now(timezone.utc).isoformat()
        if isinstance(self.auth, dict):
            self.auth = AuthInfo(**self.auth)
        if isinstance(self.api, dict):
            self.api = APIInfo(**self.api)


class AppProfileStore:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.profile_file = self.state_dir / "app-profile.json"
        self._profile: AppProfile | None = None
        self._load()

    def _load(self):
        if self.profile_file.exists():
            data = json.loads(self.profile_file.read_text())
            self._profile = AppProfile(**data)

    def _save(self):
        if self._profile is None:
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.profile_file.write_text(json.dumps(asdict(self._profile), indent=2))

    def exists(self) -> bool:
        return self._profile is not None

    def create(self, target: str) -> AppProfile:
        self._profile = AppProfile(target=target)
        self._save()
        return self._profile

    def get(self) -> AppProfile | None:
        return self._profile

    def update(self, **kwargs) -> AppProfile | None:
        if self._profile is None:
            return None
        for key, value in kwargs.items():
            if hasattr(self._profile, key):
                setattr(self._profile, key, value)
        self._save()
        return self._profile

    def add_entry_point(self, url: str, method: str = "GET",
                        auth_required: bool = False, params: list[str] | None = None,
                        notes: str = "") -> bool:
        if self._profile is None:
            return False
        self._profile.entry_points.append({
            "url": url,
            "method": method,
            "auth_required": auth_required,
            "params": params or [],
            "notes": notes,
        })
        self._save()
        return True

    def add_crown_jewel(self, description: str) -> bool:
        if self._profile is None:
            return False
        self._profile.crown_jewels.append(description)
        self._save()
        return True

    def hunting_ready(self) -> tuple[bool, list[str]]:
        """Check if profile is complete enough to begin hunting."""
        if self._profile is None:
            return False, ["No app profile exists — run profiling first"]
        issues = []
        if not self._profile.tech_stack.get("backend"):
            issues.append("Backend tech stack unknown")
        if not self._profile.auth.mechanism:
            issues.append("Auth mechanism not identified")
        if not self._profile.entry_points:
            issues.append("No entry points cataloged")
        if not self._profile.crown_jewels:
            issues.append("Crown jewels not identified — what is the highest-value target?")
        return len(issues) == 0, issues

    def to_dict(self) -> dict:
        if self._profile is None:
            return {}
        return asdict(self._profile)
