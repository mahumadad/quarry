"""Tests for the extended FINDING_ORACLES set and chain composition.

Covers the 13 new oracle classes (jwt-forgery, oauth-misconfig,
saml-forgery, nosqli, graphql-introspection, mass-assignment,
subdomain-takeover, host-header-injection, cache-poisoning,
http-smuggling, prototype-pollution, ldap-injection,
password-reset-poisoning), their hunt-skill slug aliases, and the
end-to-end chains they unlock.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.chain_exploit import (  # noqa: E402
    FINDING_ORACLES,
    GOAL_CAPABILITIES,
    ChainExploitEngine,
)


def engine() -> ChainExploitEngine:
    return ChainExploitEngine(tempfile.mkdtemp())


NEW_ORACLES = {
    "jwt-forgery", "oauth-misconfig", "saml-forgery", "nosqli",
    "graphql-introspection", "mass-assignment", "subdomain-takeover",
    "host-header-injection", "cache-poisoning", "http-smuggling",
    "prototype-pollution", "ldap-injection", "password-reset-poisoning",
}


def test_new_oracles_present():
    for name in NEW_ORACLES:
        assert name in FINDING_ORACLES, f"missing oracle {name}"
        spec = FINDING_ORACLES[name]
        assert spec["produces"], f"{name} produces nothing"
        assert spec["oracle"]["check"], f"{name} has no oracle check"
        assert spec["evidence_keys"], f"{name} has no evidence keys"


def test_every_oracle_wellformed():
    for name, spec in FINDING_ORACLES.items():
        assert isinstance(spec["produces"], list), name
        assert isinstance(spec["consumes"], list), name
        for cap in spec["produces"] + spec["consumes"]:
            assert isinstance(cap, str) and cap, name
        # consumed capabilities must be producible by someone (else the
        # edge can never close) — data-flow integrity.
    producible = {c for s in FINDING_ORACLES.values() for c in s["produces"]}
    for name, spec in FINDING_ORACLES.items():
        for cap in spec["consumes"]:
            assert cap in producible, f"{name} consumes {cap} which no oracle produces"


SLUG_ALIASES = {
    "jwt": "jwt-forgery",
    "oauth": "oauth-misconfig",
    "saml": "saml-forgery",
    "nosqli": "nosqli",
    "graphql": "graphql-introspection",
    "mass-assignment": "mass-assignment",
    "subdomain-takeover": "subdomain-takeover",
    "host-header": "host-header-injection",
    "cache-poisoning": "cache-poisoning",
    "http-smuggling": "http-smuggling",
    "prototype-pollution": "prototype-pollution",
    "ldap-xpath-injection": "ldap-injection",
    "password-reset": "password-reset-poisoning",
    "2fa-bypass": "auth-bypass",
    "403-bypass": "privilege-escalation",
}


def test_hunt_slug_aliases_resolve():
    e = ChainExploitEngine.__new__(ChainExploitEngine)
    for slug, oracle in SLUG_ALIASES.items():
        resolved = e._oracle_class({"vuln_class": slug})
        assert resolved == oracle, f"{slug} -> {resolved}, expected {oracle}"
        assert resolved in FINDING_ORACLES, f"{resolved} not an oracle"


def test_chain_jwt_to_mass_assignment():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "jwt", "title": "JWT none algorithm"},
        {"id": "f2", "vuln_class": "mass-assignment", "title": "role injection"},
    ])
    assert any(c.goal_reached == "admin_session" for c in chains)
    assert all(c.combined_severity in ("high", "critical") for c in chains)


def test_chain_oauth_to_mass_assignment():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "oauth", "title": "redirect_uri flaw"},
        {"id": "f2", "vuln_class": "mass-assignment", "title": "isAdmin"},
    ])
    assert any(c.goal_reached == "admin_session" for c in chains)


def test_chain_password_reset_to_credential_reuse():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "password-reset", "title": "reset poison"},
        {"id": "f2", "vuln_class": "credential-reuse", "title": "reuse"},
    ])
    assert any(c.goal_reached == "admin_session" for c in chains)


def test_chain_saml_to_privesc():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "saml", "title": "signature wrapping"},
        {"id": "f2", "vuln_class": "privesc", "title": "role change"},
    ])
    assert any(c.goal_reached == "admin_session" for c in chains)


def test_chain_nosqli_to_idor():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "nosqli", "title": "$ne operator"},
        {"id": "f2", "vuln_class": "idor", "title": "cross-user read"},
    ])
    assert any(c.goal_reached == "data_store" for c in chains)


def test_chain_smuggling_to_cloud():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "http-smuggling", "title": "CL.TE"},
        {"id": "f2", "vuln_class": "ssrf", "title": "internal fetch"},
        {"id": "f3", "vuln_class": "cloud-metadata-ssrf", "title": "IMDS"},
    ])
    assert any(c.goal_reached == "credential:cloud_key" for c in chains)
    assert any(c.combined_severity == "critical" for c in chains)


def test_chain_ldap_to_credential_reuse():
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "ldap-injection", "title": "filter bypass"},
        {"id": "f2", "vuln_class": "credential-reuse", "title": "reuse"},
    ])
    assert any(c.goal_reached == "admin_session" for c in chains)


def test_classic_chains_still_compose():
    """The pre-existing kill chains must keep working after the extension."""
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "ssrf", "title": "ssrf"},
        {"id": "f2", "vuln_class": "cloud-metadata-ssrf", "title": "imds"},
    ])
    assert any(c.goal_reached == "credential:cloud_key" for c in chains)
    # xxe -> cloud-metadata-ssrf was the other historical closable chain
    # (xxe produces internal_service, cloud-metadata consumes it).
    chains = engine().compose_chains([
        {"id": "f1", "vuln_class": "xxe", "title": "xxe"},
        {"id": "f2", "vuln_class": "cloud-metadata-ssrf", "title": "imds"},
    ])
    assert chains, "xxe->cloud-metadata chain lost"


def test_goals_are_reachable():
    """Every GOAL_CAPABILITY must be producible by at least one oracle."""
    producible = {c for s in FINDING_ORACLES.values() for c in s["produces"]}
    for goal in GOAL_CAPABILITIES:
        assert goal in producible, f"goal {goal} unreachable"


def test_new_oracles_have_no_orphan_capabilities():
    """New oracle capabilities should use the existing vocabulary."""
    known_prefixes = ("credential:", "network_access:")
    known_caps = {"internal_service", "code_exec", "file_read", "file_write",
                  "data_store", "admin_session", "identity"}
    for name in NEW_ORACLES:
        for cap in FINDING_ORACLES[name]["produces"] + FINDING_ORACLES[name]["consumes"]:
            ok = cap in known_caps or cap.startswith(known_prefixes)
            assert ok, f"{name} uses unknown capability {cap}"
