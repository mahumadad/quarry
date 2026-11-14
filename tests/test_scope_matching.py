"""Scope target-matching hardening (report §4).

Product rules fixed by these tests:
  - host-only matching (ports stripped, not part of scope);
  - a CIDR/range in a command is in scope only if fully contained in an
    in-scope network and not overlapping any out-of-scope entry (fail-closed);
  - ambiguous tokens that look like a host/IP are treated as targets
    (fail-closed), while clear local file args are not.
Known limitations deliberately NOT covered (documented in the report): bare
no-dot hosts (localhost), decimal/short-dotted IP forms, IDN normalization,
redirect-following and DNS rebinding.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from scope import Scope  # noqa: E402


@pytest.fixture()
def scope():
    s = Scope(authorization="signed-test-authorization")
    s.add_in_scope("10.0.0.0/24", "cidr")
    s.add_in_scope("in.com", "domain")
    s.add_in_scope("*.example.com", "wildcard")
    s.add_in_scope("https://app.test/api", "url")
    s.add_out_of_scope("10.0.9.9", "ip")              # outside the /24
    s.add_out_of_scope("admin.in.com", "domain")
    s.add_out_of_scope("https://in.com/private", "url")
    return s


# --- plain IP / domain / out precedence ------------------------------------

def test_plain_membership(scope):
    assert scope.is_in_scope("10.0.0.50")
    assert scope.is_in_scope("sub.in.com")
    assert not scope.is_in_scope("10.0.9.9")
    assert not scope.is_in_scope("admin.in.com")
    assert not scope.is_in_scope("10.1.0.1")


def test_out_of_scope_url_beats_in_scope_domain(scope):
    # in.com is an in-scope domain, but /private is explicitly out.
    assert not scope.is_in_scope("https://in.com/private/users")
    assert scope.is_in_scope("https://in.com/public")


# --- §4.1 CIDR / range containment -----------------------------------------

def test_cidr_target_must_be_contained(scope):
    assert scope.is_in_scope("10.0.0.0/24")       # equal to in-scope net
    assert scope.is_in_scope("10.0.0.128/25")     # subnet
    assert not scope.is_in_scope("10.0.0.0/8")    # superset — escapes scope
    assert not scope.is_in_scope("10.0.1.0/24")   # different net


def test_range_target_must_be_contained(scope):
    assert scope.is_in_scope("10.0.0.10-20")
    assert not scope.is_in_scope("10.0.0.10-10.0.1.5")


def test_cidr_overlapping_out_of_scope_blocked():
    s = Scope(authorization="x")
    s.add_in_scope("10.0.0.0/24", "cidr")
    s.add_out_of_scope("10.0.0.5", "ip")          # carved out of the /24
    assert not s.is_in_scope("10.0.0.0/24")       # covers the excluded .5
    assert s.is_in_scope("10.0.0.128/25")         # avoids .5


def test_cidr_command_escape_blocked(scope):
    ok, _ = scope.validate_command("nmap in.com 10.0.0.0/8")
    assert not ok


# --- §4.3 host/path split --------------------------------------------------

def test_remote_host_with_web_extension_is_checked(scope):
    ok, _ = scope.validate_command("curl in.com evil.com/index.php")
    assert not ok
    ok, _ = scope.validate_command("curl in.com admin.in.com/x.php")
    assert not ok


def test_in_scope_url_with_path_allowed(scope):
    ok, _ = scope.validate_command("curl https://in.com/x.php")
    assert ok


# --- §4.8 ports (host-only) ------------------------------------------------

def test_port_is_stripped(scope):
    assert scope.is_in_scope("in.com:443")
    ok, _ = scope.validate_command("curl http://in.com:8443/health")
    assert ok
    ok, _ = scope.validate_command("nmap evil.com:22")
    assert not ok


# --- §4.6 url entry matching -----------------------------------------------

def test_url_entry_path_matching(scope):
    assert scope.is_in_scope("https://app.test/api/users")
    assert not scope.is_in_scope("https://app.test/admin")
    assert not scope.is_in_scope("https://app.test/api/../admin")  # traversal


def test_exact_url_entry_not_self_blocked(scope):
    # Regression: the bare host must not be extracted separately and sink the URL.
    ok, _ = scope.validate_command("curl https://app.test/api")
    assert ok


# --- §4.7 wildcard on host only --------------------------------------------

def test_wildcard_matches_host_only(scope):
    assert scope.is_in_scope("https://sub.example.com/x")
    assert not scope.is_in_scope("http://evil.com/.example.com")


# --- §4.9 local file args are not targets ----------------------------------

def test_local_file_args_not_treated_as_targets(scope):
    assert scope.validate_command("python3 exploit.py in.com")[0]
    assert scope.validate_command("curl in.com --data-binary @secrets.env")[0]


def test_template_filenames_ignored():
    command = ("nuclei -u https://example.test -t /tmp/python-env-secret-exposed.yaml "
               "-t relative/graphql.api.yaml -jsonl")
    targets = Scope._extract_targets(command)
    assert "https://example.test" in targets
    assert not any(t.endswith((".yaml", ".yml", ".json", ".txt")) for t in targets), targets


# --- §4.2 alt IP formats (IPv6 / hex) --------------------------------------

def test_ipv6_literal_checked(scope):
    ok, _ = scope.validate_command("nmap fe80::1 in.com")
    assert not ok


def test_hex_ip_in_url_checked(scope):
    assert not scope.is_in_scope("http://0x0a090909/")  # 10.9.9.9, out of scope
