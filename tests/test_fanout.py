"""Fan-out recon is scope-gated like every other command runner.

Freezes that an out-of-scope recon command is blocked BEFORE it spawns a
process, that an in-scope command reaches the spawn, and that outside an
engagement the gate is a no-op (same contract as the PreToolUse hook and the
sync/async runners). subprocess.run is faked so no real recon tool ever runs.
"""
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import engine.fanout as fanout  # noqa: E402
from engine.fanout import FanOutEngine, ReconTask  # noqa: E402
from engine.timeguard import TimeWindowGuard  # noqa: E402


@pytest.fixture()
def no_real_subprocess(monkeypatch):
    """Record spawns and return a benign result instead of running anything."""
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return types.SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(fanout.subprocess, "run", fake_run)
    return calls


@pytest.fixture()
def engagement(tmp_path):
    state = tmp_path / ".pentest-state"
    state.mkdir()
    (state / "scope.json").write_text(json.dumps({
        "in_scope": [{"pattern": "target.example.com", "type": "domain"}],
        "out_of_scope": [],
        "authorization": "signed RoE",
    }))
    TimeWindowGuard(str(tmp_path)).configure(
        windows=[], timezone="UTC",
        expires_at="2027-01-01T00:00:00+00:00")
    return tmp_path


def test_out_of_scope_recon_blocked(engagement, no_real_subprocess):
    engine = FanOutEngine(audit_dir=str(engagement))
    res = engine._run_task(ReconTask(name="nmap", command="nmap evil.attacker.com"))
    assert res.error.startswith("policy"), res.error
    assert no_real_subprocess == []  # never spawned


def test_in_scope_recon_reaches_spawn(engagement, no_real_subprocess):
    engine = FanOutEngine(audit_dir=str(engagement))
    res = engine._run_task(ReconTask(name="nmap", command="nmap target.example.com"))
    assert not res.error
    assert no_real_subprocess == ["nmap target.example.com"]  # gate allowed it


def test_no_engagement_is_noop(tmp_path, no_real_subprocess):
    engine = FanOutEngine(audit_dir=str(tmp_path))  # no .pentest-state
    res = engine._run_task(ReconTask(name="x", command="nmap evil.attacker.com"))
    assert not res.error.startswith("policy"), res.error
    assert no_real_subprocess == ["nmap evil.attacker.com"]


def test_pacing_throttles_recon_commands(tmp_path, no_real_subprocess):
    # A pacing profile rewrites the preset commands to carry a rate ceiling;
    # the default (off) leaves them exactly as the presets define them.
    paced = FanOutEngine(audit_dir=str(tmp_path), pacing="quiet")
    paced.recon_blast("target.example.com", ["port-scan"])
    assert any("--max-rate 5" in c for c in no_real_subprocess)

    no_real_subprocess.clear()
    default = FanOutEngine(audit_dir=str(tmp_path))  # pacing defaults to off
    default.recon_blast("target.example.com", ["port-scan"])
    assert no_real_subprocess and not any(
        "--max-rate" in c for c in no_real_subprocess)
