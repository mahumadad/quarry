"""Noise governor — an operator-chosen aggression dial, not a reactive backoff.

The governor turns a profile (off/quiet/balanced/aggressive) into the rate
flags each tool understands, and rewrites a command to carry them WITHOUT
clobbering a limit the command already sets. `off` injects nothing, so a
default engagement behaves exactly as before.
"""
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.pacing import (PROFILE_NAMES, apply_to_command,  # noqa: E402
                           delay_advice, get_profile, nuclei_knobs, rate_flags)


def test_profiles_present():
    assert set(PROFILE_NAMES) == {"off", "quiet", "balanced", "aggressive"}
    for name in PROFILE_NAMES:
        get_profile(name)  # does not raise


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        get_profile("stealthy")


def test_off_injects_nothing():
    for tool in ("nmap", "nuclei", "ffuf", "httpx", "sqlmap"):
        assert rate_flags(tool, "off") == []


def test_rate_flags_per_tool_quiet():
    assert rate_flags("nmap", "quiet") == ["-T", "1", "--max-rate", "5"]
    assert rate_flags("nuclei", "quiet") == ["-rl", "5", "-c", "1"]
    assert rate_flags("ffuf", "quiet") == ["-rate", "5", "-p", "1.0"]
    assert rate_flags("httpx", "quiet") == ["-rate-limit", "5"]
    assert rate_flags("katana", "quiet") == ["-rate-limit", "5"]
    assert rate_flags("masscan", "quiet") == ["--rate", "5"]
    assert rate_flags("sqlmap", "quiet") == ["--delay", "1.0"]
    assert rate_flags("dalfox", "quiet") == ["--delay", "1000"]  # ms


def test_rate_flags_scale_with_profile():
    # Aggressive lets more through than quiet on the same tool.
    q = rate_flags("nuclei", "quiet")
    a = rate_flags("nuclei", "aggressive")
    assert int(q[1]) < int(a[1])  # higher rate-limit
    assert int(q[3]) < int(a[3])  # higher concurrency


def test_unknown_tool_gets_no_flags():
    assert rate_flags("whatweb", "quiet") == []


def test_apply_injects_missing_limit():
    cmd = "nmap -sT --top-ports 1000 -T4 target.example.com -oX -"
    out = apply_to_command(cmd, "quiet")
    assert "--max-rate 5" in out       # rate ceiling added
    assert "-T4" in out                # the command's own timing is kept
    assert "-T 1" not in out           # governor does not fight it


def test_apply_does_not_misfire_on_similar_token():
    # "-sT" must not be mistaken for the timing flag "-T".
    out = apply_to_command("nmap -sT target.example.com", "quiet")
    assert "-T 1" in out  # no timing present, so the governor sets one


def test_apply_ffuf_adds_rate_and_pause():
    cmd = "ffuf -u https://t/FUZZ -w list.txt -mc 200,403 -s"
    out = apply_to_command(cmd, "quiet")
    assert "-rate 5" in out
    assert "-p 1.0" in out


def test_apply_detects_tool_after_a_pipe():
    out = apply_to_command("echo 't' | httpx -silent -title", "quiet")
    assert "-rate-limit 5" in out


def test_apply_off_is_identity():
    cmd = "nmap -sT --top-ports 1000 -T4 target.example.com -oX -"
    assert apply_to_command(cmd, "off") == cmd


def test_apply_unknown_tool_is_identity():
    assert apply_to_command("whatweb -q target.example.com", "quiet") == \
        "whatweb -q target.example.com"


def test_apply_is_idempotent():
    cmd = "ffuf -u https://t/FUZZ -w list.txt -s"
    once = apply_to_command(cmd, "balanced")
    twice = apply_to_command(once, "balanced")
    assert once == twice  # a limit already present is not added again


def test_delay_advice_bounds_and_determinism():
    assert delay_advice("off", random.Random(0)) == 0.0
    a = delay_advice("quiet", random.Random(0))
    b = delay_advice("quiet", random.Random(0))
    assert a == b                       # seeded -> reproducible
    assert 0.6 <= a <= 1.4              # 1.0s +/- 40% jitter


def test_nuclei_knobs_bounded():
    rl, c = nuclei_knobs("aggressive")
    assert 1 <= rl <= 100 and 1 <= c <= 25
    rl_q, c_q = nuclei_knobs("quiet")
    assert rl_q == 5 and c_q == 1
