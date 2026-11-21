"""Noise governor — an operator-chosen pacing dial for active tooling.

`defense_evasion.AdaptiveThrottle` already slows down *reactively* once a target
answers 429/503/403. This module is the complement: a *proactive* aggression
profile the operator picks for an engagement, turned into the rate flags every
tool understands, so a scan does not open at full tilt and trip a rate limit,
WAF or IDS before the first adaptive signal ever arrives.

Four profiles:

  - ``off``        no injection at all — tool defaults, behaves as before.
  - ``quiet``      one worker, ~5 req/s, 1s spacing — stay under the radar.
  - ``balanced``   a handful of workers, ~20 req/s — the usual default.
  - ``aggressive`` fast but still bounded — authorized, time-boxed windows.

Everything here is pure and deterministic (no sleeps, no I/O): callers apply
the advice. ``rate_flags`` yields the flags for one tool; ``apply_to_command``
rewrites a command to carry them without clobbering a limit it already sets;
``delay_advice`` returns a jittered per-request wait for direct HTTP callers.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class PacingProfile:
    name: str
    max_rate: int        # requests/sec ceiling
    concurrency: int     # parallel workers
    delay: float         # seconds between requests (delay-based tools)
    jitter: float        # +/- fraction applied to delay_advice
    nmap_timing: int     # nmap -T value (0..5)


PROFILES: dict[str, PacingProfile] = {
    "off": PacingProfile("off", max_rate=100, concurrency=25,
                         delay=0.0, jitter=0.0, nmap_timing=4),
    "quiet": PacingProfile("quiet", max_rate=5, concurrency=1,
                           delay=1.0, jitter=0.4, nmap_timing=1),
    "balanced": PacingProfile("balanced", max_rate=20, concurrency=5,
                              delay=0.2, jitter=0.25, nmap_timing=2),
    "aggressive": PacingProfile("aggressive", max_rate=100, concurrency=20,
                                delay=0.0, jitter=0.1, nmap_timing=4),
}

PROFILE_NAMES = list(PROFILES)


def get_profile(name: str) -> PacingProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError("unknown pacing profile {!r}; known: {}".format(
            name, PROFILE_NAMES))


def _fmt(seconds: float) -> str:
    """Format a delay as a short decimal string (1.0, 0.2, 0.0)."""
    return str(round(float(seconds), 3))


# How each tool spells its rate limit. Only tools present here are paced; an
# unknown tool gets no flags (and apply_to_command leaves it untouched).
_TOOL_FLAG_BUILDERS = {
    "nmap": lambda p: ["-T", str(p.nmap_timing)]
    + (["--max-rate", str(p.max_rate)] if p.max_rate else []),
    "masscan": lambda p: ["--rate", str(p.max_rate)] if p.max_rate else [],
    "nuclei": lambda p: ["-rl", str(p.max_rate), "-c", str(p.concurrency)],
    "httpx": lambda p: ["-rate-limit", str(p.max_rate)] if p.max_rate else [],
    "katana": lambda p: ["-rate-limit", str(p.max_rate)] if p.max_rate else [],
    "ffuf": lambda p: ["-rate", str(p.max_rate), "-p", _fmt(p.delay)],
    "feroxbuster": lambda p: (["--rate-limit", str(p.max_rate)]
                              if p.max_rate else []),
    "gobuster": lambda p: ["--delay", _fmt(p.delay) + "s"],
    "sqlmap": lambda p: ["--delay", _fmt(p.delay)],
    "dalfox": lambda p: ["--delay", str(int(round(p.delay * 1000)))],  # ms
}


def rate_flags(tool: str, profile: str) -> list[str]:
    """Rate-limit flags for ``tool`` under ``profile``; ``off`` -> no flags."""
    if profile == "off":
        return []
    p = get_profile(profile)
    builder = _TOOL_FLAG_BUILDERS.get(tool)
    return list(builder(p)) if builder else []


def _detect_tool(tokens: list[str]) -> str | None:
    """First token (basename) that names a tool we know how to pace."""
    for tok in tokens:
        base = tok.split("/")[-1]
        if base in _TOOL_FLAG_BUILDERS:
            return base
    return None


def _has_flag(tokens: list[str], flag: str) -> bool:
    """Whether ``flag`` is already set, attached (``-T4``) or detached."""
    for tok in tokens:
        if tok == flag or tok.startswith(flag + "=") or tok.startswith(flag):
            # startswith covers the attached short form (-T4) and --flag=val;
            # it does not match "-sT" for "-T" since that starts with "-s".
            return True
    return False


def apply_to_command(command: str, profile: str) -> str:
    """Append pacing flags to ``command`` for its tool, skipping any limit it
    already sets. ``off`` and unknown/limitless tools return it unchanged."""
    if profile == "off" or not command.strip():
        return command
    tokens = command.split()
    tool = _detect_tool(tokens)
    if tool is None:
        return command
    flags = rate_flags(tool, profile)
    additions: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        value = flags[i + 1] if i + 1 < len(flags) else ""
        i += 2
        if _has_flag(tokens, flag):
            continue
        additions.append(flag)
        if value != "":
            additions.append(value)
    if not additions:
        return command
    return command + " " + " ".join(additions)


def delay_advice(profile: str, rng: random.Random | None = None) -> float:
    """A jittered per-request wait in seconds (0.0 when the profile adds none).

    No sleep is performed here — the caller waits — keeping the module testable.
    """
    p = get_profile(profile)
    if p.delay <= 0:
        return 0.0
    rng = rng or random.Random()
    factor = 1.0 + rng.uniform(-p.jitter, p.jitter)
    return round(p.delay * factor, 3)


def nuclei_knobs(profile: str) -> tuple[int, int]:
    """(rate_limit, concurrency) for NucleiRunner, clamped to its safe bounds."""
    p = get_profile(profile)
    rate = min(max(p.max_rate, 1), 100)
    concurrency = min(max(p.concurrency, 1), 25)
    return rate, concurrency
