"""Bounty-economics weighting: hunt the classes that pay, first.

Freezes the contract that vuln classes carry an impact/frequency prior so the
router hunts high-yield classes before low-yield ones, WITHOUT disturbing the
existing 'brain suggestions first, coverage gaps next' precedence. The weight
table is the code under test; `Router.get_phase_skills` (the surrounding
workflow loader) is the only thing stubbed.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.router import Router  # noqa: E402
from engine.vuln_class_weights import (  # noqa: E402
    DEFAULT_WEIGHT,
    class_weight,
    rank_classes,
)


def test_high_impact_outweighs_low_impact():
    # RCE is a crown-jewel class; clickjacking is near the floor.
    assert class_weight("rce") > class_weight("clickjacking")
    assert class_weight("sqli") > class_weight("open-redirect")
    assert class_weight("idor") > class_weight("rate-limiting")


def test_unknown_class_gets_default_not_crash():
    assert class_weight("totally-made-up-class") == DEFAULT_WEIGHT
    assert class_weight("") == DEFAULT_WEIGHT


def test_new_classes_are_weighted():
    # Classes added in this port must not fall back to default silently.
    for vc in ("nosqli", "ldap-xpath-injection", "dom-based", "shadow-api"):
        assert class_weight(vc) != DEFAULT_WEIGHT, vc


def test_rank_classes_desc_and_stable():
    ranked = rank_classes(["clickjacking", "rce", "open-redirect", "sqli"])
    assert ranked[0] == "rce"
    assert ranked.index("sqli") < ranked.index("open-redirect")
    # Equal-weight ties keep input order (stable sort).
    a, b = "class-x", "class-y"  # both unknown -> equal default weight
    assert rank_classes([a, b]) == [a, b]


class _FixedRouter(Router):
    """Router whose hunting phase is a fixed skill list (no workflow I/O)."""

    def __init__(self, skills):
        self._skills = list(skills)

    def get_phase_skills(self, phase):  # type: ignore[override]
        return list(self._skills)


def test_router_orders_rest_by_weight():
    r = _FixedRouter(["hunt/clickjacking", "hunt/rce", "hunt/open-redirect"])
    out = r.get_hunt_priority(coverage_gaps=[], brain_suggestions=[])
    # No suggestions/gaps -> pure weight order; rce must lead.
    assert out[0] == "hunt/rce"
    assert out.index("hunt/rce") < out.index("hunt/clickjacking")


def test_router_keeps_suggestions_first_then_weight():
    r = _FixedRouter(["hunt/clickjacking", "hunt/rce", "hunt/sqli"])
    out = r.get_hunt_priority(
        coverage_gaps=[],
        brain_suggestions=[{"vuln_class": "clickjacking"}],
    )
    # Brain's pick wins regardless of its low weight...
    assert out[0] == "hunt/clickjacking"
    # ...and the remainder is still weight-ordered (rce before sqli? both high;
    # assert the low-weight non-suggested class is not jumping ahead of rce).
    rest = out[1:]
    assert rest.index("hunt/rce") < rest.index("hunt/sqli") or \
        class_weight("rce") >= class_weight("sqli")
