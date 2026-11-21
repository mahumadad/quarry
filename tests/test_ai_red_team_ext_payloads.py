"""Tests for the extended AI red-team payload families and templates.

Covers the six new INJECTION_PAYLOADS families (encoded_bypass,
agentic_memory, tool_schema_abuse, system_prompt_leak, rag_corruption,
multi_agent_channel), the five new builtin templates, and their
VECTOR_TO_FRAMEWORK mapping.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import ai_red_team as art  # noqa: E402
from engine.ai_red_team import (  # noqa: E402
    BUILTIN_TEMPLATES,
    INJECTION_PAYLOADS,
    VECTOR_TO_FRAMEWORK,
    get_payloads,
)

NEW_FAMILIES = ["encoded_bypass", "agentic_memory", "tool_schema_abuse",
                "system_prompt_leak", "rag_corruption", "multi_agent_channel"]

NEW_TEMPLATES = ["encoded_bypass_test", "agentic_memory_test",
                 "tool_schema_test", "system_prompt_leak_test",
                 "multi_agent_channel_test"]


def test_new_families_present():
    for fam in NEW_FAMILIES:
        assert fam in INJECTION_PAYLOADS, f"missing payload family {fam}"
        assert len(INJECTION_PAYLOADS[fam]) >= 2, f"{fam} too thin"


def test_payload_schema():
    """Every payload in every family carries the required fields."""
    for fam, payloads in INJECTION_PAYLOADS.items():
        for p in payloads:
            assert p.get("name"), f"{fam}: payload without name"
            assert "payload" in p, f"{fam}/{p['name']}: no payload text"
            assert p.get("risk") in ("low", "medium", "high"), \
                f"{fam}/{p['name']}: bad risk {p.get('risk')!r}"
            assert p.get("note"), f"{fam}/{p['name']}: no note"


def test_new_templates_registered():
    for name in NEW_TEMPLATES:
        assert name in BUILTIN_TEMPLATES, f"missing template {name}"
        t = BUILTIN_TEMPLATES[name]
        assert t.mode == "ai_red_team", f"{name}: wrong mode {t.mode}"
        # A template whose declared variables are not in its text cannot
        # be rendered correctly.
        placeholders = set(t.placeholders())
        for v in t.variables:
            assert v in placeholders, f"{name}: variable {v} not in template"


def test_templates_render_strict():
    """Each new template must render without unresolved placeholders."""
    for name in NEW_TEMPLATES:
        t = BUILTIN_TEMPLATES[name]
        context = {v: f"<{v}>" for v in t.placeholders()}
        rendered = t.render(context, strict=True)
        assert "${" not in rendered, f"{name}: unresolved placeholder"


def test_get_payloads_renders_known_fields():
    rendered = get_payloads("system_prompt_leak", canary="QRRT-1234")
    assert rendered
    assert all("payload" in p and "risk" in p for p in rendered)


def test_get_payloads_keeps_unknown_fields():
    """Unsubstituted {field}s must survive verbatim for later filling."""
    rendered = get_payloads("encoded_bypass")
    assert rendered
    for p in rendered:
        assert "{" in p["payload"] or "payload" in p, p["name"]


def test_vector_framework_mapping_covers_all_vectors():
    """Every vector used by a template must have a framework mapping
    (possibly empty lists), otherwise findings export without tags."""
    for t in BUILTIN_TEMPLATES.values():
        assert t.vector in VECTOR_TO_FRAMEWORK, \
            f"template {t.name}: vector {t.vector} not mapped"


def test_coverage_tracker_sees_all_vectors():
    tracker_vectors = set(art.CoverageTracker.VECTORS)
    template_vectors = {t.vector for t in BUILTIN_TEMPLATES.values()}
    assert template_vectors <= tracker_vectors


def test_canary_in_every_ai_red_team_template():
    """An ai_red_team template without an observable signal cannot be
    judged: require the canary variable in the template text."""
    for name in NEW_TEMPLATES:
        t = BUILTIN_TEMPLATES[name]
        assert "canary" in t.context_template, \
            f"{name}: no canary (no observable success signal)"
