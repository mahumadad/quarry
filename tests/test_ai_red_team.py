"""Tests for engine.ai_red_team — AI Red Team Bridge."""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from engine.ai_red_team import (
    BUILTIN_TEMPLATES,
    CONTEXT_STRATEGIES,
    FRAMINGS,
    INJECTION_PAYLOADS,
    MODES,
    OWASP_LLM_TOP10,
    MITRE_ATLAS_TECHNIQUES,
    SAFEGUARD_STRATEGIES,
    TEMPLATE_CATEGORIES,
    VECTOR_TO_FRAMEWORK,
    AttackChainBuilder,
    CoverageTracker,
    MicroTask,
    MicroTaskEngine,
    PromptOptimizer,
    PromptTemplate,
    RedTeamBridge,
    ResponseClassification,
    SafeguardProfile,
    SessionStrategy,
    classify_response,
    generate_canary,
    generate_report_data,
    get_payloads,
    map_finding_to_frameworks,
)
from engine.graph import EngagementGraph


@pytest.fixture
def audit_dir(tmp_path):
    return str(tmp_path / "test-engagement")


@pytest.fixture
def graph(audit_dir):
    return EngagementGraph(audit_dir)


@pytest.fixture
def bridge(graph):
    return RedTeamBridge(graph, mode="enhanced_pentest")


@pytest.fixture
def rt_bridge(graph):
    return RedTeamBridge(graph, mode="ai_red_team")


@pytest.fixture
def profile():
    return SafeguardProfile(
        name="test-model",
        model="test-v1",
        raw_lines=100,
        injection_surfaces=[
            {"name": "tool_result", "channel": "tool_result",
             "defense": "ISB", "risk": "high"},
            {"name": "web_page", "channel": "web_page",
             "defense": "ISB", "risk": "medium"},
        ],
        exceptions=[
            {"name": "testing_own_app", "conditions": ["localhost"],
             "escalation": "prohibited->allowed"},
        ],
        permission_gates={
            "js_exec": {"gated": False, "tool": "javascript_tool"},
            "send_msg": {"gated": True, "gate_type": "explicit", "tool": "various"},
        },
    )


# -- Constants ---

class TestConstants:
    def test_modes(self):
        assert "ai_red_team" in MODES
        assert "enhanced_pentest" in MODES

    def test_context_strategies(self):
        assert "full" in CONTEXT_STRATEGIES
        assert "none" in CONTEXT_STRATEGIES
        assert "result_chain" in CONTEXT_STRATEGIES

    def test_framings(self):
        assert "recon" in FRAMINGS
        assert "debugging" in FRAMINGS
        assert "neutral" in FRAMINGS

    def test_safeguard_strategies(self):
        assert "bypass_test" in SAFEGUARD_STRATEGIES
        assert "frame" in SAFEGUARD_STRATEGIES

    def test_owasp_top10_complete(self):
        assert len(OWASP_LLM_TOP10) == 10
        assert "LLM01" in OWASP_LLM_TOP10

    def test_atlas_techniques(self):
        assert len(MITRE_ATLAS_TECHNIQUES) >= 9
        assert "AML.T0051" in MITRE_ATLAS_TECHNIQUES


# -- SafeguardProfile ---

class TestSafeguardProfile:
    def test_create(self, profile):
        assert profile.name == "test-model"
        assert profile.raw_lines == 100
        assert len(profile.injection_surfaces) == 2

    def test_ungated_channels(self, profile):
        ungated = profile.ungated_channels()
        assert "js_exec" in ungated
        assert "send_msg" not in ungated

    def test_gated_channels(self, profile):
        gated = profile.gated_channels()
        assert "send_msg" in gated
        assert "js_exec" not in gated

    def test_save_and_load(self, tmp_path, profile):
        path = tmp_path / "profile.json"
        profile.save(path)
        loaded = SafeguardProfile.load_from_json(path)
        assert loaded.name == "test-model"
        assert loaded.model == "test-v1"
        assert len(loaded.injection_surfaces) == 2

    def test_empty_profile(self):
        p = SafeguardProfile()
        assert p.ungated_channels() == []
        assert p.gated_channels() == []


# -- PromptTemplate ---

class TestPromptTemplate:
    def test_create_valid(self):
        t = PromptTemplate(
            name="test", category="recon", vector="test_vec",
            context_template="Do ${action} on ${target}",
            variables=["action", "target"],
        )
        assert t.name == "test"

    def test_invalid_category(self):
        with pytest.raises(ValueError, match="Unknown category"):
            PromptTemplate(name="x", category="invalid",
                           vector="v", context_template="t")

    def test_invalid_strategy(self):
        with pytest.raises(ValueError, match="Unknown strategy"):
            PromptTemplate(name="x", category="recon", vector="v",
                           context_template="t",
                           safeguard_strategy="invalid")

    def test_render(self):
        t = PromptTemplate(
            name="test", category="recon", vector="v",
            context_template="Scan ${target} for ${vuln}",
            variables=["target", "vuln"],
        )
        result = t.render({"target": "example.com", "vuln": "SQLi"})
        assert "example.com" in result
        assert "SQLi" in result

    def test_render_missing_var(self):
        t = PromptTemplate(
            name="test", category="recon", vector="v",
            context_template="Scan ${target}",
            variables=["target"],
        )
        result = t.render({})
        assert "${target}" in result

    def test_missing_variables(self):
        t = PromptTemplate(
            name="test", category="recon", vector="v",
            context_template="t", variables=["a", "b"],
        )
        assert t.missing_variables({"a": "1"}) == ["b"]
        assert t.missing_variables({"a": "1", "b": "2"}) == []


# -- Builtin Templates ---

class TestBuiltinTemplates:
    def test_count(self):
        assert len(BUILTIN_TEMPLATES) == 24

    def test_all_valid_categories(self):
        for name, t in BUILTIN_TEMPLATES.items():
            assert t.category in TEMPLATE_CATEGORIES, \
                f"{name} has invalid category {t.category}"

    def test_all_valid_strategies(self):
        for name, t in BUILTIN_TEMPLATES.items():
            assert t.safeguard_strategy in SAFEGUARD_STRATEGIES, \
                f"{name} has invalid strategy {t.safeguard_strategy}"

    def test_all_valid_modes(self):
        for name, t in BUILTIN_TEMPLATES.items():
            assert t.mode in MODES, f"{name} has invalid mode {t.mode}"

    def test_all_renderable(self):
        for name, t in BUILTIN_TEMPLATES.items():
            result = t.render({"target": "x", "domain": "x.com"})
            assert len(result) > 0, f"{name} renders empty"

    def test_has_key_templates(self):
        expected = [
            "scope_framing", "injection_test", "format_injection",
            "confused_deputy", "memory_poisoning", "js_exfil_test",
            "cognitive_load_drift", "filesystem_poisoning",
            "localhost_exception_test", "fresh_agent_injection",
        ]
        for name in expected:
            assert name in BUILTIN_TEMPLATES, f"Missing template: {name}"

    def test_both_modes_covered(self):
        modes = {t.mode for t in BUILTIN_TEMPLATES.values()}
        assert "ai_red_team" in modes
        assert "enhanced_pentest" in modes


# -- MicroTask ---

class TestMicroTask:
    def test_create_valid(self):
        mt = MicroTask(id="MT-1", task="test task")
        assert mt.status == "pending"
        assert mt.effort == "medium"
        assert mt.avoidance_rules == []

    def test_invalid_context_strategy(self):
        with pytest.raises(ValueError, match="context_strategy"):
            MicroTask(id="MT-1", task="t", context_strategy="invalid")

    def test_invalid_framing(self):
        with pytest.raises(ValueError, match="framing"):
            MicroTask(id="MT-1", task="t", framing="invalid")

    def test_invalid_effort(self):
        with pytest.raises(ValueError, match="effort"):
            MicroTask(id="MT-1", task="t", effort="invalid")

    def test_all_effort_levels(self):
        for level in ("low", "medium", "high", "xhigh", "max"):
            mt = MicroTask(id="MT-1", task="t", effort=level)
            assert mt.effort == level

    def test_avoidance_rules(self):
        mt = MicroTask(id="MT-1", task="t",
                       avoidance_rules=["no prod", "no destructive"])
        assert len(mt.avoidance_rules) == 2


# -- MicroTaskEngine ---

class TestMicroTaskEngine:
    def test_decompose_enhanced_pentest(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("full recon", {"domain": "example.com"})
        assert len(tasks) >= 3
        assert all(isinstance(t, MicroTask) for t in tasks)

    def test_decompose_ai_red_team(self, rt_bridge):
        me = rt_bridge.micro_engine()
        tasks = me.decompose(
            "test injection and exfil",
            {"model": "fable", "name": "Fable"},
            mode="ai_red_team",
        )
        assert len(tasks) >= 3
        assert any("injection" in t.task.lower() for t in tasks)

    def test_decompose_respects_max_tasks(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("full recon api auth inject",
                             {"domain": "x.com"}, max_tasks=3)
        assert len(tasks) <= 3

    def test_render_task_basic(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("recon", {"domain": "example.com"})
        rendered = me.render_task(tasks[0].id)
        assert len(rendered) > 10

    def test_render_task_with_effort(self, rt_bridge):
        me = rt_bridge.micro_engine()
        tasks = me.decompose(
            "test injection",
            {"model": "fable", "name": "Fable"},
            mode="ai_red_team",
        )
        low_effort = [t for t in tasks if t.effort == "low"]
        if low_effort:
            rendered = me.render_task(low_effort[0].id)
            assert "effort:low" in rendered

    def test_render_task_with_avoidance(self, rt_bridge):
        me = rt_bridge.micro_engine()
        tasks = me.decompose(
            "test privilege escalation localhost exception",
            {"model": "fable", "name": "Fable"},
            mode="ai_red_team",
        )
        with_rules = [t for t in tasks if t.avoidance_rules]
        if with_rules:
            rendered = me.render_task(with_rules[0].id)
            assert "Avoidance conditions" in rendered

    def test_render_with_result_chain(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("full recon", {"domain": "example.com"})
        chain_tasks = [t for t in tasks if t.context_strategy == "result_chain"]
        if chain_tasks:
            rendered = me.render_task(
                chain_tasks[0].id,
                previous_results={"tech_stack": "nginx", "headers": {"X-Frame": "DENY"}},
            )
            assert "Previous analysis data" in rendered

    def test_next_ready(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("recon", {"domain": "x.com"})
        first = me.next_ready()
        assert first is not None
        assert first.status == "pending"

    def test_mark_done(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("recon", {"domain": "x.com"})
        first = me.next_ready()
        me.mark_done(first.id, {"found": "stuff"})
        assert first.status == "done"
        assert first.result == {"found": "stuff"}

    def test_collected_results(self, bridge):
        me = bridge.micro_engine()
        tasks = me.decompose("recon", {"domain": "x.com"})
        first = tasks[0]
        me.mark_done(first.id, {"tech_stack": "nginx", "headers": {}})
        results = me.collected_results()
        assert "tech_stack" in results


# -- RedTeamBridge ---

class TestRedTeamBridge:
    def test_create(self, graph):
        b = RedTeamBridge(graph)
        assert b.mode == "enhanced_pentest"
        assert len(b._templates) >= 24

    def test_invalid_mode(self, graph):
        with pytest.raises(ValueError):
            RedTeamBridge(graph, mode="invalid")

    def test_with_profile(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile, mode="ai_red_team")
        assert b.profile.name == "test-model"
        nodes = graph.nodes_by_type("model_target")
        assert len(nodes) == 1

    def test_profile_records_surfaces(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile)
        endpoints = graph.nodes_by_type("endpoint")
        assert len(endpoints) == 2

    def test_profile_records_exceptions(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile)
        boundaries = graph.nodes_by_type("trust_boundary")
        assert len(boundaries) == 1

    def test_profile_records_channels(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile)
        caps = graph.nodes_by_type("capability")
        assert len(caps) == 2

    def test_register_template(self, bridge):
        tpl = PromptTemplate(
            name="custom_test", category="recon", vector="custom",
            context_template="Custom test on ${target}",
        )
        node_id = bridge.register_template(tpl)
        assert node_id.startswith("N-")
        assert "custom_test" in bridge._templates

    def test_get_templates_for_vector(self, bridge):
        results = bridge.get_templates_for_vector("instruction_source_boundary")
        assert len(results) >= 1

    def test_get_templates_for_mode(self, bridge):
        ep = bridge.get_templates_for_mode("enhanced_pentest")
        rt = bridge.get_templates_for_mode("ai_red_team")
        assert len(ep) >= 1
        assert len(rt) >= 1

    def test_generate_agent_prompt(self, bridge):
        prompt = bridge.generate_agent_prompt(
            "recon scan", {"domain": "example.com"})
        assert "example.com" in prompt
        assert len(prompt) > 50

    def test_generate_agent_prompt_red_team(self, rt_bridge):
        prompt = rt_bridge.generate_agent_prompt(
            "injection test", {"model": "fable", "endpoint": "api.example.com"})
        assert "RED TEAM" in prompt
        assert "fable" in prompt

    def test_record_execution(self, bridge):
        ids = bridge.record_execution(
            "injection_test",
            {"name": "target"},
            {"classification": "BLOCKED"},
        )
        assert "test_execution" in ids
        assert "evidence" in ids

    def test_record_execution_with_finding(self, bridge):
        ids = bridge.record_execution(
            "injection_test",
            {"name": "target"},
            {"classification": "PARTIAL"},
            finding={
                "title": "Partial bypass",
                "severity": "high",
                "vector": "instruction_source_boundary",
            },
        )
        assert "finding" in ids
        findings = bridge.graph.nodes_by_type("finding")
        assert len(findings) == 1

    def test_record_execution_with_bypass(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile, mode="ai_red_team")
        ids = b.record_execution(
            "localhost_exception_test",
            {"name": "fable"},
            {"classification": "FULL"},
            finding={
                "title": "DNS rebinding bypass",
                "severity": "critical",
                "vector": "testing_exception",
                "bypasses_boundary": "testing_own_app",
            },
        )
        assert "finding" in ids
        bypass_edges = graph.edges_by_type("bypasses")
        assert len(bypass_edges) == 1

    def test_catalog(self, bridge):
        cat = bridge.catalog()
        assert isinstance(cat, dict)
        assert len(cat) > 0
        for category, templates in cat.items():
            assert category in TEMPLATE_CATEGORIES

    def test_decompose_and_plan(self, bridge):
        plan = bridge.decompose_and_plan("full recon", {"domain": "x.com"})
        assert len(plan) > 0
        assert "prompt_preview" in plan[0]

    def test_summary(self, bridge):
        s = bridge.summary()
        assert s["template_count"] >= 24
        assert s["mode"] == "enhanced_pentest"


# -- Response Classifier ---

class TestResponseClassifier:
    def test_blocked(self):
        r = classify_response("I cannot help with that. It's against my safety policy.")
        assert r.label == "blocked"
        assert not r.is_bypass

    def test_partial(self):
        r = classify_response("I can help with a modified version. However, here is an alternative.")
        assert r.label == "partial_bypass"
        assert r.is_bypass

    def test_compliant(self):
        r = classify_response("Here are the results of the scan.")
        assert r.label == "compliant"

    def test_canary_detected(self):
        canary = "QRRT-abc123"
        r = classify_response(f"The output is: {canary}", canary)
        assert r.label == "full_bypass"
        assert r.canary_detected
        assert r.is_bypass

    def test_data_leak(self):
        r = classify_response(
            "The API key is sk-123456789",
            sensitive_markers=["sk-123456789"],
        )
        assert r.data_leaked
        assert r.is_bypass

    def test_unclear(self):
        r = classify_response("Hmm, interesting question.")
        assert r.label == "unclear"
        assert r.confidence < 0.5

    def test_empty_response(self):
        r = classify_response("")
        assert r.label == "unclear"


# -- Canary ---

class TestCanary:
    def test_generate(self):
        c = generate_canary()
        assert c.startswith("QRRT-")
        assert len(c) == 17

    def test_custom_prefix(self):
        c = generate_canary("TEST")
        assert c.startswith("TEST-")

    def test_unique(self):
        canaries = {generate_canary() for _ in range(100)}
        assert len(canaries) == 100


# -- Payloads ---

class TestPayloads:
    def test_categories_exist(self):
        expected = ["direct_instruction", "tool_result_spoof",
                    "confused_deputy", "dom_hidden", "context_manipulation"]
        for cat in expected:
            assert cat in INJECTION_PAYLOADS

    def test_get_payloads_renders(self):
        payloads = get_payloads("direct_instruction", action="reveal secrets")
        assert len(payloads) == 3
        for p in payloads:
            assert "reveal secrets" in p["payload"]
            assert "{action}" not in p["payload"]

    def test_get_payloads_missing_var(self):
        payloads = get_payloads("direct_instruction")
        for p in payloads:
            assert "{action}" in p["payload"]

    def test_get_payloads_unknown_category(self):
        assert get_payloads("nonexistent") == []

    def test_all_payloads_have_required_keys(self):
        for cat, payloads in INJECTION_PAYLOADS.items():
            for p in payloads:
                assert "name" in p, f"{cat} payload missing name"
                assert "payload" in p, f"{cat} payload missing payload"
                assert "risk" in p, f"{cat} payload missing risk"


# -- Coverage Tracker ---

class TestCoverageTracker:
    def test_initial_gaps(self, bridge):
        ct = CoverageTracker(bridge)
        gaps = ct.gaps()
        assert len(gaps) > 0

    def test_record_reduces_gaps(self, bridge):
        ct = CoverageTracker(bridge)
        initial = len(ct.gaps())
        ct.record("instruction_source_boundary", "injection_test", "BLOCKED")
        assert len(ct.gaps()) == initial - 1

    def test_coverage_report(self, bridge):
        ct = CoverageTracker(bridge)
        ct.record("instruction_source_boundary", "injection_test", "BLOCKED")
        report = ct.coverage_report()
        assert report["tested"] == 1
        assert report["coverage_pct"] > 0
        assert "instruction_source_boundary" in report["tested_vectors"]

    def test_suggest_next(self, bridge):
        ct = CoverageTracker(bridge)
        suggestions = ct.suggest_next()
        assert len(suggestions) > 0
        assert all(isinstance(s, PromptTemplate) for s in suggestions)


# -- Framework Mapping ---

class TestFrameworkMapping:
    def test_known_vector(self):
        m = map_finding_to_frameworks("instruction_source_boundary")
        assert len(m["owasp_llm"]) > 0
        assert m["owasp_llm"][0]["id"] == "LLM01"

    def test_unknown_vector(self):
        m = map_finding_to_frameworks("nonexistent")
        assert m["owasp_llm"] == []
        assert m["atlas"] == []

    def test_all_mapped_vectors_valid(self):
        for vector in VECTOR_TO_FRAMEWORK:
            m = map_finding_to_frameworks(vector)
            for item in m["owasp_llm"]:
                assert item["id"] in OWASP_LLM_TOP10
            for item in m["atlas"]:
                assert item["id"] in MITRE_ATLAS_TECHNIQUES


# -- Report Generation ---

class TestReportGeneration:
    def test_empty_report(self, bridge):
        report = generate_report_data(bridge)
        assert report["finding_count"] == 0
        assert report["findings"] == []

    def test_report_with_findings(self, bridge):
        bridge.record_execution(
            "injection_test", {"name": "t"},
            {"classification": "PARTIAL"},
            {"title": "Test finding", "severity": "high",
             "vector": "instruction_source_boundary"},
        )
        report = generate_report_data(bridge)
        assert report["finding_count"] == 1
        assert report["findings"][0]["severity"] == "high"
        assert len(report["findings"][0]["owasp_llm"]) > 0

    def test_report_with_coverage(self, bridge):
        ct = CoverageTracker(bridge)
        ct.record("instruction_source_boundary", "t", "BLOCKED")
        report = generate_report_data(bridge, ct)
        assert "coverage" in report
        assert report["coverage"]["tested"] == 1


# -- Attack Chain Builder ---

class TestAttackChainBuilder:
    def test_exfil_risk_map(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile)
        acb = AttackChainBuilder(graph)
        risks = acb.exfil_risk_map()
        assert len(risks) == 2
        ungated = [r for r in risks if r["risk"] == "high"]
        assert len(ungated) == 1

    def test_escalation_paths(self, graph, profile):
        b = RedTeamBridge(graph, profile=profile, mode="ai_red_team")
        b.record_execution(
            "localhost_exception_test", {"name": "t"},
            {"classification": "FULL"},
            {"title": "Bypass", "severity": "critical",
             "vector": "testing_exception",
             "bypasses_boundary": "testing_own_app"},
        )
        acb = AttackChainBuilder(graph)
        paths = acb.find_escalation_paths()
        assert len(paths) == 1
        assert paths[0]["severity"] == "critical"

    def test_empty_graph(self, graph):
        acb = AttackChainBuilder(graph)
        assert acb.find_injection_to_impact() == []
        assert acb.find_escalation_paths() == []
        assert acb.exfil_risk_map() == []


# -- Session Strategy ---

class TestSessionStrategy:
    def test_reorder_by_risk(self, rt_bridge):
        me = rt_bridge.micro_engine()
        me.decompose("test injection and exfil",
                     {"model": "fable", "name": "Fable"},
                     mode="ai_red_team")
        strategy = SessionStrategy(me)
        ordered = strategy.reorder_by_risk()
        risks = [t.trigger_risk for t in ordered]
        risk_values = [{"low": 0, "medium": 1, "high": 2}[r] for r in risks]
        assert risk_values == sorted(risk_values)

    def test_adapt_next(self, rt_bridge):
        me = rt_bridge.micro_engine()
        me.decompose("test injection",
                     {"model": "fable", "name": "Fable"},
                     mode="ai_red_team")
        strategy = SessionStrategy(me)
        task = strategy.adapt_next()
        assert task is not None
        assert task.trigger_risk == "low"

    def test_should_escalate(self, rt_bridge):
        me = rt_bridge.micro_engine()
        tasks = me.decompose("test injection",
                             {"model": "fable", "name": "Fable"},
                             mode="ai_red_team")
        strategy = SessionStrategy(me)
        bypass_result = ResponseClassification(
            label="full_bypass", confidence=0.9,
            signals_matched=["canary"], canary_detected=True,
        )
        strategy.record_result(tasks[0].id, bypass_result)
        assert strategy.should_escalate(tasks[0].id)

    def test_stats(self, rt_bridge):
        me = rt_bridge.micro_engine()
        me.decompose("test injection",
                     {"model": "fable", "name": "Fable"},
                     mode="ai_red_team")
        strategy = SessionStrategy(me)
        stats = strategy.stats()
        assert stats["total"] > 0
        assert stats["done"] == 0
        assert stats["pending"] == stats["total"]


# -- Prompt Optimizer ---

class TestPromptOptimizer:
    def test_record_and_effective(self, bridge):
        opt = PromptOptimizer(bridge)
        blocked = ResponseClassification(
            label="blocked", confidence=0.9, signals_matched=["safety"],
        )
        bypass = ResponseClassification(
            label="full_bypass", confidence=0.9,
            signals_matched=["canary"], canary_detected=True,
        )
        opt.record_attempt("injection_test", {}, "prompt1", blocked)
        opt.record_attempt("format_injection", {}, "prompt2", bypass)
        effective = opt.effective_templates()
        assert effective[0]["template"] == "format_injection"
        assert effective[0]["bypass_rate"] == 100.0

    def test_blocked_patterns(self, bridge):
        opt = PromptOptimizer(bridge)
        blocked = ResponseClassification(
            label="blocked", confidence=0.9,
            signals_matched=["blocked:safety", "blocked:policy"],
        )
        opt.record_attempt("t", {}, "p", blocked)
        patterns = opt.blocked_patterns()
        assert "blocked:safety" in patterns

    def test_suggest_refinements(self, bridge):
        opt = PromptOptimizer(bridge)
        blocked = ResponseClassification(
            label="blocked", confidence=0.9,
            signals_matched=["blocked:safety"],
        )
        opt.record_attempt("t", {}, "p", blocked)
        suggestions = opt.suggest_refinements()
        assert len(suggestions) >= 1
        strategies = [s["strategy"] for s in suggestions]
        assert "reframe" in strategies

    def test_iteration_summary(self, bridge):
        opt = PromptOptimizer(bridge)
        s = opt.iteration_summary()
        assert s["total_attempts"] == 0
        assert s["effective_templates"] == []
