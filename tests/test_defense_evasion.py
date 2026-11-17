"""Tests for defense_evasion — WAF bypass, rate limiting, fingerprint rotation."""

import os
import tempfile

import pytest

os.sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.graph import EngagementGraph
from engine.defense_evasion import (
    BYPASS_TECHNIQUES,
    USER_AGENTS,
    WAF_SIGNATURES,
    BypassEngine,
    DefenseEvasionOrchestrator,
    FingerprintRotator,
    RateLimitEvader,
    RateLimitProfile,
    WAFFingerprinter,
    WAFProfile,
)


@pytest.fixture
def tmp_audit():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def graph(tmp_audit):
    return EngagementGraph(tmp_audit)


class TestConstants:
    def test_waf_signatures_count(self):
        assert len(WAF_SIGNATURES) == 8

    def test_waf_signatures_have_required_keys(self):
        for vendor, sig in WAF_SIGNATURES.items():
            assert "headers" in sig
            assert "cookies" in sig
            assert "server" in sig
            assert "status_codes" in sig
            assert "body_patterns" in sig

    def test_bypass_techniques_categories(self):
        expected = {"encoding", "header_manipulation", "request_structure",
                    "protocol", "timing"}
        assert set(BYPASS_TECHNIQUES.keys()) == expected

    def test_user_agents_count(self):
        assert len(USER_AGENTS) == 8


class TestWAFFingerprinter:
    def test_cloudflare_detection(self):
        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            headers={"cf-ray": "abc123", "Server": "cloudflare"},
            cookies=["__cfruid=x"],
            status_code=403,
            body="Attention Required! | Cloudflare Ray ID: abc")
        assert profile.vendor == "cloudflare"
        assert profile.confidence > 0.5
        assert "cf-ray" in profile.detected_headers

    def test_aws_waf_detection(self):
        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            headers={"x-amzn-requestid": "abc", "x-amzn-trace-id": "xyz"},
            cookies=["awsalb=foo"],
            status_code=403,
            body="Request blocked")
        assert profile.vendor == "aws_waf"
        assert profile.confidence > 0.3

    def test_no_waf_detected(self):
        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            headers={"content-type": "text/html"},
            cookies=[],
            status_code=200,
            body="Hello World")
        assert profile.vendor == "none_detected"

    def test_modsecurity_detection(self):
        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            headers={"Server": "ModSecurity"},
            cookies=[],
            status_code=403,
            body="Not Acceptable! Rules triggered")
        assert profile.vendor == "modsecurity"

    def test_akamai_detection(self):
        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            headers={"x-akamai-transformed": "9", "Server": "AkamaiGHost"},
            cookies=["ak_bmsc=abc"],
            status_code=403,
            body="Access Denied. Reference #abc")
        assert profile.vendor == "akamai"


class TestWAFProfile:
    def test_suggested_bypasses_excludes_blocked(self):
        p = WAFProfile(vendor="cloudflare", confidence=0.9)
        p.bypass_history = [
            {"technique": "double_url_encode", "success": False},
            {"technique": "mixed_case", "success": True},
        ]
        suggestions = p.suggested_bypasses
        assert "double_url_encode" not in suggestions
        assert "mixed_case" not in suggestions

    def test_to_dict(self):
        p = WAFProfile(vendor="test", confidence=0.5)
        d = p.to_dict()
        assert d["vendor"] == "test"
        assert d["confidence"] == 0.5


class TestBypassEngine:
    @pytest.fixture
    def engine(self):
        return BypassEngine(seed=42)

    def test_double_url_encode(self, engine):
        result = engine.double_url_encode("<script>")
        assert "%25" in result
        assert "<" not in result

    def test_unicode_fullwidth(self, engine):
        result = engine.unicode_fullwidth("<script>")
        assert result != "<script>"
        assert len(result) == len("<script>")

    def test_html_entities(self, engine):
        result = engine.html_entities("<a>")
        assert "&#60;" in result
        assert "&#97;" in result
        assert "&#62;" in result

    def test_hex_encode(self, engine):
        result = engine.hex_encode("<")
        assert result == "\\x3c"

    def test_mixed_case_deterministic(self):
        e1 = BypassEngine(seed=42)
        e2 = BypassEngine(seed=42)
        assert e1.mixed_case("select") == e2.mixed_case("select")

    def test_comment_insertion(self, engine):
        result = engine.comment_insertion("SELECT * FROM")
        assert "/**/" in result

    def test_comment_insertion_short_input(self, engine):
        assert engine.comment_insertion("ab") == "ab"

    def test_null_byte_inject(self, engine):
        result = engine.null_byte_inject("file.php")
        assert result.endswith("%00")

    def test_path_normalization_generates_variants(self, engine):
        variants = engine.path_normalization("/admin/users")
        assert len(variants) >= 4
        assert "/admin/users" in variants

    def test_generate_bypass_variants(self, engine):
        variants = engine.generate_bypass_variants("<script>alert(1)</script>")
        assert len(variants) >= 1
        assert all("technique" in v and "payload" in v for v in variants)

    def test_generate_bypass_variants_max(self, engine):
        variants = engine.generate_bypass_variants("<img src=x>", max_variants=3)
        assert len(variants) <= 3

    def test_generate_header_bypasses(self, engine):
        bypasses = engine.generate_header_bypasses()
        assert len(bypasses) >= 10
        xff = [b for b in bypasses if "X-Forwarded-For" in b]
        assert len(xff) >= 4


class TestRateLimitEvader:
    @pytest.fixture
    def evader(self):
        return RateLimitEvader(seed=42)

    def test_normal_response(self, evader):
        result = evader.record_response(200, {})
        assert result["action"] == "continue"

    def test_429_triggers_wait(self, evader):
        result = evader.record_response(429, {"Retry-After": "5"})
        assert result["action"] == "wait"
        assert result["delay"] > 0
        assert result["consecutive_429"] == 1

    def test_exponential_backoff(self, evader):
        delays = []
        for _ in range(5):
            result = evader.record_response(429, {})
            delays.append(result["delay"])
        assert delays[-1] > delays[0]

    def test_delay_decays_after_success(self, evader):
        evader.record_response(429, {})
        evader.record_response(429, {})
        high_delay = evader.recommended_delay
        evader.record_response(200, {})
        assert evader.recommended_delay < high_delay

    def test_rate_limit_header_detection(self, evader):
        evader.record_response(429, {"x-ratelimit-limit": "100",
                                      "x-ratelimit-remaining": "0"})
        assert evader.profile is not None
        assert evader.profile.requests_per_window == 100

    def test_get_stats(self, evader):
        evader.record_response(200, {})
        evader.record_response(429, {})
        stats = evader.get_stats()
        assert stats["total_requests"] == 2
        assert stats["rate_limited"] == 1
        assert stats["rate_limit_pct"] == 50.0

    def test_max_delay_capped(self, evader):
        for _ in range(20):
            evader.record_response(429, {})
        assert evader.recommended_delay <= 120.0


class TestFingerprintRotator:
    @pytest.fixture
    def rotator(self):
        return FingerprintRotator(seed=42)

    def test_next_user_agent_rotates(self, rotator):
        agents = [rotator.next_user_agent() for _ in range(len(USER_AGENTS) + 1)]
        assert agents[0] == agents[len(USER_AGENTS)]
        assert len(set(agents[:len(USER_AGENTS)])) == len(USER_AGENTS)

    def test_random_user_agent(self, rotator):
        ua = rotator.random_user_agent()
        assert ua in USER_AGENTS

    def test_generate_headers(self, rotator):
        h = rotator.generate_headers()
        assert "User-Agent" in h
        assert "Accept" in h
        assert "Accept-Language" in h
        assert "Accept-Encoding" in h

    def test_chrome_headers_include_sec(self, rotator):
        for _ in range(len(USER_AGENTS)):
            h = rotator.generate_headers()
            if "Chrome" in h["User-Agent"] and "Edg" not in h["User-Agent"]:
                assert "Sec-Ch-Ua" in h
                break
        else:
            pytest.fail("No Chrome UA generated Sec-Ch headers")

    def test_tls_config_hint(self, rotator):
        config = rotator.tls_config_hint()
        assert "cipher_preference" in config
        assert "tls_version" in config
        assert "alpn" in config

    def test_deterministic_with_seed(self):
        r1 = FingerprintRotator(seed=99)
        r2 = FingerprintRotator(seed=99)
        assert r1.random_user_agent() == r2.random_user_agent()


class TestDefenseEvasionOrchestrator:
    @pytest.fixture
    def orch(self, graph):
        return DefenseEvasionOrchestrator(graph)

    def test_fingerprint_waf_records_to_graph(self, orch, graph):
        orch.fingerprint_waf(
            target="example.com",
            headers={"cf-ray": "x", "Server": "cloudflare"},
            cookies=["__cfruid=y"],
            status_code=403,
            body="Cloudflare Ray ID: z")

        caps = graph.nodes_by_type("capability")
        assert len(caps) >= 1
        assert any("cloudflare" in c.label.lower() for c in caps)

    def test_no_waf_does_not_record(self, orch, graph):
        orch.fingerprint_waf(
            target="clean.com",
            headers={},
            cookies=[],
            status_code=200,
            body="OK")
        caps = graph.nodes_by_type("capability")
        assert len(caps) == 0
