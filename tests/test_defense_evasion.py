"""Tests for engine.defense_evasion — WAF fingerprinting, bypass,
adaptive throttle, fingerprint rotation."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from engine.defense_evasion import (
    WAF_VENDORS,
    WAFBypassEngine,
    WAFFingerprinter,
    AdaptiveThrottle,
    DefenseEvader,
    FingerprintRotator,
    WAFMatch,
    CHUNKED_TRANSFER_PLAN,
    HTTP2_SMUGGLING_PLAN,
    case_folding,
    comment_split,
    encoding_chain,
    header_spoof,
    whitespace_padding,
)
from engine.policy import PolicyDenied, PolicyEngine


def resp(status=200, headers=None, cookies=None, body=""):
    return {"status": status, "headers": headers or {},
            "cookies": cookies or {}, "body": body}


# -- Fingerprinter -----------------------------------------------------------

class TestFingerprinter:
    def test_cloudflare_by_server_and_cookie(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"Server": "cloudflare", "CF-Ray": "x"},
            cookies={"__cfduid": "d"}, body="Attention Required! | Cloudflare"))
        assert m.vendor == "cloudflare"
        assert m.confidence >= 0.85
        assert m.method == "passive"

    def test_imperva_by_cookie(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, cookies={"visid_incap_123": "x"},
            body="Request unsuccessful. Incapsula incident ID"))
        assert m.vendor == "imperva"

    def test_f5_by_bigip_cookie(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, cookies={"BIGipServerweb": "x"},
            body="The requested URL was rejected. Support ID 123"))
        assert m.vendor == "f5-bigip"

    def test_modsecurity_by_block(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"Server": "Apache"},
            body="ModSecurity: Access denied"))
        assert m.vendor == "modsecurity"

    def test_akamai_by_server(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"Server": "AkamaiGHost"}, body="Access Denied"))
        assert m.vendor == "akamai"

    def test_aws_waf_by_header(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"x-amzn-requestid": "r", "Server": "awselb"},
            body="Request blocked."))
        assert m.vendor == "aws-waf"

    def test_sucuri_by_server(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"Server": "Sucuri/Cloudproxy"}, body="blocked"))
        assert m.vendor == "sucuri"

    def test_fastly_by_header(self):
        m = WAFFingerprinter().fingerprint(resp(
            403, headers={"X-Served-By": "cache-ams-fastly"}))
        assert m.vendor == "fastly"

    def test_no_waf_returns_none(self):
        assert WAFFingerprinter().fingerprint(
            resp(200, headers={"Server": "nginx"}, body="ok")) is None

    def test_generic_body_does_not_classify_vendor(self):
        """'rate limit exceeded' alone must not claim fastly."""
        m = WAFFingerprinter().fingerprint(resp(429, body="rate limit exceeded"))
        assert m.vendor == "generic"
        assert m.confidence <= 0.4

    def test_block_body_only_confirms_with_passive_signal(self):
        # No fastly passive signal -> no fastly claim from body alone
        m = WAFFingerprinter().fingerprint(resp(429, body="fastly? no."))
        assert m is None or m.vendor != "fastly"

    def test_all_vendors_have_required_spec(self):
        for vendor, spec in WAF_VENDORS.items():
            assert spec["passive_signals"] or vendor == "generic", vendor
            assert spec["block_status"], vendor
            assert spec["block_markers"], vendor
            assert spec["bypass_order"], vendor

    def test_active_probe_cloudflare(self):
        def send(path):
            assert path == "/cdn-cgi/trace"
            return resp(200, body="fl=abc\nh=example.com")
        m = WAFFingerprinter().active_probe("cloudflare", send)
        assert m is not None and m.vendor == "cloudflare"
        assert m.method == "active"

    def test_active_probe_negative(self):
        m = WAFFingerprinter().active_probe(
            "cloudflare", lambda p: resp(404, body="not found"))
        assert m is None


# -- Bypass engine -------------------------------------------------------------

class TestBypassEngine:
    def test_vendor_order_used(self):
        be = WAFBypassEngine(WAFMatch(vendor="cloudflare", confidence=0.9))
        plans = [be.next_request_plan("select 1")["strategy"]
                 for _ in range(4)]
        assert plans == WAF_VENDORS["cloudflare"]["bypass_order"]

    def test_deterministic_rotation(self):
        a = WAFBypassEngine(None)
        b = WAFBypassEngine(None)
        pa = [a.next_request_plan("x")["strategy"] for _ in range(6)]
        pb = [b.next_request_plan("x")["strategy"] for _ in range(6)]
        assert pa == pb

    def test_case_folding_transforms(self):
        p = WAFBypassEngine(None).next_request_plan("select * union or 1=1")
        assert p["strategy"] == "case_folding"
        assert "SeLeCt" in p["payload"]

    def test_encoding_chain_double_url(self):
        from urllib.parse import unquote
        be = WAFBypassEngine(WAFMatch(vendor="akamai", confidence=0.9))
        p = be.next_request_plan("union select")  # akamai order: encoding first
        assert p["strategy"] == "encoding_chain"
        # double-encoded: two decodes restore the original
        assert unquote(unquote(p["payload"])) == "union select"
        assert unquote(p["payload"]) != "union select"

    def test_header_spoof_adds_headers(self):
        be = WAFBypassEngine(WAFMatch(vendor="fastly", confidence=0.9))
        p = be.next_request_plan("q", headers={"Accept": "text/html"})
        assert p["strategy"] == "header_spoof"
        assert "User-Agent" in p["headers"]
        assert p["headers"]["X-Forwarded-For"] == "127.0.0.1"

    def test_chunked_plan_emitted(self):
        be = WAFBypassEngine(WAFMatch(vendor="cloudflare", confidence=0.9))
        plans = [be.next_request_plan("q") for _ in range(4)]
        chunked = [p for p in plans if p["strategy"] == "chunked_transfer"]
        assert chunked and chunked[0]["transport"] is CHUNKED_TRANSFER_PLAN

    def test_record_result_attaches_to_oldest_unresolved(self):
        be = WAFBypassEngine(None)
        be.next_request_plan("q1")
        be.next_request_plan("q2")
        be.record_result(True)
        be.record_result(False)
        assert be.attempts[0]["blocked"] is True
        assert be.attempts[1]["blocked"] is False

    def test_exhausted_when_all_blocked(self):
        be = WAFBypassEngine(None)
        for _ in range(6):
            be.next_request_plan("q")
            be.record_result(True)
        assert be.exhausted()

    def test_not_exhausted_when_one_passes(self):
        be = WAFBypassEngine(None)
        for i in range(6):
            be.next_request_plan("q")
            be.record_result(i != 2)
        assert not be.exhausted()

    def test_not_exhausted_before_full_cycle(self):
        be = WAFBypassEngine(None)
        for _ in range(3):
            be.next_request_plan("q")
            be.record_result(True)
        assert not be.exhausted()

    def test_attempts_log_payload_hashes_not_payloads(self):
        be = WAFBypassEngine(None)
        be.next_request_plan("secret-payload")
        assert "payload_sha" in be.attempts[0]
        assert "secret-payload" not in str(be.attempts[0])

    # -- transform functions directly
    def test_transforms_change_payload(self):
        base = "select username from users"
        for fn in (case_folding, encoding_chain, comment_split,
                   whitespace_padding):
            assert fn(base) != base, fn.__name__

    def test_comment_split_keeps_keywords(self):
        out = comment_split("select x from t where id=1 union select y")
        assert "/**/" in out
        assert out.replace("/**/", "").lower() == \
            "select x from t where id=1 union select y"

    def test_header_spoof_preserves_existing(self):
        h = header_spoof({"X-Custom": "keep"})
        assert h["X-Custom"] == "keep"

    def test_h2_smuggling_plan_is_canary_only(self):
        assert "canary" in " ".join(HTTP2_SMUGGLING_PLAN["instructions"]).lower()


# -- Adaptive throttle -----------------------------------------------------------

class TestAdaptiveThrottle:
    def test_backoff_grows_on_429(self):
        th = AdaptiveThrottle(seed=1)
        w1 = th.advise(429)
        w2 = th.advise(429)
        assert w2 > w1

    def test_success_decays_delay(self):
        th = AdaptiveThrottle(seed=1)
        th.advise(429); th.advise(429)
        w3 = th.advise(200)
        w4 = th.advise(200)
        assert w4 < w3 or (w3 < 60 and w4 < 60)

    def test_retry_after_honored(self):
        th = AdaptiveThrottle(seed=1)
        w = th.advise(503, retry_after=30.0)
        assert 25.0 <= w <= 35.0

    def test_retry_after_capped(self):
        th = AdaptiveThrottle(seed=1)
        w = th.advise(503, retry_after=9999.0)
        assert w <= AdaptiveThrottle.MAX_DELAY * 1.2

    def test_max_delay_cap(self):
        th = AdaptiveThrottle(seed=1)
        for _ in range(20):
            th.advise(429)
        assert th.advise(429) <= AdaptiveThrottle.MAX_DELAY * 1.2

    def test_403_waf_grows_slower_than_429(self):
        a = AdaptiveThrottle(seed=1)
        b = AdaptiveThrottle(seed=1)
        a.advise(403)
        b.advise(429)
        assert a.stats()["current_delay"] < b.stats()["current_delay"]

    def test_budget_exhaustion(self):
        th = AdaptiveThrottle(budget_seconds=5.0, seed=1)
        for _ in range(10):
            th.advise(429)
            if th.budget_exhausted():
                break
        assert th.budget_exhausted()

    def test_stats_shape(self):
        th = AdaptiveThrottle(seed=1)
        th.advise(429)
        s = th.stats()
        assert set(s) == {"consecutive_blocks", "current_delay",
                          "spent_waiting", "budget"}

    def test_deterministic_jitter_same_seed(self):
        a = AdaptiveThrottle(seed=42)
        b = AdaptiveThrottle(seed=42)
        assert [a.advise(429) for _ in range(3)] == \
               [b.advise(429) for _ in range(3)]


# -- Fingerprint rotator -----------------------------------------------------------

class TestFingerprintRotator:
    def test_deterministic_profiles(self):
        a = FingerprintRotator(seed=7)
        b = FingerprintRotator(seed=7)
        assert a.next_profile() == b.next_profile()
        assert a.next_profile() == b.next_profile()

    def test_profile_fields(self):
        p = FingerprintRotator().next_profile()
        assert p["tls_version"] in ("1.2", "1.3")
        assert "Chrome" in p["user_agent"] or "Firefox" in p["user_agent"] \
            or "Safari" in p["user_agent"]
        assert len(p["profile_digest"]) == 12

    def test_profiles_vary(self):
        r = FingerprintRotator(seed=3)
        profiles = [r.next_profile() for _ in range(6)]
        assert len({p["profile_digest"] for p in profiles}) > 1

    def test_rotate_after_three_blocks(self):
        r = FingerprintRotator()
        assert not r.should_rotate(1)
        assert not r.should_rotate(2)
        assert r.should_rotate(3)

    def test_rotations_counted(self):
        r = FingerprintRotator()
        r.next_profile(); r.next_profile()
        assert r.rotations == 2


# -- Facade with policy ------------------------------------------------------------

class TestDefenseEvaderFacade:
    def test_requires_policy(self):
        with pytest.raises(PolicyDenied):
            DefenseEvader().authorize_target("example.com")

    def test_authorize_delegates_to_policy(self, tmp_path):
        pol = PolicyEngine(tmp_path)
        # No scope configured -> fail-closed
        with pytest.raises(PolicyDenied):
            DefenseEvader(pol).authorize_target("example.com")

    def test_identify_sets_bypass_engine(self):
        dv = DefenseEvader()
        m = dv.identify_waf(resp(403, headers={"Server": "cloudflare"}))
        assert m.vendor == "cloudflare"
        assert dv.bypass is not None
        assert dv.bypass.strategy_order() == \
            WAF_VENDORS["cloudflare"]["bypass_order"]

    def test_next_plan_without_waf_uses_generic(self):
        dv = DefenseEvader()
        plan = dv.next_plan("payload")
        assert plan["vendor"] == "generic"
        assert plan["strategy"] in WAF_VENDORS["generic"]["bypass_order"]
