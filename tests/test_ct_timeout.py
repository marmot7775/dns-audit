"""Doc 61: a crt.sh timeout no longer sets the audit's wall time.

The CT check waited up to ten seconds on crt.sh, Phase 2 waits for its
slowest check, and a timeout was never cached, so every audit of a domain
with a large certificate history paid the full wait and got nothing for it.
The read timeout is now five seconds, a timeout is remembered for
CT_TIMEOUT_CACHE_TTL, and the Not checked card says what happened.
"""
import os
import sys
import time
from unittest.mock import patch

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
from conftest import fake_dns
from test_ui_consistency_a11y import DOMAIN, _zone


NEW_EXPLANATION = (
    "Certificate Transparency was not assessed. This audit reads CT data from the public "
    "crt.sh service, which did not answer within five seconds. That is common for domains "
    "with thousands of certificates and says nothing about your certificates either way. "
    "To review them yourself, search this domain on "
    "<a href=\"https://crt.sh\" target=\"_blank\" rel=\"noopener\">crt.sh</a>."
)
NEW_DETAIL = "crt.sh did not answer in time. This is a gap in the audit, not a finding about your domain."


@pytest.fixture(autouse=True)
def _empty_ct_caches():
    saved = dict(audit_engine._ct_cache), dict(audit_engine._ct_timeout_cache)
    audit_engine._ct_cache.clear()
    audit_engine._ct_timeout_cache.clear()
    yield
    audit_engine._ct_cache.clear()
    audit_engine._ct_timeout_cache.clear()
    audit_engine._ct_cache.update(saved[0])
    audit_engine._ct_timeout_cache.update(saved[1])


class _NeverAnswers:
    """requests.get for a crt.sh that accepts the connection and never replies.

    It sleeps just past whatever read timeout the caller passed, capped at
    eleven seconds, then raises the Timeout requests would raise.
    """

    def __init__(self):
        self.crt_sh_calls = 0

    def __call__(self, url, *args, timeout=None, **kwargs):
        if "crt.sh" not in str(url):
            raise requests.exceptions.ConnectionError("network disabled in tests")
        self.crt_sh_calls += 1
        read = timeout[1] if isinstance(timeout, tuple) else timeout
        time.sleep(min(read if read is not None else 11, 11) + 0.1)
        raise requests.exceptions.ReadTimeout("crt.sh did not answer")


def _ct_card(result):
    return next(c for c in result["checks"] if c["name"] == "Certificate Transparency")


def test_crt_sh_query_asks_for_deduplicated_rows():
    seen = {}

    def _fake_get(url, params=None, **kwargs):
        seen["params"] = params
        raise requests.exceptions.ConnectionError("network disabled in tests")

    with patch("requests.get", _fake_get):
        audit_engine._raw_check_ct_uncached("example.com", {})
    assert seen["params"].get("deduplicate") == "Y"


def test_ct_check_gives_up_within_six_seconds():
    fake = _NeverAnswers()
    with patch("requests.get", fake):
        start = time.monotonic()
        raw = audit_engine._raw_check_ct("slow.example", {})
        took = time.monotonic() - start
    assert took < 6, f"the CT check waited {took:.1f}s on a crt.sh that never answered"
    assert raw["unavailable_reason"] == "timeout"
    assert fake.crt_sh_calls == 1


def test_full_audit_is_not_held_by_crt_sh():
    # Baseline: the same fixture with crt.sh failing at once, so elapsed is
    # the Phase 2 time of the other checks.
    with fake_dns(_zone()):
        baseline = audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope="complete")
    other_checks = baseline["elapsed_seconds"]

    fake = _NeverAnswers()
    with fake_dns(_zone()), patch("requests.get", fake):
        first = audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope="complete")
        repeat = audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope="complete")

    # A first miss costs at most the five second read timeout.
    assert first["elapsed_seconds"] < other_checks + 5 + 1, first["elapsed_seconds"]
    assert _ct_card(first)["status"] == "unavailable"
    # A repeat inside the window costs nothing on top of the other checks.
    assert repeat["elapsed_seconds"] < other_checks + 1, repeat["elapsed_seconds"]
    assert fake.crt_sh_calls == 1
    assert _ct_card(repeat)["explanation"] == NEW_EXPLANATION


def test_timeout_is_remembered_for_fifteen_minutes():
    assert audit_engine.CT_TIMEOUT_CACHE_TTL == 900
    audit_engine._set_cached_ct_timeout(
        "slow.example", {"status": "warning", "total_certs": 0, "unavailable_reason": "timeout"},
    )

    def _must_not_call(*args, **kwargs):
        raise AssertionError("crt.sh was queried inside the timeout window")

    with patch("requests.get", _must_not_call):
        raw = audit_engine._raw_check_ct("slow.example", {})
    assert raw["unavailable_reason"] == "timeout_cached"

    audit_engine._ct_timeout_cache["slow.example"]["timestamp"] -= 901
    calls = []

    def _fails_fast(url, *args, **kwargs):
        calls.append(url)
        raise requests.exceptions.ConnectionError("network disabled in tests")

    with patch("requests.get", _fails_fast):
        raw = audit_engine._raw_check_ct("slow.example", {})
    assert calls, "crt.sh was not asked again after the window closed"
    assert raw["unavailable_reason"] == "request_error"


def test_a_real_past_result_still_wins_over_a_cached_timeout():
    past = {"status": "info", "total_certs": 3, "active_certs": 3}
    audit_engine._set_cached_ct("slow.example", past)
    audit_engine._ct_cache["slow.example"]["timestamp"] -= audit_engine.CT_CACHE_TTL + 10
    audit_engine._set_cached_ct_timeout("slow.example", {"status": "warning", "unavailable_reason": "timeout"})

    with patch("requests.get", lambda *a, **k: pytest.fail("crt.sh was queried")):
        assert audit_engine._raw_check_ct("slow.example", {}) == past


def test_a_timeout_does_not_replace_a_real_past_result():
    past = {"status": "info", "total_certs": 3, "active_certs": 3}
    audit_engine._set_cached_ct("slow.example", past)
    audit_engine._ct_cache["slow.example"]["timestamp"] -= audit_engine.CT_CACHE_TTL + 10

    def _times_out(*args, **kwargs):
        raise requests.exceptions.ReadTimeout("crt.sh did not answer")

    with patch("requests.get", _times_out):
        assert audit_engine._raw_check_ct("slow.example", {}) == past
    assert audit_engine._get_stale_ct("slow.example") == past


def test_timeout_cache_is_bounded():
    for i in range(audit_engine.CT_CACHE_MAX_SIZE + 500):
        audit_engine._set_cached_ct_timeout(f"t-{i}.example", {"unavailable_reason": "timeout"})
    assert len(audit_engine._ct_timeout_cache) <= audit_engine.CT_CACHE_MAX_SIZE


def _unavailable(reason):
    return {"status": "warning", "total_certs": 0, "unavailable_reason": reason, "issues": []}


@pytest.mark.parametrize("reason", ["timeout", "timeout_cached"])
def test_card_says_crt_sh_did_not_answer(reason):
    card = result_transformer.transform_ct(_unavailable(reason), "google.com")
    assert card["status"] == "unavailable"
    assert card["pill_label"] == "Not checked"
    assert card["explanation"] == NEW_EXPLANATION
    assert card["details"] == [{"type": "info", "text": NEW_DETAIL}]
    assert "frequently unavailable" not in card["explanation"]


def test_too_large_keeps_its_wording():
    raw = _unavailable("response_too_large")
    raw["status"] = "unavailable"
    card = result_transformer.transform_ct(raw, "google.com")
    assert card["verdict"] == "CT log query unavailable (too many certificates)"
    assert card["explanation"].startswith(
        "The Certificate Transparency log query returned more data than could be processed."
    )
    assert card["details"][0]["text"] == "CT log response too large to analyze automatically"
