"""The Certificate Transparency card retries by itself (2026-10-25).

An audit whose CT card came back Not checked asks /api/ct again after a
pause and swaps the card in place, counters included. If that fails too,
the card offers Try again. The endpoint skips the timeout memory, which
would only replay the failure.
"""
import json
import os
import sys
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
from test_dmarc_grades import RUA, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

D = "doc44.test"
GOOD_CARD = {"name": "Certificate Transparency", "plain_name": "Certificates issued for your domain (CT logs)",
             "status": "pass", "pill_label": "2 certs", "verdict": "2 active certs from 1 issuer",
             "record": None, "explanation": "x", "details": [], "fix": None, "fix_records": None}


def _data(audit):
    d = json.loads(json.dumps(_run(audit, f"v=DMARC1; p=none; {RUA}"), default=str))
    ct = next(c for c in d["checks"] if c["name"] == "Certificate Transparency")
    assert ct["status"] == "unavailable"
    return d


def test_the_endpoint_skips_the_timeout_memory():
    audit_engine._ct_cache.pop(D, None)
    audit_engine._set_cached_ct_timeout(D, {"status": "warning", "unavailable_reason": "timeout",
                                            "total_certs": 0, "issues": []})
    calls = []

    def fake_uncached(domain, raw):
        calls.append(domain)
        return {"check": "Certificate Transparency", "domain": domain, "total_certs": 1,
                "active_certs": 1, "issuers": [{"name": "R11", "count": 1}], "wildcards": [],
                "expiring_soon": [], "expired_recent": [], "subdomains_found": [],
                "caa_mismatches": [], "issues": [], "status": "info", "source": "Cert Spotter"}

    import server as server_module
    with patch.object(audit_engine, "_raw_check_ct_uncached", fake_uncached), \
         patch.object(audit_engine, "_raw_check_caa", lambda d: {}):
        card = TestClient(server_module.app).get("/api/ct", params={"domain": D}).json()
    assert calls == [D]
    assert card["status"] == "pass" and card["plain_name"]
    assert "Source: Cert Spotter." in card["explanation"]
    # A success is cached and the timeout memory cleared.
    assert audit_engine._get_cached_ct(D) is not None
    assert audit_engine._get_cached_ct_timeout(D) is None
    audit_engine._ct_cache.pop(D, None)


def test_the_endpoint_validates_the_domain():
    import server as server_module
    assert TestClient(server_module.app).get("/api/ct", params={"domain": "not a domain"}).status_code == 400


def test_a_retry_that_answers_swaps_the_card_and_the_counts(browser, audit):  # noqa: F811
    data = _data(audit)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.route("**/api/ct*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                      body=json.dumps(GOOD_CARD)))
        _render(page, data)
        before = int(page.text_content("#summary-unavailable"))
        assert page.get_attribute("#check-certificate-transparency", "data-status") == "unavailable"
        page.evaluate("() => retryCt(lastAuditData, true)")
        page.wait_for_function("() => document.getElementById('check-certificate-transparency').dataset.status === 'pass'")
        assert int(page.text_content("#summary-unavailable")) == before - 1
        assert page.locator(".ct-retry").count() == 0
        assert not errors, errors
    finally:
        ctx.close()


def test_a_retry_that_fails_offers_try_again(browser, audit):  # noqa: F811
    data = _data(audit)
    still = {**GOOD_CARD, "status": "unavailable"}
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.route("**/api/ct*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                      body=json.dumps(still)))
        _render(page, data)
        page.evaluate("() => retryCt(lastAuditData, true)")
        page.wait_for_selector(".ct-retry-btn")
        assert "says nothing about your certificates" in page.text_content(".ct-retry")
        page.unroute("**/api/ct*")
        page.route("**/api/ct*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                      body=json.dumps(GOOD_CARD)))
        page.click(".ct-retry-btn")
        page.wait_for_function("() => document.getElementById('check-certificate-transparency').dataset.status === 'pass'")
        assert not errors, errors
    finally:
        ctx.close()


def test_a_newer_audit_ignores_the_old_retry(browser, audit):  # noqa: F811
    data = _data(audit)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.route("**/api/ct*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                      body=json.dumps(GOOD_CARD)))
        _render(page, data)
        page.evaluate("() => { const old = lastAuditData; lastAuditData = {...old}; return retryCt(old, true); }")
        assert page.get_attribute("#check-certificate-transparency", "data-status") == "unavailable"
    finally:
        ctx.close()
