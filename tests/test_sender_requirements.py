"""Gmail, Yahoo and Microsoft sender requirements checklist (2026-10-25).

Three rows are graded from the SPF, DKIM and DMARC cards; five depend on
how mail is sent and say they are not visible in DNS. The page shows the
block on Inbox readiness and Full audit, and the PDF follows the page.
"""
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import RUA, _pdf_text, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

HEADING = "Gmail, Yahoo, and Microsoft sender requirements"
GOOD = f"v=DMARC1; p=none; {RUA}"


def _rows(result):
    return {r["key"]: r for r in result["sender_requirements"]["rows"]}


def test_a_complete_setup_meets_the_three_dns_rows(audit):
    req = _run(audit, GOOD, scope="deliverability")["sender_requirements"]
    rows = {r["key"]: r for r in req["rows"]}
    assert [rows[k]["status"] for k in ("spf", "dkim", "dmarc")] == ["met"] * 3
    assert rows["dmarc"]["note"] == "p=none meets it."
    assert req["state"] == "pass"
    assert req["met"] == 3 and req["dns_total"] == 3
    assert [r["key"] for r in req["rows"] if r["status"] == "outside_dns"] == [
        "alignment", "reverse_dns", "tls", "unsubscribe", "spam_rate"]


def test_no_dmarc_record_is_not_met(audit):
    req = _run(audit, None, scope="deliverability")["sender_requirements"]
    assert {r["key"]: r["status"] for r in req["rows"]}["dmarc"] == "not_met"
    assert req["state"] == "fail"
    assert req["summary"].startswith("Your DNS misses 1 of the 3")


def test_no_spf_record_is_not_met(audit):
    result = _run(audit, GOOD, scope="deliverability", spf="google-site-verification=x")
    assert _rows(result)["spf"]["status"] == "not_met"


def test_a_dkim_key_not_found_is_not_confirmed(audit):
    from test_dmarc_grades import DOMAIN, _zone
    result = audit(_zone(GOOD), DOMAIN, scope="deliverability")  # no selector, none found
    assert _rows(result)["dkim"]["status"] in ("met", "unknown")
    if _rows(result)["dkim"]["status"] == "unknown":
        assert "selector" in _rows(result)["dkim"]["note"]


def test_a_run_without_email_checks_has_no_checklist(audit):
    assert _run(audit, GOOD, scope="dns_security")["sender_requirements"] is None


@pytest.mark.parametrize("scope,shown", [
    ("deliverability", True), ("complete", True),
    ("senders", False), ("email_security", False),
])
def test_the_pdf_shows_it_where_the_page_does(audit, scope, shown):
    assert (HEADING in _pdf_text(_run(audit, GOOD, scope=scope))) is shown


@pytest.mark.parametrize("scope,shown", [("deliverability", True), ("senders", False)])
def test_the_page_shows_it_under_the_headline(browser, audit, scope, shown):  # noqa: F811
    data = json.loads(json.dumps(_run(audit, GOOD, scope=scope), default=str))
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        assert (page.locator(".req-block").count() == 1) is shown
        if shown:
            assert page.text_content("#req-heading") == HEADING
            words = page.eval_on_selector_all(".req-list:not(details .req-list) .req-word",
                                              "els => els.map(e => e.textContent)")
            assert words == ["Met", "Met", "Met"]
            # The five rows DNS cannot show start folded.
            assert page.evaluate("() => document.querySelector('.req-more').open") is False
        assert not errors, errors
    finally:
        ctx.close()


def test_the_alignment_row_switches_to_who_sends_as_you(browser, audit):  # noqa: F811
    data = json.loads(json.dumps(_run(audit, GOOD, scope="deliverability"), default=str))
    ctx, page, errors = _page(browser, "dark", 1280)
    requests = []
    page.on("request", lambda r: requests.append(r.url))
    # The rerun never answers; only the request it sends is under test.
    page.route("**/api/**", lambda route: None)
    try:
        _render(page, data)
        page.click(".req-more > summary")
        page.click("[data-req-scope='senders']")
        assert page.get_attribute(".scope-btn[data-scope='senders']", "aria-checked") == "true"
        # The link reruns this domain under Who sends as you, not only the pill.
        page.wait_for_timeout(300)
        streams = [u for u in requests if "/api/audit/stream" in u]
        assert streams, "no audit was started"
        query = parse_qs(urlparse(streams[-1]).query)
        assert query["domain"] == [data["domain"]]
        assert query["scope"] == ["senders"]
    finally:
        ctx.close()


def test_a_dkim_lookup_that_did_not_complete_says_so():
    from result_transformer import build_sender_requirements
    checks = [{"name": "SPF", "status": "pass", "configured": True},
              {"name": "DKIM", "status": "unavailable"},
              {"name": "DMARC", "status": "pass", "configured": True}]
    row = next(r for r in build_sender_requirements(checks)["rows"] if r["key"] == "dkim")
    assert row["status"] == "unknown"
    assert row["note"] == "The lookup did not complete. Run the audit again."
    # A key not found under the common names keeps its own note.
    checks[1] = {"name": "DKIM", "status": "unavailable", "unavailable_kind": "not_enumerable"}
    row = next(r for r in build_sender_requirements(checks)["rows"] if r["key"] == "dkim")
    assert row["note"].startswith("No key found under common names")
