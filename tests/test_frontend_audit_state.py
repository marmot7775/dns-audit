"""Results page state that drifted from the audit on screen.

- Scope pills: a pill picked with the arrow keys, or clicked while an audit
  ran, moved currentScope without running anything. The next click compared
  with currentScope, found no change and did nothing, and the lit pill sat
  over results for another scope.
- An audit started within 300 ms of the previous result was hidden by that
  result's delayed reveal, which showed the old results over the new run.
- An HTTP error from the stream (a 400 for a bad selector) sent the same
  audit again to /api/audit, costing a second rate limit slot.
- A #check-* hash from the opening link stayed in the URL and opened that
  card on every later audit.
- Recheck read a lookup that did not complete ("Not checked") as Better or
  Worse, and an empty panel when it fit neither.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_dmarc_grades import _run  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401


def _with_scope(data, scope):
    d = copy.deepcopy(data)
    d["scope"] = scope
    return d


def _capture(page):
    urls = []
    page.on("request", lambda r: urls.append(r.url))
    return urls


def _hang_api(page):
    # Registered after _serve, so it wins for /api: the audit never answers.
    page.route("**/api/**", lambda route: None)


def test_enter_on_an_arrow_selected_pill_runs_that_scope(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, _with_scope(fixture_result, "deliverability"))
        _hang_api(page)
        urls = _capture(page)
        page.focus(".scope-btn.active")
        page.keyboard.press("ArrowRight")
        page.keyboard.press("Enter")
        page.wait_for_timeout(300)
        streams = [u for u in urls if "/api/audit/stream" in u]
        assert streams and "scope=senders" in streams[0], urls
        assert not errors, errors
    finally:
        ctx.close()


def test_the_lit_pill_follows_the_result_on_screen(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.click('.scope-btn[data-scope="complete"]')
        _render(page, _with_scope(fixture_result, "deliverability"))
        assert page.get_attribute(".scope-btn.active", "data-scope") == "deliverability"
        assert not errors, errors
    finally:
        ctx.close()


def test_a_new_audit_right_after_a_result_keeps_its_loading_state(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _hang_api(page)
        page.evaluate("""d => {
            document.getElementById('domain-input').value = d.domain;
            renderResults(d);
            setTimeout(() => runAudit('second.example'), 50);
        }""", fixture_result)
        page.wait_for_timeout(800)
        assert page.is_visible("#loading-section")
        assert not page.is_visible("#results-section")
        assert not errors, errors
    finally:
        ctx.close()


def test_an_http_error_from_the_stream_is_not_retried(browser):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.route("**/api/**", lambda route: route.fulfill(
            status=400, content_type="application/json",
            body=json.dumps({"detail": "Invalid DKIM selector."})))
        urls = _capture(page)
        page.evaluate("() => runAudit('example.com')")
        page.wait_for_timeout(500)
        api = [u for u in urls if "/api/" in u]
        assert len(api) == 1 and "/api/audit/stream" in api[0], api
        assert "Invalid DKIM selector." in page.inner_text("body")
    finally:
        ctx.close()


def test_a_check_hash_is_used_once(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280, "/#check-dmarc")
    try:
        _render(page, fixture_result)
        assert page.evaluate("() => window.location.hash") == ""
        assert not errors, errors
    finally:
        ctx.close()


def _data(audit, dmarc, at):
    d = json.loads(json.dumps(_run(audit, dmarc, scope="deliverability"), default=str))
    d["audited_at"] = at
    return d


def test_recheck_ignores_checks_that_were_not_read(browser, audit):  # noqa: F811
    first = _data(audit, None, "2026-10-20T10:00:00Z")
    second = copy.deepcopy(first)
    second["audited_at"] = "2026-10-24T10:00:00Z"
    for c in second["checks"]:
        c["status"] = "unavailable"
    third = copy.deepcopy(first)
    third["audited_at"] = "2026-10-25T10:00:00Z"
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, first)
        _render(page, second)
        text = page.inner_text(".recheck").upper()
        assert "BETTER" not in text and "WORSE" not in text, text
        assert "NOTHING CHANGED" in text, text
        # The run after compares with the last reading, not with Not checked.
        _render(page, third)
        text = page.inner_text(".recheck").upper()
        assert "BETTER" not in text and "WORSE" not in text, text
        assert not errors, errors
    finally:
        ctx.close()
