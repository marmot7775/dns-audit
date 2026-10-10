"""A shared link reruns the audit the sharer saw, selector included.

The link carried the domain and scope but not the DKIM selector, so a
result run with a selector reopened without that lookup and could show a
different DKIM card. The link now carries sel=, and the page reads it with
the server's selector rule (config.SELECTOR_PATTERN).
"""
import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_ui_consistency_a11y import _page, _serve, browser, fixture_result  # noqa: E402,F401


def _open(browser, query):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280, "/" + query)
    page.wait_for_timeout(300)
    return ctx, page, errors


def _stream_query(page, requests):
    urls = [r for r in requests if "/api/audit/stream" in r]
    assert urls, "no audit was started"
    return parse_qs(urlparse(urls[0]).query)


def test_link_with_a_selector_runs_the_audit_with_it(browser):  # noqa: F811
    requests = []
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.route("**/*", _serve)
    page.on("request", lambda r: requests.append(r.url))
    page.goto("http://dns-audit.test/?d=github.com&sel=s1")
    page.wait_for_timeout(300)
    try:
        assert page.input_value("#selector-input") == "s1"
        assert page.evaluate("document.getElementById('selector-field').classList.contains('visible')")
        assert page.get_attribute("#selector-toggle", "aria-expanded") == "true"
        assert _stream_query(page, requests)["selector"] == ["s1"]
    finally:
        ctx.close()


def test_a_selector_the_server_would_refuse_is_dropped(browser):  # noqa: F811
    requests = []
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.route("**/*", _serve)
    page.on("request", lambda r: requests.append(r.url))
    page.goto("http://dns-audit.test/?d=github.com&sel=%3Cb%3Ex")
    page.wait_for_timeout(300)
    try:
        assert page.input_value("#selector-input") == ""
        assert "selector" not in _stream_query(page, requests)
    finally:
        ctx.close()


def test_share_url_carries_the_selector_of_the_shown_result(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _open(browser, "")
    try:
        with_sel = page.evaluate("d => { renderResults(d, 's1'); return _getShareUrl(); }", fixture_result)
        assert parse_qs(urlparse(with_sel).query).get("sel") == ["s1"]
        without = page.evaluate("d => { renderResults(d); return _getShareUrl(); }", fixture_result)
        assert "sel" not in parse_qs(urlparse(without).query)
        assert errors == []
    finally:
        ctx.close()
