"""Doc 68: three defects on the edges of the report.

1. The removed-tag rows in the RFC 9989 record breakdown were one unwrapped
   flex line, so at phone width the reason sentence started past the right
   edge and the container clipped rather than scrolled.
2. The form refused internationalized domains the API audits happily:
   normalizeDomain did no punycode conversion, and the three copies of the
   validity regex were a stale fork of config.DOMAIN_PATTERN that rejects
   every punycode TLD as well.
3. (The footer row lives in tests/test_footer_attribution_identical.py,
   beside the Doc 39 check it widens.)

The browser checks render a fixture zone in headless Chromium the way
tests/test_ui_consistency_a11y.py does; they skip where Chromium is not
installed, and CI installs it.
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_ui_consistency_a11y as ui  # noqa: E402
from config import DOMAIN_PATTERN  # noqa: E402
from dns_tools import normalize_domain  # noqa: E402

_page = ui._page
_render = ui._render
browser = ui.browser
DOMAIN = ui.DOMAIN

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------
# 1. Removed-tag rows fit the viewport
# ---------------------------------------------------------------

@pytest.fixture(scope="module")
def deprecated_result():
    """A DMARC record carrying tags RFC 9989 removed, so the rows render."""
    zone = ui._zone(
        dmarc=f"v=DMARC1; p=quarantine; pct=50; ri=86400; rf=afrf; rua=mailto:d@{DOMAIN}")
    return json.loads(json.dumps(ui._run(zone), default=str))


_OPEN_BREAKDOWN = """() => {
    const card = document.getElementById('check-dmarc');
    card.classList.add('expanded');
    card.querySelectorAll('.cd-header').forEach(h => h.click());
    return document.querySelectorAll('.dbis-dep-item').length;
}"""

_MEASURE_ROWS = """() => {
    const vw = document.documentElement.clientWidth;
    const rows = [...document.querySelectorAll('.dbis-dep-item')];
    return {vw, rows: rows.map(r => {
        const kids = [...r.children];
        const reason = r.querySelector('.dbis-dep-reason');
        const rb = reason.getBoundingClientRect();
        const tags = kids.filter(k => k !== reason);
        return {
            maxChildRight: Math.max(...kids.map(k => Math.round(k.getBoundingClientRect().right))),
            reasonRight: Math.round(rb.right),
            reasonWidth: Math.round(rb.width),
            reasonText: reason.textContent.trim().length,
            reasonTop: Math.round(rb.top),
            tagsBottom: Math.max(...tags.map(k => Math.round(k.getBoundingClientRect().bottom))),
        };
    })};
}"""


def _rows(browser, width, data):
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, data)
        count = page.evaluate(_OPEN_BREAKDOWN)
        assert count > 0, "the fixture rendered no .dbis-dep-item rows"
        page.wait_for_timeout(400)
        return page.evaluate(_MEASURE_ROWS), errors
    finally:
        ctx.close()


@pytest.mark.parametrize("width", [320, 360, 390])
def test_removed_tag_rows_stay_inside_the_viewport_on_a_phone(browser, deprecated_result, width):
    m, errors = _rows(browser, width, deprecated_result)
    for row in m["rows"]:
        assert row["maxChildRight"] <= m["vw"], (width, row)
        assert row["reasonRight"] <= m["vw"], (width, row)
    assert errors == []


@pytest.mark.parametrize("width", [320, 360, 390])
def test_the_reason_text_is_actually_readable_on_a_phone(browser, deprecated_result, width):
    """It used to start at x=421 in a 390px viewport, clipped, not scrollable."""
    m, errors = _rows(browser, width, deprecated_result)
    for row in m["rows"]:
        assert row["reasonText"] > 0
        assert row["reasonWidth"] > 0, (width, row)
        # Its own line, below the tag and badge row.
        assert row["reasonTop"] >= row["tagsBottom"], (width, row)
    assert errors == []


@pytest.mark.parametrize("width", [768, 1280])
def test_the_rows_still_fit_at_tablet_and_desktop(browser, deprecated_result, width):
    m, errors = _rows(browser, width, deprecated_result)
    for row in m["rows"]:
        assert row["maxChildRight"] <= m["vw"], (width, row)
        assert row["reasonWidth"] > 0, (width, row)
    assert errors == []


def _declarations(css, selector):
    """The rule's declarations with comments stripped.

    A comment naming a property it removed would otherwise read as that
    property still being set.
    """
    body = re.search(re.escape(selector) + r" \{(.*?)\}", css, re.S).group(1)
    return re.sub(r"/\*.*?\*/", "", body, flags=re.S)


def test_the_row_wraps_and_the_spec_reference_no_longer_refuses_to_shrink():
    css = open(os.path.join(REPO, "static", "style.css"), encoding="utf-8").read()
    assert "flex-wrap: wrap" in _declarations(css, ".dbis-dep-item")
    assert "flex-basis: 100%" in _declarations(css, ".dbis-dep-reason")
    assert "flex-shrink" not in _declarations(css, ".dbis-spec-ref")


# ---------------------------------------------------------------
# 2. Internationalized domains reach the API
# ---------------------------------------------------------------

# (typed, expected normalized form)
IDN_CASES = [
    ("bücher.de", "xn--bcher-kva.de"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("президент.рф", "xn--d1abbgf6aiiy.xn--p1ai"),
    ("παράδειγμα.δοκιμή", "xn--hxajbheg2az3al.xn--jxalpdlp"),
    ("مثال.إختبار", "xn--mgbh0fb.xn--kgbechtv"),
    ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
    ("sub.bücher.de", "sub.xn--bcher-kva.de"),
    ("café.example.com", "xn--caf-dma.example.com"),
    ("https://bücher.de/path?x=1", "xn--bcher-kva.de"),
    ("user@bücher.de", "xn--bcher-kva.de"),
    ("bücher.de:443", "xn--bcher-kva.de"),
]

ASCII_CASES = [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("example.com.", "example.com"),
    ("https://example.com/x", "example.com"),
]

REJECTED = ["not a domain", "example..com", "a_b.com", "-bad.com", "bad-.com",
            "example.c", "example.123", "example.co-", "localhost", ""]


@pytest.fixture(scope="module")
def js(browser):
    """One page, used to call app.js's own normalizeDomain and DOMAIN_RE."""
    ctx, page, errors = _page(browser, "dark", 1280)
    yield page
    ctx.close()


def _normalize(js, values):
    return js.evaluate("""vals => vals.map(v => {
        const n = normalizeDomain(v);
        return {n, valid: !!n && DOMAIN_RE.test(n)};
    })""", values)


@pytest.mark.parametrize("typed,expected", IDN_CASES + ASCII_CASES)
def test_the_browser_punycodes_what_the_reader_typed(js, typed, expected):
    got = _normalize(js, [typed])[0]
    assert got["n"] == expected, typed
    assert got["valid"], f"{typed} normalized to {got['n']} and the regex refused it"


@pytest.mark.parametrize("typed", REJECTED)
def test_input_that_is_not_a_domain_is_still_refused(js, typed):
    assert not _normalize(js, [typed])[0]["valid"], typed


@pytest.mark.parametrize("typed", [c[0] for c in IDN_CASES + ASCII_CASES] + REJECTED)
def test_the_browser_and_the_server_agree(js, typed):
    """The page must not refuse what the API accepts, which was the defect."""
    got = _normalize(js, [typed])[0]
    server_norm = normalize_domain(typed)
    server_valid = bool(server_norm and DOMAIN_PATTERN.match(server_norm))
    assert got["n"] == server_norm, typed
    assert got["valid"] == server_valid, typed


def test_typing_an_idn_and_submitting_runs_the_punycode_audit(browser):
    """End to end through the real form: the request that leaves is ASCII."""
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        asked = []
        page.route("**/api/audit/stream**", lambda route: (
            asked.append(route.request.url),
            route.fulfill(status=200, headers={"content-type": "text/event-stream"},
                          body="event: error\ndata: {\"error\": \"stub\"}\n\n"),
        ) and None)
        page.fill("#domain-input", "bücher.de")
        page.click("#audit-btn")
        page.wait_for_timeout(1200)
        assert asked, "the form never called the audit endpoint"
        assert "xn--bcher-kva.de" in asked[0], asked
        assert page.input_value("#domain-input") == "xn--bcher-kva.de"
        assert page.evaluate(
            "() => { const e = document.getElementById('domain-inline-error');"
            " return e ? e.style.display : 'none'; }") != "block"
    finally:
        ctx.close()


def test_typing_something_that_is_not_a_domain_still_shows_the_inline_error(browser):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.fill("#domain-input", "not a domain")
        page.click("#audit-btn")
        page.wait_for_timeout(400)
        m = page.evaluate("""() => {
            const e = document.getElementById('domain-inline-error');
            return {shown: !!e && e.style.display === 'block', text: e ? e.textContent : ''};
        }""")
        assert m["shown"], m
        # The reader's own text, not a percent-encoded rewrite of it.
        assert "%20" not in m["text"], m["text"]
        assert "not a domain" in m["text"], m["text"]
    finally:
        ctx.close()


# ---------------------------------------------------------------
# One regex, and it is the server's
# ---------------------------------------------------------------

def test_the_validity_regex_is_declared_once():
    app_js = open(os.path.join(REPO, "static", "app.js"), encoding="utf-8").read()
    assert app_js.count("const DOMAIN_RE") == 1
    assert "DOMAIN_RE_URL" not in app_js
    # The literal itself appears exactly once.
    assert len(re.findall(r"\^\(\?!-\)\[A-Za-z0-9-\]\{1,63\}", app_js)) == 1


def test_the_browser_regex_is_the_server_pattern():
    """They were a stale fork: the page rejected every punycode TLD."""
    app_js = open(os.path.join(REPO, "static", "app.js"), encoding="utf-8").read()
    literal = re.search(r"^const DOMAIN_RE = /(.*)/;$", app_js, re.M).group(1)
    assert literal == DOMAIN_PATTERN.pattern, (literal, DOMAIN_PATTERN.pattern)
