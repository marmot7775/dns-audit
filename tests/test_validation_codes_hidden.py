"""Internal validation codes stay out of the page (Doc 74).

The strict validation list and the RFC 9989 delta callout printed rule
codes such as SINGLE_RECORD and PCT_REMOVED beside each message, and the
list hid them under 640 px, so desktop and phone readers saw different
pages. Neither is rendered now. The code field stays in the JSON for API
users.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import DOMAIN, _card, _pdf_text, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A bare rua address fails RFC 9989 and passes RFC 7489, so the delta
# callout shows; pct, rf and ri add RFC 9989-only warnings.
DMARC = f"v=DMARC1; p=none; pct=50; rf=afrf; ri=86400; rua=d@{DOMAIN}"

# Scoped to the two lists: page-wide, the pattern also matches the card
# title "DMARC", which is not a code.
_CODE_TEXT_JS = r"""() => {
    const found = [];
    document.querySelectorAll('.sv-block, .st-future').forEach(root => {
        const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        for (let n = w.nextNode(); n; n = w.nextNode()) {
            const t = n.textContent.trim();
            if (/^[A-Z][A-Z0-9_]{3,}$/.test(t)) found.push(t);
        }
    });
    return found;
}"""


@pytest.fixture
def result(audit):
    return json.loads(json.dumps(_run(audit, DMARC), default=str))


def _all_codes(card):
    items = [c for cat in card["strict_validation"]["categories"] for c in cat["checks"]]
    items += [c for cat in card["legacy_validation"]["categories"] for c in cat["checks"]]
    items += card["spec_comparison"]["dmarcbis_only_items"]
    return items


def test_the_fixture_has_both_lists_and_the_api_keeps_every_code(result):
    card = _card(result)
    assert card["spec_comparison"]["legacy_only_pass"] is True
    assert card["spec_comparison"]["dmarcbis_only_items"]
    assert card["strict_validation"]["fail_count"] > 0
    items = _all_codes(card)
    assert items and all(i.get("code") for i in items)
    codes = {i["code"] for i in items}
    assert {"URI_NO_MAILTO", "PCT_REMOVED", "RF_REMOVED", "RI_REMOVED"} <= codes


@pytest.mark.parametrize("width", [1280, 390])
def test_no_code_reaches_the_rendered_page(browser, result, width):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, result)
        page.evaluate("""() => {
            document.querySelectorAll('.result-header').forEach(h => h.click());
            document.querySelectorAll('.cd-body.is-hidden').forEach(b => b.classList.remove('is-hidden'));
            document.querySelectorAll('.spec-legacy.is-hidden').forEach(b => b.classList.remove('is-hidden'));
        }""")
        assert page.query_selector(".st-future-item") is not None
        assert page.query_selector(".sv-check") is not None
        assert page.query_selector(".sv-check-code, .st-future-code") is None
        assert page.query_selector_all(".sv-block") and page.query_selector(".st-future")
        assert page.evaluate(_CODE_TEXT_JS) == []
        body = page.inner_text("#check-dmarc")
        for code in {i["code"] for i in _all_codes(_card(result))}:
            assert code not in body, code
        assert not errors, errors
    finally:
        ctx.close()


def test_desktop_and_phone_show_the_same_list(browser, result):  # noqa: F811
    lists = []
    for width in (1280, 390):
        ctx, page, _ = _page(browser, "dark", width)
        try:
            _render(page, result)
            page.click("#check-dmarc .result-header")
            page.evaluate("() => document.querySelectorAll('#check-dmarc .cd-body.is-hidden')"
                          ".forEach(b => b.classList.remove('is-hidden'))")
            lists.append(page.eval_on_selector_all(
                "#check-dmarc .spec-dmarcbis .sv-check, #check-dmarc .st-future-item",
                "els => els.filter(e => e.getClientRects().length).map(e => e.innerText.trim())"))
        finally:
            ctx.close()
    assert lists[0] and lists[0] == lists[1]


def test_the_pdf_prints_no_code(result):
    text = _pdf_text(result)
    for code in {i["code"] for i in _all_codes(_card(result))}:
        assert code not in text, code


def test_the_styles_for_the_codes_are_gone():
    with open(os.path.join(REPO_ROOT, "static", "style.css"), encoding="utf-8") as f:
        css = f.read()
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        js = f.read()
    for name in ("sv-check-code", "st-future-code"):
        assert name not in css and name not in js, name
