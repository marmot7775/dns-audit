"""Results page controls that did not do what they named (review of Docs 38 to 70).

Browser tests: the summary buttons open the panel they name, the page reads
the scope from the result rather than the selected button, the spec toggle
switches the header counts along with the body, nothing scrolls sideways
at 320 wide, and Ctrl+R still reloads.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import RUA, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401


def _data(audit, dmarc, **kw):
    return json.loads(json.dumps(_run(audit, dmarc, **kw), default=str))


def _visible(page, sel):
    return page.evaluate(
        "s => { const e = document.querySelector(s); return !!e && e.getClientRects().length > 0; }", sel)


@pytest.mark.parametrize("dmarc", [None, f"v=DMARC1; p=none; {RUA}"])
@pytest.mark.parametrize("mode", ["dmarcbis", "legacy"])
def test_summary_buttons_open_the_panel_they_name(browser, audit, dmarc, mode):  # noqa: F811
    data = _data(audit, dmarc)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        if mode == "legacy" and page.query_selector("#check-dmarc .st-seg[data-mode='legacy']"):
            page.evaluate("""() => { const c = document.getElementById('check-dmarc');
                c.querySelector('.result-header').click();
                c.querySelectorAll('.cd-header').forEach(h => h.click());
                c.querySelector(".st-seg[data-mode='legacy']").click();
                c.querySelectorAll('.cd-header[aria-expanded="true"]').forEach(h => h.click()); }""")
        for label, target in (("View Attack Surface", "#dmarc-attack-surface .cd-body"),
                              ("Copy Recommended Record", "#dmarc-record-builder .cd-body")):
            btn = page.query_selector(f".es-action:text-is('{label}')")
            if btn is None:
                continue
            btn.click()
            page.wait_for_timeout(100)
            assert _visible(page, target), (label, mode)
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("scope", ["transport", "dns_infra"])
def test_no_attack_surface_button_without_a_dmarc_card(browser, audit, scope):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}", scope=scope)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        labels = page.eval_on_selector_all(".es-action", "els => els.map(e => e.textContent)")
        assert "View Attack Surface" not in labels
        assert not errors, errors
    finally:
        ctx.close()


def test_the_page_uses_the_results_scope_not_the_selected_button(browser, audit):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}")
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.evaluate("() => { currentScope = 'transport'; }")
        _render(page, data)
        cards = page.eval_on_selector_all("#results-list .result-card", "els => els.length")
        assert cards == len(data["checks"])
        assert page.query_selector("#check-dmarc") is not None
        assert "scope=transport" not in page.evaluate("() => _getShareUrl()")
        assert "scope=transport" not in page.url
        assert not errors, errors
    finally:
        ctx.close()


def test_rfc_7489_mode_switches_the_header_counts(browser, audit):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=reject; foo=bar; pct=50; {RUA}")
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        page.evaluate("""() => { const c = document.getElementById('check-dmarc');
            c.querySelector('.result-header').click();
            c.querySelectorAll('.cd-header').forEach(h => h.click()); }""")
        read = """() => { const c = document.getElementById('check-dmarc');
            const visText = e => [...e.querySelectorAll('span')].filter(s => s.getClientRects().length
                && !s.querySelector('span')).map(s => s.textContent).join('') || e.textContent;
            const heads = [...c.querySelectorAll('.cd-header')];
            const details = heads.find(h => h.querySelector('.cd-header-title').textContent === 'Details');
            const strict = heads.find(h => h.querySelector('.cd-header-title').textContent === 'Strict Record Validation');
            const shown = [...c.querySelectorAll('.cd-subsection')].filter(s => s.getClientRects().length).length;
            return {details: visText(details.querySelector('.cd-header-count')),
                    strict: visText(strict.querySelector('.cd-header-count')), shown}; }"""
        before = page.evaluate(read)
        page.click("#check-dmarc .st-seg[data-mode='legacy']")
        after = page.evaluate(read)
        assert "RFC 9989" not in after["strict"], after
        assert after["details"].startswith(f"{after['shown']} section"), after
        assert before["details"].startswith(f"{before['shown']} section"), before
        assert not errors, errors
    finally:
        ctx.close()


PAGES = ["/", "/about", "/privacy", "/articles/", "/articles/dmarcbis",
         "/articles/dnssec", "/articles/dane"]


@pytest.mark.parametrize("path", PAGES)
def test_nothing_scrolls_sideways_at_320(browser, path):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 320, path)
    try:
        page.wait_for_timeout(200)
        assert page.evaluate("document.documentElement.scrollWidth") <= 320
        right = page.eval_on_selector(".theme-toggle", "e => e.getBoundingClientRect().right")
        assert right <= 320, right
    finally:
        ctx.close()


def test_ctrl_r_is_left_to_the_browser(browser, audit):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}")
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        prevented = page.evaluate("""() => {
            const ev = new KeyboardEvent('keydown', {key: 'r', ctrlKey: true, bubbles: true, cancelable: true});
            document.body.dispatchEvent(ev);
            return ev.defaultPrevented; }""")
        assert prevented is False
        plain = page.evaluate("""() => {
            const ev = new KeyboardEvent('keydown', {key: 'r', bubbles: true, cancelable: true});
            document.body.dispatchEvent(ev);
            return ev.defaultPrevented; }""")
        assert plain is True
    finally:
        ctx.close()
