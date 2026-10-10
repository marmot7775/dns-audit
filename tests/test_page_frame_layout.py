"""The frame around every page: sticky header, footer, first view of results.

After an audit the page scrolled the results to 10px from the top of the
window, under the 61px sticky header, so the domain line and the PDF,
Export and Share buttons were the part a visitor could not see. On a page
shorter than the window the footer stopped part way down with bare
background beneath it. The footer note sat left aligned under two right
aligned link rows.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_ui_consistency_a11y import _page, _render, _serve, browser, fixture_result  # noqa: E402,F401


@pytest.mark.parametrize("width", [1280, 390])
def test_results_land_below_the_sticky_header(browser, fixture_result, width):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, fixture_result)
        page.wait_for_timeout(1500)
        header_bottom, domain_top = page.evaluate("""() => [
            document.querySelector('.site-header').getBoundingClientRect().bottom,
            document.getElementById('result-domain').getBoundingClientRect().top]""")
        assert domain_top >= header_bottom, (header_bottom, domain_top)
        assert domain_top - header_bottom < 60, "scrolled past the top of the results"
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("path", ["/", "/about"])
def test_footer_reaches_the_bottom_of_a_short_page(browser, path):  # noqa: F811
    ctx = browser.new_context(viewport={"width": 1280, "height": 2400})
    page = ctx.new_page()
    page.route("**/*", _serve)
    page.goto("http://dns-audit.test" + path)
    try:
        bottom, height = page.evaluate("""() => [
            Math.round(document.querySelector('.site-footer').getBoundingClientRect().bottom),
            innerHeight]""")
        assert bottom == height
    finally:
        ctx.close()


@pytest.mark.parametrize("width,align", [(1280, "right"), (390, "center")])
def test_footer_note_follows_its_column(browser, width, align):  # noqa: F811
    ctx, page, _ = _page(browser, "light", width)
    try:
        assert page.evaluate(
            "getComputedStyle(document.querySelector('.footer-attribution')).textAlign") == align
    finally:
        ctx.close()


@pytest.mark.parametrize("width", [1280, 700, 390])
def test_domain_input_spans_the_card_and_the_selector_link_lines_up(browser, width):  # noqa: F811
    """Capped at 600px, the input stopped short of the title and scope
    buttons above it and left a blank band down the right of the card; the
    selector link was centred under it."""
    ctx, page, _ = _page(browser, "dark", width)
    try:
        card_l, card_r, input_l, input_r, text_l, sub_l = page.evaluate("""() => {
            const c = document.querySelector('.audit-input-card').getBoundingClientRect();
            const i = document.querySelector('.input-wrapper').getBoundingClientRect();
            const r = document.createRange();
            r.selectNodeContents(document.getElementById('selector-toggle'));
            const s = document.querySelector('.audit-subtitle').getBoundingClientRect();
            return [c.left, c.right, i.left, i.right, r.getBoundingClientRect().left, s.left];
        }""")
        assert abs((input_l - card_l) - (card_r - input_r)) <= 1
        assert abs(input_l - sub_l) <= 1
        assert abs(text_l - input_l) <= 1
    finally:
        ctx.close()
