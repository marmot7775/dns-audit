"""Details content fits its panel at every width (Doc 79).

Each Details panel (.cd-section) clips at its border with overflow hidden,
and so does the card body that drives the open and close animation. Long
unbroken values inside them (record values, tag chips, SPF include names,
the header summaries) used to run past that edge and were cut off. They
now wrap inside their own box, or scroll inside their own container.

The four results are live audits of github.com, paypal.com, bbc.co.uk and
ietf.org, saved from dns-audit.com at bce461c on 2026-09-29. Every card
and every Details panel is opened, then each width is measured in both
themes.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_ui_consistency_a11y import (  # noqa: F401
    _page,
    _render,
    browser,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "details_width")
DOMAINS = ["github.com", "paypal.com", "bbc.co.uk", "ietf.org"]
WIDTHS = [1280, 820, 390, 320]

OPEN_ALL_JS = """() => {
    document.querySelectorAll('.result-card').forEach(c => setCardExpanded(c, true));
    document.querySelectorAll('.result-card .cd-body.is-hidden').forEach(b => {
        b.classList.remove('is-hidden');
        const h = b.parentElement.querySelector('.cd-header');
        if (h) h.setAttribute('aria-expanded', 'true');
    });
}"""

# For every element and every text run inside a card, find the nearest
# ancestor that clips horizontally. A scroll container on the way up means
# the content scrolls rather than being cut, so it is not a clip. Text is
# measured with a Range, because a block box can sit inside the panel while
# the unbroken text in it runs past.
MEASURE_JS = r"""() => {
    const clips = ox => ox === 'hidden' || ox === 'clip';
    const scrolls = ox => ox === 'auto' || ox === 'scroll';
    const clipOf = el => {
        for (let a = el.parentElement; a; a = a.parentElement) {
            const ox = getComputedStyle(a).overflowX;
            if (scrolls(ox)) return null;
            if (clips(ox)) return a;
            if (a.classList.contains('result-card')) return null;
        }
        return null;
    };
    const edge = a => a.getBoundingClientRect().left + a.clientLeft + a.clientWidth;
    const name = e => e.tagName.toLowerCase() + (typeof e.className === 'string' && e.className
        ? '.' + e.className.trim().split(/\s+/).join('.') : '');
    const cut = [];
    for (const card of document.querySelectorAll('.result-card')) {
        for (const el of card.querySelectorAll('*')) {
            if (!el.getClientRects().length || el.closest('.sr-only')) continue;
            const a = clipOf(el);
            if (a && el.getBoundingClientRect().right > edge(a) + 0.5)
                cut.push(`${card.id} ${name(el)} past ${name(a)}`);
        }
        const walker = document.createTreeWalker(card, NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
            const el = n.parentElement;
            if (!n.textContent.trim() || !el.getClientRects().length || el.closest('.sr-only')) continue;
            const ox = getComputedStyle(el).overflowX;
            if (scrolls(ox)) continue;
            const a = clips(ox) ? el : clipOf(el);
            if (!a) continue;
            const r = document.createRange();
            r.selectNodeContents(n);
            const right = Math.max(...[...r.getClientRects()].map(x => x.right));
            if (right > edge(a) + 0.5)
                cut.push(`${card.id} "${n.textContent.trim().slice(0, 40)}" past ${name(a)}`);
        }
    }
    const counts = [...document.querySelectorAll('.cd-header-count')]
        .filter(c => c.getClientRects().length && c.scrollWidth > c.clientWidth)
        .map(c => c.textContent.trim());
    const headers = [...document.querySelectorAll('.result-card .cd-header')]
        .filter(h => h.getClientRects().length)
        .map(h => h.getBoundingClientRect().height);
    return {cut, counts, headers, docWidth: document.documentElement.scrollWidth,
            viewport: window.innerWidth};
}"""


@pytest.fixture(scope="module")
def results():
    out = {}
    for d in DOMAINS:
        with open(os.path.join(FIXTURES, d + ".json")) as f:
            out[d] = json.load(f)
    return out


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("domain", DOMAINS)
def test_details_content_fits_its_panel(browser, results, domain, theme):  # noqa: F811
    ctx, page, errors = _page(browser, theme, WIDTHS[0])
    try:
        _render(page, results[domain])
        page.evaluate(OPEN_ALL_JS)
        failures = []
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(400)
            m = page.evaluate(MEASURE_JS)
            if m["cut"]:
                failures.append(f"{width}px: {len(m['cut'])} cut off, e.g. {m['cut'][:5]}")
            if m["counts"]:
                failures.append(f"{width}px: header summary ellipsized: {m['counts']}")
            if m["docWidth"] != m["viewport"]:
                failures.append(f"{width}px: page scrolls sideways ({m['docWidth']})")
            if width <= 640 and min(m["headers"]) < 44:
                failures.append(f"{width}px: a Details header is under 44px ({min(m['headers'])})")
        assert not failures, failures
        assert errors == []
    finally:
        ctx.close()


def test_the_card_body_still_clips_for_its_animation():
    css = open(os.path.join(os.path.dirname(FIXTURES), "..", "..", "static", "style.css")).read()
    body = css.split(".result-body {", 1)[1].split("}", 1)[0]
    assert "overflow: hidden" in body
    assert "grid-template-rows: 0fr" in body
