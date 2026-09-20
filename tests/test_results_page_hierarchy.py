"""Doc 63: the results page opens as a list, not as everything at once.

Every check card starts collapsed, an opened card shows what was found with
one collapsed Details section under it, and every panel that used to stack
in the card body is still reachable through a labelled sub-header.

The browser checks render the Doc 38 fixture zone in headless Chromium
through renderResults(), the same way tests/test_ui_consistency_a11y.py
does; they skip where Chromium is not installed, and CI installs it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_ui_consistency_a11y as ui  # noqa: E402

# The Doc 38 fixture, the static-file route and the headless browser are the
# ones Doc 48 already set up; both modules render the same zone.
_page = ui._page
_render = ui._render
browser = ui.browser
fixture_result = ui.fixture_result

# The panels the DMARC card files under Details, in the order it builds them.
DMARC_SECTIONS = [
    "Strict Record Validation",
    "Email Spoofing Attack Surface",
    "Subdomain Security",
    "DMARC Record Breakdown",
    "DMARC Policy Discovery (Tree Walk)",
    "RFC 9989 Readiness",
    "DMARC Evaluation",
    "DMARC Report Delivery Chain",
    "Authentication resilience",
    "Change History",
]


def _open_dmarc(page):
    page.evaluate("() => document.querySelector('#check-dmarc .result-header').click()")
    page.wait_for_timeout(400)


def _open_details(page):
    page.evaluate("""() => document.querySelector(
        '#check-dmarc .card-details > [role="heading"] > .cd-header').click()""")
    page.wait_for_timeout(200)


# ---------------------------------------------------------------
# 1. The page opens as twelve closed rows
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_every_card_starts_collapsed_and_the_page_is_short(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => ({
            cards: document.querySelectorAll('.result-card').length,
            expanded: document.querySelectorAll('.result-card.expanded').length,
            headersOpen: document.querySelectorAll(
                '.result-header[aria-expanded="true"]').length,
            headersClosed: document.querySelectorAll(
                '.result-header[aria-expanded="false"]').length,
            emptyVerdicts: [...document.querySelectorAll('.result-card')]
                .filter(c => !c.querySelector('.result-verdict').textContent.trim())
                .map(c => c.id),
            height: document.documentElement.scrollHeight,
            toggle: document.querySelector('#toggle-all-btn span').textContent,
        })""")
        assert m["cards"] == 12, m["cards"]
        assert m["expanded"] == 0, f"{m['expanded']} cards render open"
        assert m["headersOpen"] == 0
        assert m["headersClosed"] == m["cards"]
        assert m["emptyVerdicts"] == [], m["emptyVerdicts"]
        assert m["height"] < 5000, f"the closed page is {m['height']}px tall"
        assert m["toggle"] == "Expand All", m["toggle"]
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# 2. Anything that scrolls to a card opens it
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_priorities_row_opens_the_card_it_points_at(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => {
            const row = document.querySelector('#priority-list [data-scroll-to]');
            row.click();
            return {target: row.dataset.scrollTo};
        }""")
        page.wait_for_timeout(700)
        state = page.evaluate("""id => {
            const card = document.getElementById(id);
            const r = card.getBoundingClientRect();
            return {open: card.classList.contains('expanded'),
                    aria: card.querySelector('.result-header').getAttribute('aria-expanded'),
                    top: r.top, viewport: window.innerHeight};
        }""", m["target"])
        assert state["open"], f"{m['target']} stayed closed"
        assert state["aria"] == "true"
        assert -40 < state["top"] < state["viewport"], state
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_url_hash_opens_the_card_it_names(browser, fixture_result, theme):
    # The harness serves the static pages only, so the audit a ?d= parameter
    # would start cannot run here. The hash is what this exercises: the page
    # loads at /#check-dmarc and the result renders into it.
    ctx, page, errors = _page(browser, theme, 1280, path="/#check-dmarc")
    try:
        _render(page, fixture_result)
        state = page.evaluate("""() => {
            const card = document.getElementById('check-dmarc');
            return {open: card.classList.contains('expanded'),
                    aria: card.querySelector('.result-header').getAttribute('aria-expanded'),
                    top: card.getBoundingClientRect().top,
                    others: document.querySelectorAll('.result-card.expanded').length};
        }""")
        assert state["open"], "the DMARC card stayed closed on a #check-dmarc URL"
        assert state["aria"] == "true"
        assert -40 < state["top"] < 900, state
        assert state["others"] == 1, "the hash opened more than the card it named"
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_executive_summary_buttons_open_their_targets(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        targets = page.evaluate("""() => [...document.querySelectorAll(
            '#executive-summary-slot [data-scroll-to]')].map(b => b.dataset.scrollTo)""")
        assert targets, "the fixture rendered no executive summary buttons"
        for target in targets:
            page.evaluate("""t => document.querySelector(
                `#executive-summary-slot [data-scroll-to="${t}"]`).click()""", target)
            page.wait_for_timeout(500)
            state = page.evaluate("""t => {
                const el = document.getElementById(t);
                const card = el.closest('.result-card');
                return {isCard: !!card, open: card ? card.classList.contains('expanded') : null,
                        top: el.getBoundingClientRect().top};
            }""", target)
            if state["isCard"]:
                assert state["open"], f"{target} was scrolled to but not opened"
            assert -40 < state["top"] < 900, (target, state)
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# 3. One level of hierarchy inside a card
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_an_opened_card_shows_findings_and_one_closed_details_section(
        browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        _open_dmarc(page)
        m = page.evaluate("""() => {
            const card = document.getElementById('check-dmarc');
            const sub = [...card.querySelectorAll(
                '.cd-subsection > [role="heading"] > .cd-header')];
            return {
                body: [...card.querySelectorAll('.result-body-inner > *')]
                    .map(e => e.className),
                detailsHeaders: card.querySelectorAll(
                    '.card-details > [role="heading"] > .cd-header').length,
                detailsCount: card.querySelector(
                    '.card-details > [role="heading"] > .cd-header .cd-header-count')
                    .textContent.trim(),
                titles: sub.map(h => h.querySelector('.cd-header-title').textContent.trim()),
                summaries: sub.map(h => {
                    const c = h.querySelector('.cd-header-count');
                    return c ? c.textContent.trim() : '';
                }),
                subVisible: sub.filter(h => h.offsetParent).length,
                panelsVisible: [...card.querySelectorAll(
                    '.sv-block, .as-block, .sua-block, .record-breakdown, .tree-walk,'
                    + ' .dbis-block, .dmarc-eval, .report-chain, .rcb-block, .cd-change')]
                    .filter(e => e.offsetParent).length,
                controls: sub.every(h => h.getAttribute('aria-expanded') === 'false'
                    && document.getElementById(h.getAttribute('aria-controls'))),
            };
        }""")
        assert "explanation" in m["body"][0]
        assert any(c.startswith("detail-item") for c in m["body"]), m["body"]
        assert "record-block" in m["body"], m["body"]
        assert m["body"][-1] == "card-details-wrap", m["body"]
        assert m["detailsHeaders"] == 1, m["detailsHeaders"]
        assert m["titles"] == DMARC_SECTIONS, m["titles"]
        assert m["detailsCount"] == f"{len(DMARC_SECTIONS)} sections", m["detailsCount"]
        assert all(m["summaries"]), m["summaries"]
        assert m["subVisible"] == 0, "a sub-header showed before Details was opened"
        assert m["panelsVisible"] == 0, "a panel showed before its sub-header was clicked"
        assert m["controls"], "a sub-header is missing aria-expanded or aria-controls"

        # Two clicks reach any panel: Details, then the panel's sub-header.
        _open_details(page)
        opened = page.evaluate("""() => {
            const card = document.getElementById('check-dmarc');
            const sub = [...card.querySelectorAll(
                '.cd-subsection > [role="heading"] > .cd-header')];
            const before = sub.filter(h => h.offsetParent).length;
            const shown = [];
            for (const h of sub) {
                h.click();
                const body = document.getElementById(h.getAttribute('aria-controls'));
                shown.push({title: h.querySelector('.cd-header-title').textContent.trim(),
                            visible: !!body.offsetParent && body.textContent.trim().length > 0,
                            aria: h.getAttribute('aria-expanded')});
            }
            return {before, shown};
        }""")
        assert opened["before"] == len(DMARC_SECTIONS), opened["before"]
        for row in opened["shown"]:
            assert row["visible"], f"{row['title']} did not open"
            assert row["aria"] == "true", row
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# 4. The spec toggle still works from inside Details
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_spec_toggle_inside_details_switches_the_validation_view(
        browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        _open_dmarc(page)
        _open_details(page)
        page.evaluate("""() => document.querySelector(
            '#check-dmarc .cd-subsection > [role="heading"] > .cd-header').click()""")
        page.wait_for_timeout(200)

        def spec_state():
            return page.evaluate("""() => {
                const card = document.getElementById('check-dmarc');
                const spec = card.querySelector('.cd-subsection .spec-label, .sv-block .tag');
                return {
                    bisVisible: [...card.querySelectorAll('.cd-body .spec-dmarcbis .sv-block')]
                        .filter(e => e.offsetParent).length,
                    legacyVisible: [...card.querySelectorAll('.cd-body .spec-legacy .sv-block')]
                        .filter(e => e.offsetParent).length,
                    label: spec ? spec.textContent.trim() : '',
                };
            }""")

        before = spec_state()
        assert before["bisVisible"] == 1 and before["legacyVisible"] == 0, before
        assert before["label"] == "RFC 9989", before

        page.evaluate("() => document.querySelector('#check-dmarc .st-seg-legacy').click()")
        page.wait_for_timeout(200)
        after = spec_state()
        assert after["bisVisible"] == 0 and after["legacyVisible"] == 1, after

        page.evaluate("() => document.querySelector('#check-dmarc .st-seg-dmarcbis').click()")
        page.wait_for_timeout(200)
        assert spec_state() == before
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# 5. Copy All Records does not depend on what is open
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_copy_all_records_copies_the_same_text_open_or_closed(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        page.evaluate("""() => {
            window.__copied = null;
            Object.defineProperty(navigator, 'clipboard', {
                configurable: true,
                value: {writeText: t => { window.__copied = t; return Promise.resolve(); }},
            });
        }""")
        collapsed = page.evaluate("""() => {
            document.getElementById('copy-all-btn').click();
            return window.__copied;
        }""")
        expanded = page.evaluate("""() => {
            document.getElementById('toggle-all-btn').click();
            window.__copied = null;
            document.getElementById('copy-all-btn').click();
            return {text: window.__copied,
                    open: document.querySelectorAll('.result-card.expanded').length};
        }""")
        assert expanded["open"] == 12, "Expand All did not open every card"
        assert collapsed, "Copy All Records copied nothing with the cards collapsed"
        assert collapsed != "No DNS records found."
        assert collapsed == expanded["text"]
        assert errors == []
    finally:
        ctx.close()
