"""The results page and the PDF answer a first-time visitor in one order:
the verdict with counts that match the list, What to do with its first row
open, the sender requirements, then every check behind one closed toggle.

The browser checks render the Doc 38 fixture zone in headless Chromium
through renderResults(), as tests/test_results_page_hierarchy.py does; they
skip where Chromium is not installed, and CI installs it.
"""
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_ui_consistency_a11y as ui  # noqa: E402

_page = ui._page
_render = ui._render
browser = ui.browser
fixture_result = ui.fixture_result

THEMES = ["dark", "light"]


def _row_counts(page):
    """Rows per tier as the list holds them, and the counts as the headline
    and the What to do heading print them."""
    return page.evaluate("""() => {
        const rows = [...document.querySelectorAll('#priority-list .priority-row')];
        const byTier = {};
        rows.forEach(r => { byTier[r.dataset.tier] = (byTier[r.dataset.tier] || 0) + 1; });
        return {
            byTier,
            headline: [...document.querySelectorAll('#executive-summary .es-count')]
                .map(b => [b.dataset.planTier, parseInt(b.textContent, 10), b.textContent]),
            heading: document.getElementById('priority-summary').textContent,
        };
    }""")


# ---------------------------------------------------------------
# The headline counts are the list's counts
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", THEMES)
def test_headline_counts_match_the_rows_in_the_list(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        m = _row_counts(page)
        assert m["headline"], "the fixture has plan rows"
        for tier, n, _text in m["headline"]:
            assert m["byTier"].get(tier, 0) == n, (tier, n, m["byTier"])
        # Every row is counted by some headline part, and none twice.
        assert sum(n for _t, n, _x in m["headline"]) == sum(m["byTier"].values())
        # The heading over the list says the same words.
        assert ", ".join(x for _t, _n, x in m["headline"]) == m["heading"]
        assert errors == []
    finally:
        ctx.close()


def test_a_count_opens_its_first_row(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        tiers = [b for b in page.evaluate(
            "() => [...document.querySelectorAll('#executive-summary .es-count')]"
            ".map(b => b.dataset.planTier)")]
        last = tiers[-1]
        page.click(f'#executive-summary .es-count[data-plan-tier="{last}"]')
        page.wait_for_timeout(700)
        state = page.evaluate("""tier => {
            const row = document.querySelector(`#priority-list .priority-row[data-tier="${tier}"]`);
            const head = row.querySelector('.priority-head');
            const body = document.getElementById(head.getAttribute('aria-controls'));
            const r = row.getBoundingClientRect();
            return {open: head.getAttribute('aria-expanded'), shown: body.offsetHeight > 0,
                    top: r.top, vh: innerHeight};
        }""", last)
        assert state["open"] == "true" and state["shown"], state
        assert 0 <= state["top"] < state["vh"], state
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# What to do is the primary list: first row open, whole row a button
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", THEMES)
def test_first_row_is_open_and_the_rest_are_closed(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        m = page.evaluate("""() => {
            const heads = [...document.querySelectorAll('#priority-list .priority-head')];
            const info = h => {
                const body = document.getElementById(h.getAttribute('aria-controls'));
                return {aria: h.getAttribute('aria-expanded'), shown: body.offsetHeight > 0,
                        cue: h.querySelector('.priority-cue').textContent};
            };
            const first = document.querySelector('#priority-list > .priority-row .priority-head');
            return {
                total: heads.length,
                first: info(first),
                firstIsFirst: heads[0] === first,
                firstHasRecord: !!document.getElementById(first.getAttribute('aria-controls'))
                    .querySelector('.plan-part'),
                rest: heads.slice(1).filter(h => h.offsetParent !== null).map(info),
            };
        }""")
        assert m["total"] >= 1 and m["firstIsFirst"]
        assert m["first"] == {"aria": "true", "shown": True, "cue": "Hide fix"}, m["first"]
        assert m["firstHasRecord"]
        for r in m["rest"]:
            assert r == {"aria": "false", "shown": False, "cue": "Show fix"}, r
        assert errors == []
    finally:
        ctx.close()


def test_the_whole_row_opens_it_by_click_and_by_keyboard(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        heads = page.locator("#priority-list > .priority-row .priority-head")
        assert heads.count() >= 2, "the fixture needs two main rows"
        second = heads.nth(1)
        assert second.get_attribute("role") == "button"
        assert second.get_attribute("tabindex") == "0"
        assert second.get_attribute("aria-expanded") == "false"
        # A click on the text, not the chevron.
        second.locator(".priority-text").click()
        assert second.get_attribute("aria-expanded") == "true"
        assert second.locator(".priority-cue").text_content() == "Hide fix"
        second.focus()
        page.keyboard.press("Enter")
        assert second.get_attribute("aria-expanded") == "false"
        page.keyboard.press("Space")
        assert second.get_attribute("aria-expanded") == "true"
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Technical details: one closed section under What to do
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", THEMES)
def test_checks_start_behind_one_closed_toggle(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        m = page.evaluate("""() => {
            const t = document.getElementById('tech-toggle');
            const body = document.getElementById('technical-body');
            const plan = document.getElementById('priority-section');
            return {
                aria: t.getAttribute('aria-expanded'),
                label: document.getElementById('tech-toggle-label').textContent,
                bodyShown: body.offsetHeight > 0,
                cardsInside: body.querySelectorAll('.result-card').length,
                cardsOutside: [...document.querySelectorAll('.result-card')]
                    .filter(c => !body.contains(c)).length,
                expandAllInside: body.contains(document.getElementById('toggle-all-btn')),
                copyAllInside: body.contains(document.getElementById('copy-all-btn')),
                visibleCards: [...document.querySelectorAll('.result-card')]
                    .filter(c => c.offsetHeight > 0).length,
                afterPlan: !!(plan.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_FOLLOWING),
                cards: document.querySelectorAll('.result-card').length,
            };
        }""")
        assert m["aria"] == "false"
        assert m["label"] == "Show all 12 checks", m["label"]
        assert not m["bodyShown"] and m["visibleCards"] == 0
        assert m["cardsInside"] == m["cards"] and m["cardsOutside"] == 0
        assert m["expandAllInside"] and m["copyAllInside"]
        assert m["afterPlan"]
        # Nothing is deleted: the cards are in the document, closed.
        assert m["cards"] == 12, m["cards"]
        assert errors == []
    finally:
        ctx.close()


def test_the_toggle_opens_and_closes_the_checks(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        page.click("#tech-toggle")
        assert page.get_attribute("#tech-toggle", "aria-expanded") == "true"
        assert page.text_content("#tech-toggle-label") == "Hide all 12 checks"
        assert page.locator("#results-list .result-card").first.is_visible()
        page.click("#toggle-all-btn")
        assert page.locator("#results-list .result-card.expanded").count() > 0
        page.click("#tech-toggle")
        assert page.get_attribute("#tech-toggle", "aria-expanded") == "false"
        assert not page.locator("#results-list .result-card").first.is_visible()
        assert errors == []
    finally:
        ctx.close()


def test_a_link_to_a_check_opens_the_section_that_holds_it(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        page.evaluate("openCard('check-dmarc')")
        page.wait_for_timeout(700)
        assert page.get_attribute("#tech-toggle", "aria-expanded") == "true"
        assert page.locator("#check-dmarc").is_visible()
        assert errors == []
    finally:
        ctx.close()


def test_a_new_audit_closes_the_section_again(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        assert page.get_attribute("#tech-toggle", "aria-expanded") == "true"
        _render(page, fixture_result, open_checks=False)
        assert page.get_attribute("#tech-toggle", "aria-expanded") == "false"
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Order: sender requirements sit under What to do, closed
# ---------------------------------------------------------------

def test_page_order_is_verdict_plan_requirements_checks(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result, open_checks=False)
        order = page.evaluate("""() => {
            const ids = ['executive-summary', 'sender-map-slot', 'priority-section',
                         'requirements-slot', 'technical-section'];
            const y = ids.map(id => document.getElementById(id).getBoundingClientRect().top
                                    + scrollY);
            return {ids, y, req: document.querySelector('#requirements-slot .req-block'),
                    reqOpen: document.querySelector('#requirements-slot .req-block')
                        && document.querySelector('#requirements-slot .req-block').open,
                    reqSummaryHeight: document.querySelector('.req-head').offsetHeight};
        }""")
        ys = [y for i, y in zip(order["ids"], order["y"]) if i != "sender-map-slot"]
        assert ys == sorted(ys), order
        assert order["reqOpen"] is False
        # One heading and one summary line, not the checklist.
        assert order["reqSummaryHeight"] < 120, order["reqSummaryHeight"]
        assert page.locator("#requirements-slot .req-list").first.is_hidden()
        page.click("#requirements-slot .req-head")
        assert page.locator("#requirements-slot .req-list").first.is_visible()
        assert errors == []
    finally:
        ctx.close()


def test_the_sender_map_stays_above_the_plan():
    html = open(os.path.join(ui.STATIC, "index.html"), encoding="utf-8").read()
    assert html.index('id="sender-map-slot"') < html.index('id="priority-section"')
    assert html.index('id="priority-section"') < html.index('id="requirements-slot"')
    assert html.index('id="requirements-slot"') < html.index('id="technical-section"')


# ---------------------------------------------------------------
# Every card paints: the blank boxes in a full-page screenshot
# ---------------------------------------------------------------

def test_no_card_skips_painting_so_none_prints_blank(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => [...document.querySelectorAll('.result-card')].map(c => ({
            id: c.id, cv: getComputedStyle(c).contentVisibility, h: c.offsetHeight}))""")
        assert all(c["cv"] == "visible" for c in m), m
        # Closed, a card is one short row; none is held at a 302px placeholder.
        assert all(c["h"] < 120 for c in m), m
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Narrow screens, both themes: no sideways scroll, 44px targets
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("width", [320, 375])
def test_narrow_widths_have_no_horizontal_scroll_and_big_targets(
        browser, fixture_result, theme, width):
    ctx, page, errors = _page(browser, theme, width)
    try:
        _render(page, fixture_result, open_checks=False)
        m = page.evaluate("""() => {
            const small = sel => [...document.querySelectorAll(sel)]
                .filter(e => e.offsetParent !== null && e.getBoundingClientRect().height < 43.5)
                .map(e => sel + ' ' + Math.round(e.getBoundingClientRect().height));
            return {
                scrollW: document.documentElement.scrollWidth, vw: innerWidth,
                small: [...small('.es-count'), ...small('.priority-head'),
                        ...small('.plan-optional-toggle'), ...small('#tech-toggle'),
                        ...small('.req-head')],
                wide: [...document.querySelectorAll('.priority-row, .es-block, .req-block, #tech-toggle')]
                    .filter(e => e.getBoundingClientRect().right > innerWidth + 0.5)
                    .map(e => e.className),
            };
        }""")
        assert m["scrollW"] <= m["vw"], m
        assert m["small"] == [], m["small"]
        assert m["wide"] == [], m["wide"]
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# The PDF follows the page
# ---------------------------------------------------------------

@pytest.fixture(scope="module")
def pdf_data(fixture_result):
    return fixture_result


def _pdf_text(data, appendix):
    pypdf = pytest.importorskip("pypdf")
    import pdf_report
    reader = pypdf.PdfReader(io.BytesIO(pdf_report.generate_pdf(data, appendix=appendix)))
    return "\n".join(p.extract_text() for p in reader.pages)


@pytest.mark.parametrize("appendix", [False, True], ids=["short", "appendix"])
def test_pdf_order_is_verdict_counts_fixes_requirements_checks(pdf_data, appendix):
    text = _pdf_text(pdf_data, appendix)
    marks = ["The short answer", "What to do", "Gmail, Yahoo, and Microsoft sender requirements",
             "Checks"]
    at = []
    for m in marks:
        hit = re.search(r"(?m)^\s*(?:\d\s+)?" + re.escape(m) + r"\b", text)
        assert hit, f"{m!r} is missing from the PDF"
        at.append(hit.start())
    assert at == sorted(at), dict(zip(marks, at))
    assert "Do these first" not in text, "the plan's first rows are not listed twice"


@pytest.mark.parametrize("appendix", [False, True], ids=["short", "appendix"])
def test_pdf_counts_match_the_plan_and_every_row_is_written_out(pdf_data, appendix):
    import pdf_report
    text = _pdf_text(pdf_data, appendix)
    items = pdf_data["security_roadmap"]["items"]
    optional = [i for i in items if pdf_report._is_optional_item(i)]
    main = [i for i in items if not pdf_report._is_optional_item(i)]
    tiers = {}
    for i in main:
        tiers[i["priority"]] = tiers.get(i["priority"], 0) + 1
    if optional:
        tiers["low"] = tiers.get("low", 0) + len(optional)
    head = text.split("What to do")[0]
    for tier, n in tiers.items():
        label = pdf_report.TIER_LABELS[tier].upper()
        assert re.search(rf"{n}\s+{re.escape(label)}", head), (tier, n, head[-400:])
    # A PDF cannot expand: every row carries all four parts.
    assert text.count("What to change") >= len(items)
    assert text.count("How to confirm") >= len(items)
    assert text.count("Why it matters") >= len([i for i in items if i.get("impact")])
