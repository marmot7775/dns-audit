"""Collapsed result cards take their content out of reach (Doc 73).

A closed card hides its body with a zero-height grid row, which hides it
from the eye only. setCardExpanded() is the one place a card opens or
closes, and it makes the body inert while the card is closed, so Tab and
a screen reader skip what the reader cannot see. Browser tests on the
fixture results page.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_ui_consistency_a11y import (  # noqa: F401
    _page,
    _render,
    _run,
    _zone,
    browser,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Visible links and buttons inside a card body. Controls inside a closed
# Details section are display none and out of scope here.
_CONTROLS_JS = """sel => [...document.querySelectorAll(sel)]
    .filter(e => e.getClientRects().length > 0)
    .map(e => { if (!e.dataset.probe) e.dataset.probe = 'p' + Math.random().toString(36).slice(2);
                return e.dataset.probe; })"""


@pytest.fixture(scope="module")
def data():
    return json.loads(json.dumps(_run(_zone()), default=str))


@pytest.fixture
def results_page(browser, data):  # noqa: F811
    ctx, pg, errors = _page(browser, "dark", 1280)
    _render(pg, data)
    yield pg
    assert not errors, errors
    ctx.close()


def _tab_walk(page, limit=800):
    """Tab from the domain field to the end of the page. Each stop records
    its probe id and whether it sits inside a collapsed card's body."""
    page.focus("#domain-input")
    stops = []
    for _ in range(limit):
        page.keyboard.press("Tab")
        stop = page.evaluate("""() => {
            const e = document.activeElement;
            if (!e || e === document.body) return null;
            if (!e.dataset.probe) e.dataset.probe = 'p' + Math.random().toString(36).slice(2);
            return {id: e.dataset.probe,
                    hidden: !!e.closest('.result-card:not(.expanded) .result-body'),
                    html: e.outerHTML.slice(0, 80)};
        }""")
        if stop is None or (stops and stop["id"] == stops[0]["id"]):
            break
        if stop["id"] in {s["id"] for s in stops}:
            break
        stops.append(stop)
    return stops


def _body_controls(page, card_id):
    return set(page.evaluate(_CONTROLS_JS,
                             f"#{card_id} .result-body a[href], #{card_id} .result-body button"))


def _press_header(page, card_id):
    page.focus(f"#{card_id} .result-header")
    page.keyboard.press("Enter")


def test_tab_never_lands_inside_a_collapsed_card(results_page):
    page = results_page
    assert page.eval_on_selector_all(".result-card.expanded", "els => els.length") == 0
    stops = _tab_walk(page)
    assert any(s["html"].startswith('<div class="result-header"') for s in stops)
    assert [s["html"] for s in stops if s["hidden"]] == []


def test_every_card_body_is_inert_from_the_first_paint(results_page):
    page = results_page
    states = page.eval_on_selector_all(
        ".result-card", "els => els.map(c => [c.id, c.querySelector('.result-body').inert])")
    assert states and all(inert for _, inert in states), states


def test_enter_opens_the_body_to_tab_and_closing_takes_it_away(results_page):
    page = results_page
    controls = _body_controls(page, "check-dmarc")
    assert controls
    _press_header(page, "check-dmarc")
    assert page.get_attribute("#check-dmarc .result-header", "aria-expanded") == "true"
    reached = {s["id"] for s in _tab_walk(page)}
    assert controls <= reached, controls - reached

    _press_header(page, "check-dmarc")
    assert page.get_attribute("#check-dmarc .result-header", "aria-expanded") == "false"
    stops = _tab_walk(page)
    assert not controls & {s["id"] for s in stops}
    assert [s["html"] for s in stops if s["hidden"]] == []


def test_expand_all_then_collapse_all(results_page):
    page = results_page
    cards = page.eval_on_selector_all(".result-card", "els => els.map(e => e.id)")
    controls = set().union(*(_body_controls(page, c) for c in cards))
    assert controls

    page.click("#toggle-all-btn")
    assert page.eval_on_selector_all(
        ".result-card .result-header", "els => els.every(h => h.getAttribute('aria-expanded') === 'true')")
    reached = {s["id"] for s in _tab_walk(page)}
    assert controls <= reached, controls - reached

    page.click("#toggle-all-btn")
    assert page.eval_on_selector_all(".result-card.expanded", "els => els.length") == 0
    stops = _tab_walk(page)
    assert not controls & {s["id"] for s in stops}
    assert [s["html"] for s in stops if s["hidden"]] == []


def test_a_priorities_link_opens_a_reachable_card(results_page):
    page = results_page
    link = page.query_selector("#priority-list .plan-card-link[data-scroll-to]")
    assert link is not None
    target = link.get_attribute("data-scroll-to")
    link.evaluate("e => e.click()")
    card = page.evaluate_handle("id => document.getElementById(id).closest('.result-card')", target)
    assert card.evaluate("c => c.querySelector('.result-header').getAttribute('aria-expanded')") == "true"
    assert card.evaluate("c => c.querySelector('.result-body').inert") is False
    assert page.evaluate("""id => { const t = document.getElementById(id);
        const c = t.closest('.result-card');
        const e = t.matches('a[href],button,[tabindex]') ? t
            : (t.querySelector('a[href],button,[tabindex="0"]')
               || c.querySelector('.result-body a[href], .result-body button'));
        e.focus(); return document.activeElement === e; }""", target)


def _exposed(cdp, card_id):
    """Accessibility-tree nodes under a card's body that are not ignored."""
    doc = cdp.send("DOM.getDocument", {"depth": -1})
    ids = cdp.send("DOM.querySelectorAll", {
        "nodeId": doc["root"]["nodeId"],
        "selector": f"#{card_id} .result-body, #{card_id} .result-body *"})["nodeIds"]
    backend = {cdp.send("DOM.describeNode", {"nodeId": i})["node"]["backendNodeId"] for i in ids}
    nodes = cdp.send("Accessibility.getFullAXTree")["nodes"]
    return [n for n in nodes if n.get("backendDOMNodeId") in backend and not n.get("ignored")]


def test_a_collapsed_body_is_absent_from_the_accessibility_tree(results_page):
    page = results_page
    cdp = page.context.new_cdp_session(page)
    assert _exposed(cdp, "check-spf") == []
    page.click("#check-spf .result-header")
    assert _exposed(cdp, "check-spf")
    page.click("#check-spf .result-header")
    assert _exposed(cdp, "check-spf") == []


def test_the_open_and_close_animation_is_unchanged(results_page):
    page = results_page
    assert page.eval_on_selector(
        "#check-spf .result-body", "b => getComputedStyle(b).transitionProperty") == "grid-template-rows"
    page.click("#check-spf .result-header")
    heights = []
    for _ in range(6):
        heights.append(page.eval_on_selector("#check-spf .result-body", "b => b.getBoundingClientRect().height"))
        page.wait_for_timeout(60)
    page.wait_for_timeout(600)
    full = page.eval_on_selector("#check-spf .result-body", "b => b.getBoundingClientRect().height")
    assert any(0 < h < full for h in heights), (heights, full)


def test_one_helper_sets_the_expanded_state():
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        js = f.read()
    assert "function setCardExpanded(card, open)" in js
    assert js.count("classList.toggle('expanded'") == 1
    assert "classList.add('expanded')" not in js
