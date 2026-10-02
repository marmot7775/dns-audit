"""Doc 92: results people can read, the page layout.

The first screen is the short answer: the verdict, up to three numbered
actions ("Do these first"), See the plan, and a closed Technical summary
holding the tiles. The plan leads each row with the plain consequence and
gathers optional extras at the end, closed. The counters are one line just
above the cards, the cache badge and Request ID sit at the bottom, and the
services found in DNS are one closed section. Every closed block is inert,
the way setCardExpanded makes a closed card.

The fields the backend adds (plain_name, plain_head, who, optional,
do_first) are injected here, and the page is also checked without them,
since it has to work before the backend change ships.

Browser tests on the Doc 38 fixture zone, as in test_ui_consistency_a11y.
"""
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401

PLAIN = {"DMARC": "Spoofing policy (DMARC)", "SPF": "Approved senders (SPF)"}


def _with_backend_fields(data):
    d = copy.deepcopy(data)
    for c in d["checks"]:
        if c["name"] in PLAIN:
            c["plain_name"] = PLAIN[c["name"]]
    items = d["security_roadmap"]["items"]
    for i in items:
        i["plain_head"] = f"Plain head for {i['action']}."
        i["who"] = "Your DNS host"
        i["optional"] = i["protocol"] in ("MTA-STS", "TLS-RPT", "DANE")
    d["executive_summary"]["do_first"] = [
        {"plain_head": i["plain_head"], "title": i["action"],
         "priority": i["priority"], "protocol": i["protocol"]}
        for i in items if not i["optional"]][:3]
    return d


STATE_JS = """sel => { const e = document.querySelector(sel);
    return e ? {hidden: e.classList.contains('is-hidden') || !e.getClientRects().length,
                inert: e.inert} : null; }"""


def _tab_stops(page, limit=400):
    page.focus("#domain-input")
    seen = []
    for _ in range(limit):
        page.keyboard.press("Tab")
        info = page.evaluate("""() => { const e = document.activeElement;
            if (!e || e === document.body) return null;
            return {inside: !!e.closest('#es-tech, .plan-optional-body, #services-body'),
                    text: (e.textContent || '').trim().slice(0, 40)}; }""")
        if info is None or info in seen[-1:]:
            break
        seen.append(info)
        if len(seen) > 1 and seen[-1] == seen[0]:
            break
    return seen


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_short_answer_comes_first_and_the_tiles_are_closed(browser, fixture_result, theme):  # noqa: F811
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => {
            const es = document.getElementById('executive-summary');
            return {
                label: es.querySelector('.es-first-label').textContent,
                items: [...es.querySelectorAll('.es-first-item')].map(li => li.textContent.trim()),
                buttons: [...es.querySelectorAll(':scope > .es-actions .es-action')].map(b => b.textContent.trim()),
                riskBox: !!document.querySelector('.es-risk'),
                tilesInTech: !!es.querySelector('#es-tech .es-metrics'),
                delivInTech: !!es.querySelector('#es-tech .es-deliverability'),
                defensiveBox: !!document.getElementById('defensive-dns-card'),
            };
        }""")
        assert m["label"] == "Do these first"
        do_first = fixture_result["executive_summary"].get("do_first") or []
        assert do_first, "the backend sends do_first for this fixture"
        # Each item is the plain head, then the action title under it.
        assert m["items"] == [d["plain_head"] + d["title"] for d in do_first], m["items"]
        assert m["buttons"] == ["See the plan", "Technical summary"]
        assert not m["riskBox"] and not m["defensiveBox"]
        assert m["tilesInTech"] and m["delivInTech"]
        assert page.evaluate(STATE_JS, "#es-tech") == {"hidden": True, "inert": True}

        page.click(".es-tech-toggle")
        assert page.evaluate(STATE_JS, "#es-tech") == {"hidden": False, "inert": False}
        assert page.get_attribute(".es-tech-toggle", "aria-expanded") == "true"
        page.click(".es-tech-toggle")
        assert page.evaluate(STATE_JS, "#es-tech") == {"hidden": True, "inert": True}
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_backend_fields_lead_the_actions_rows_and_titles(browser, fixture_result, theme):  # noqa: F811
    data = _with_backend_fields(fixture_result)
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, data)
        m = page.evaluate("""() => ({
            heads: [...document.querySelectorAll('.es-first-head')].map(e => e.textContent),
            titles: [...document.querySelectorAll('.es-first-title')].map(e => e.textContent),
            plain: [...document.querySelectorAll('#priority-list > .priority-row .priority-plain')]
                .map(e => e.textContent),
            dmarcTitle: document.querySelector('#check-dmarc .result-title').textContent,
            dmarcCheck: document.getElementById('check-dmarc').dataset.check,
            optionalLabel: document.querySelector('.plan-optional-toggle').textContent.trim(),
            optionalPills: [...document.querySelectorAll('.plan-optional-body .tag')].map(t => t.textContent),
            mainPills: [...document.querySelectorAll('#priority-list > .priority-row .tag')].map(t => t.textContent),
        })""")
        first = data["executive_summary"]["do_first"]
        assert m["heads"] == [f["plain_head"] for f in first]
        assert m["titles"] == [f["title"] for f in first]
        assert m["plain"] == [f["plain_head"] for f in first]
        assert m["dmarcTitle"] == "Spoofing policy (DMARC)"
        assert m["dmarcCheck"] == "DMARC"
        assert m["optionalLabel"] == "Optional extras (3)"
        assert set(m["optionalPills"]) == {"Optional"}
        assert set(m["mainPills"]) <= {"Fix now", "Important", "Recommended", "Optional"}

        assert page.evaluate(STATE_JS, ".plan-optional-body") == {"hidden": True, "inert": True}
        parts = page.evaluate("""() => { const r = document.querySelector('#priority-list > .priority-row');
            r.querySelector('.priority-head').click();
            return [...r.querySelectorAll('.plan-part')].map(p => [
                p.querySelector('.plan-part-label').textContent,
                p.querySelector('.plan-part-body').textContent.trim()]); }""")
        assert dict(parts)["Who does this"] == "Your DNS host"
        assert [p[0] for p in parts][-2:] == ["Who does this", "How to confirm"]
        page.click(".plan-optional-toggle")
        assert page.evaluate(STATE_JS, ".plan-optional-body") == {"hidden": False, "inert": False}
        assert errors == []
    finally:
        ctx.close()


def test_tab_skips_every_closed_block(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        stops = _tab_stops(page)
        texts = [s["text"] for s in stops]
        assert "Technical summary" in texts and "See the plan" in texts
        assert [s for s in stops if s["inside"]] == [], stops
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("width", [390, 1280])
def test_counters_sit_on_one_line_above_the_cards_and_ids_at_the_bottom(
        browser, fixture_result, width):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => {
            const top = s => document.querySelector(s).getBoundingClientRect().top + scrollY;
            return {
                heading: document.getElementById('results-heading').textContent,
                grid: top('#summary-grid'), plan: top('#priority-section'),
                list: top('#results-list'), meta: top('#results-meta'),
                badgeIn: !!document.querySelector('#results-meta #cache-status-badge'),
                bannerBadge: !!document.querySelector('#domain-banner #cache-status-badge'),
                gridHeight: document.getElementById('summary-grid').getBoundingClientRect().height,
                services: document.getElementById('services-section').compareDocumentPosition(
                    document.getElementById('results-list')) & Node.DOCUMENT_POSITION_PRECEDING,
            };
        }""")
        assert m["heading"] == "Technical details: all 12 checks"
        assert m["plan"] < m["grid"] < m["list"] < m["meta"], m
        assert m["badgeIn"] and not m["bannerBadge"]
        if width == 1280:
            assert m["gridHeight"] < 40, m["gridHeight"]
        assert m["services"], "the services section is not below the cards"
        assert page.evaluate(STATE_JS, "#services-body") == {"hidden": True, "inert": True}
        page.click("#services-toggle")
        assert page.evaluate(STATE_JS, "#services-body") == {"hidden": False, "inert": False}
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_card_verdict_shows_on_a_phone(browser, fixture_result, theme):  # noqa: F811
    ctx, page, errors = _page(browser, theme, 390)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => [...document.querySelectorAll('.result-card')].map(c => {
            const v = c.querySelector('.result-verdict'), h = c.querySelector('.result-header');
            const r = v.getBoundingClientRect(), hr = h.getBoundingClientRect();
            const chev = c.querySelector('.result-chevron').getBoundingClientRect();
            const title = c.querySelector('.result-title').getBoundingClientRect();
            return {shown: r.height > 0 && getComputedStyle(v).display !== 'none',
                    inside: r.right <= hr.right + 0.5, chevronOnFirstLine: chev.top < title.bottom};
        })""")
        assert all(c["shown"] and c["inside"] for c in m), m
        assert all(c["chevronOnFirstLine"] for c in m), m
        assert page.evaluate("document.documentElement.scrollWidth") <= 390
        assert errors == []
    finally:
        ctx.close()


def test_whats_unusual_skips_what_the_plan_covers(browser, fixture_result):  # noqa: F811
    data = copy.deepcopy(fixture_result)
    data["anomalies"] = [
        {"title": "Mixed DKIM key strengths", "description": "d", "severity": "medium"},
        {"title": "MTA-STS configured without TLS-RPT", "description": "e", "severity": "medium"},
        {"title": "Something new", "description": "f", "severity": "medium", "protocol": "BIMI"},
    ]
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        titles = page.eval_on_selector_all(".anomaly-title", "els => els.map(e => e.textContent)")
        # The fixture plan has a TLS-RPT row and no DKIM or BIMI row.
        assert titles == ["Mixed DKIM key strengths", "Something new"], titles
        assert errors == []
    finally:
        ctx.close()


def test_a_defensive_domain_shows_its_signals_in_the_short_answer(browser, fixture_result):  # noqa: F811
    data = copy.deepcopy(fixture_result)
    data["defensive_dns"] = True
    data["defensive_signals"] = ["null_mx", "null_spf", "dmarc_reject"]
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        chips = page.eval_on_selector_all("#executive-summary .es-defensive .defensive-signal",
                                          "els => els.map(e => e.textContent)")
        assert len(chips) == 3, chips
        assert page.query_selector("#defensive-dns-card") is None
        assert errors == []
    finally:
        ctx.close()
