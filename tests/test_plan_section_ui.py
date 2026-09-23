"""Doc 64: What to do, rendered.

Each plan row opens to why it matters, what to change and how to confirm
the change worked, so the reader does not have to open a card and assemble
the plan from it. The Authentication Resilience panel is gone from the top
of the page and is a section inside the DMARC card.

The browser checks render the Doc 38 fixture zone in headless Chromium
through renderResults(), the way tests/test_ui_consistency_a11y.py does;
they skip where Chromium is not installed, and CI installs it.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_ui_consistency_a11y as ui  # noqa: E402

_page = ui._page
_render = ui._render
browser = ui.browser
fixture_result = ui.fixture_result
DOMAIN = ui.DOMAIN


# ---------------------------------------------------------------
# The section and its rows
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_one_row_per_roadmap_item_and_each_row_opens(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        expected = [i["action"] for i in fixture_result["security_roadmap"]["items"]]
        assert expected, "the fixture produced no plan rows"

        m = page.evaluate("""() => ({
            heading: document.querySelector('.priority-header span').textContent.trim(),
            actions: [...document.querySelectorAll('.priority-action')]
                .map(a => a.textContent.trim()),
            closed: [...document.querySelectorAll('.priority-body')]
                .filter(b => b.classList.contains('is-hidden')).length,
            heads: [...document.querySelectorAll('.priority-head')].map(h => ({
                aria: h.getAttribute('aria-expanded'),
                controls: !!document.getElementById(h.getAttribute('aria-controls')),
            })),
        })""")
        assert m["heading"] == "What to do"
        assert m["actions"] == expected
        assert m["closed"] == len(expected), "a plan row rendered open"
        assert all(h["aria"] == "false" and h["controls"] for h in m["heads"])

        opened = page.evaluate("""() => {
            const rows = [...document.querySelectorAll('.priority-row')];
            return rows.map(r => {
                r.querySelector('.priority-head').click();
                return {
                    aria: r.querySelector('.priority-head').getAttribute('aria-expanded'),
                    open: !r.querySelector('.priority-body').classList.contains('is-hidden'),
                    parts: [...r.querySelectorAll('.plan-part-label')].map(l => l.textContent),
                    link: (r.querySelector('.priority-body .plan-card-link') || {}).textContent,
                };
            });
        }""")
        for row in opened:
            assert row["open"] and row["aria"] == "true", row
            assert row["parts"][-2:] == ["What to change", "How to confirm"], row
            assert row["link"].startswith("Open the "), row
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_dmarc_row_carries_its_own_record(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        rows = page.evaluate("""() => [...document.querySelectorAll('.priority-row')]
            .filter(r => r.querySelector('.priority-protocol').textContent.trim() === 'DMARC')
            .map(row => {
                row.querySelector('.priority-head').click();
                const body = row.querySelector('.priority-body');
                const host = body.querySelector('.plan-record-host');
                const rec = body.querySelector('.record-text');
                return {
                    action: row.querySelector('.priority-action').textContent.trim(),
                    host: host ? host.textContent.replace(/\\s+/g, ' ').trim() : null,
                    record: rec ? rec.textContent.trim() : null,
                    copy: !!body.querySelector('.copy-btn'),
                    why: body.querySelector('.plan-part-body').textContent.trim(),
                    confirm: [...body.querySelectorAll('.plan-part-body')].pop().textContent.trim(),
                };
            })""")
        items = {i["action"]: i for i in fixture_result["security_roadmap"]["items"]
                 if i["protocol"] == "DMARC"}
        # The first DMARC row is the p=none one: the resilience risk sentence
        # moved onto it.
        assert "p=none is the right starting point" in rows[0]["why"]
        assert rows[0]["confirm"].startswith("Run this audit again after the change has propagated.")
        assert "This row disappears when the check passes." in rows[0]["confirm"]
        # A row with its own record shows that record, not the readiness one.
        with_record = [r for r in rows if items[r["action"]].get("record")]
        assert with_record
        for r in with_record:
            assert r["host"] == f"TXT record at _dmarc.{DOMAIN}"
            assert r["record"] == items[r["action"]]["record"]
            assert r["copy"]
        assert errors == []
    finally:
        ctx.close()


def test_a_row_with_no_record_and_no_fix_text_points_at_the_card(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        html = page.evaluate("""() => _planWhat(
            {protocol: 'SPF', action: 'Review the SPF findings'},
            {name: 'SPF', status: 'warn'}, 'check-spf').html""")
        assert 'data-scroll-to="check-spf"' in html
        assert "See the SPF card below" in html
        assert "record-text" not in html, "a row with no record must not invent one"
        assert errors == []
    finally:
        ctx.close()


def test_a_row_whose_card_has_fix_records_shows_them(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        html = page.evaluate("""() => _planWhat(
            {protocol: 'TLS-RPT', action: 'Configure TLS-RPT for failure visibility'},
            {name: 'TLS-RPT', status: 'absent', fix_records: [
                {host: '_smtp._tls.doc48.test', type: 'TXT',
                 value: 'v=TLSRPTv1; rua=mailto:tls@doc48.test'}]},
            'check-tls-rpt').html""")
        assert "_smtp._tls.doc48.test" in html
        assert "v=TLSRPTv1; rua=mailto:tls@doc48.test" in html
        assert "copy-btn" in html
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Authentication Resilience moved into the DMARC card
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_resilience_panel_is_in_the_dmarc_card_not_above_it(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        assert page.evaluate("() => !!document.getElementById('resilience-section')") is False
        assert page.evaluate("""() => document.querySelectorAll(
            '#results-section > .resilience-block').length""") == 0

        page.evaluate("() => document.querySelector('#check-dmarc .result-header').click()")
        page.evaluate("""() => document.querySelector(
            '#check-dmarc .card-details > [role="heading"] > .cd-header').click()""")
        page.wait_for_timeout(300)
        m = page.evaluate("""() => {
            const head = [...document.querySelectorAll(
                '#check-dmarc .cd-subsection > [role="heading"] > .cd-header')].find(
                h => h.querySelector('.cd-header-title').textContent.trim()
                     === 'Authentication resilience');
            if (!head) return null;
            head.click();
            const body = document.getElementById(head.getAttribute('aria-controls'));
            return {
                summary: head.querySelector('.cd-header-count').textContent.trim(),
                mechanisms: [...body.querySelectorAll('.resilience-mech-name')]
                    .map(n => n.textContent),
                text: body.textContent.replace(/\\s+/g, ' ').trim(),
            };
        }""")
        assert m, "the DMARC card has no Authentication resilience section"
        assert m["summary"] == fixture_result["resilience"]["level"].capitalize()
        assert m["mechanisms"] == ["SPF", "DKIM", "DMARC"]
        # The risk sentence is on the DMARC plan row for a p=none policy, so
        # it is said once, not twice.
        assert "p=none is the right starting point" not in m["text"]
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# The two Doc 63 Details summaries
# ---------------------------------------------------------------

def test_the_subdomain_summary_counts_names_that_exist(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        one_exposed = {"total_probed": 20, "subdomains": (
            [{"exists": True, "status": "exposed"}]
            + [{"exists": False, "status": "exposed"} for _ in range(19)])}
        two_exposed = {"total_probed": 20, "subdomains": (
            [{"exists": True, "status": "exposed"} for _ in range(2)]
            + [{"exists": False, "status": "exposed"} for _ in range(18)])}
        got = page.evaluate("""([one, two, fixture]) => ({
            one: _subdomainAuditSummary(one),
            two: _subdomainAuditSummary(two),
            fixture: _subdomainAuditSummary(fixture),
        })""", [one_exposed, two_exposed, fixture_result.get("subdomain_audit") or {}])
        assert got["one"] == "1 of 20 probed subdomains exists and is exposed"
        assert got["two"] == "2 of 20 probed subdomains exposed"
        # On the fixture zone not one of the twenty probed names resolves.
        assert got["fixture"] == "20 subdomains probed, none exposed"
        assert errors == []
    finally:
        ctx.close()


def test_the_tag_summary_counts_the_tags_in_the_record(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        breakdown = next(c for c in fixture_result["checks"]
                         if c["name"] == "DMARC")["tag_breakdown"]
        present = [t for t in breakdown["tags"] if not t.get("is_absent")]
        summary = page.evaluate("bd => _tagBreakdownSummary(bd)", breakdown)

        # v, p, pct and rua are published; fourteen rows are rendered.
        assert len(present) == 4 and len(breakdown["tags"]) == 14
        assert summary == "4 tags, 1 removed in RFC 9989"

        six_tags = {"tags": (
            [{"tag": t, "dmarcbis": "current"} for t in ("v", "p", "sp", "np")]
            + [{"tag": t, "dmarcbis": "deprecated"} for t in ("pct", "ri")]
            + [{"tag": "adkim", "is_absent": True, "dmarcbis": "current"}])}
        assert page.evaluate("bd => _tagBreakdownSummary(bd)",
                             six_tags) == "6 tags, 2 removed in RFC 9989"
        assert errors == []
    finally:
        ctx.close()


def test_the_fixture_still_carries_a_subdomain_audit(fixture_result):
    sa = fixture_result.get("subdomain_audit") or {}

    assert sa.get("total_probed") == 20
    assert json.dumps(sa)  # serialisable, which is how the page receives it
