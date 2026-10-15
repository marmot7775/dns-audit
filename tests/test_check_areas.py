"""Doc 101: the result cards sit in three areas.

CHECK_AREAS in static/app.js is the one map from card name to area. These
tests fail if the engine can emit a card name the map does not list, if the
area status lines stop adding up to the summary tiles, or if grouping breaks
a #check-* link, the layout at phone width or either theme.
"""
import ast
import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from test_dmarc_grades import RUA, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

SCOPES = ["complete", "email_full", "dmarc", "transport", "dns_infra", "security_scan"]
AREA_ORDER = ["sending", "receiving", "dns"]
HEADINGS = {"sending": "Sending your mail", "receiving": "Receiving your mail",
            "dns": "Your domain's DNS"}


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def _check_areas():
    """CHECK_AREAS as {area: [names]}, read from app.js source."""
    js = _read("static/app.js")
    block = re.search(r"const CHECK_AREAS = \{(.*?)\n\};", js, re.S).group(1)
    areas = {}
    for key, body in re.findall(r"\n    (\w+): \{(.*?)\n    \},", block, re.S):
        checks = re.search(r"checks: \[([^\]]*)\]", body).group(1)
        areas[key] = re.findall(r"'([^']+)'", checks)
    return areas


def _engine_card_names():
    """Every card name the engine can put in data.checks.

    The "name" of every dict built in a transform_* or *_card function, the
    names the deadline stubs use, and the labels the timeout and error cards
    take. APRF is left out: its card goes in draft_standards, never checks.
    """
    names = set()
    for fname in ("result_transformer.py", "audit_engine.py", "checks_extra.py"):
        tree = ast.parse(_read(fname))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            if "transform" in fn.name or fn.name.endswith("_card"):
                for d in ast.walk(fn):
                    if isinstance(d, ast.Dict):
                        for k, v in zip(d.keys, d.values):
                            if (isinstance(k, ast.Constant) and k.value == "name"
                                    and isinstance(v, ast.Constant)):
                                names.add(v.value)
            for node in ast.walk(fn):
                # _stub_subjects = [("dmarc", "DMARC", "DMARC record"), ...]
                if (isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "_stub_subjects"
                                for t in node.targets)):
                    names.update(e.elts[1].value for e in node.value.elts)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    # _timeout_card("DMARC"), _error_card("SPF", e)
                    if (node.func.id in ("_timeout_card", "_error_card") and node.args
                            and isinstance(node.args[0], ast.Constant)):
                        names.add(node.args[0].value)
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "append"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "_parallel_checks"):
                    # ("mta_sts", run_fn, transform_fn, "MTA-STS"): the label
                    # the timeout and error cards are named with.
                    label = node.args[0].elts[-1]
                    if isinstance(label, ast.Constant):
                        names.add(label.value)
    names.discard("APRF")
    return names


def test_every_card_name_the_engine_can_emit_has_an_area():
    areas = _check_areas()
    mapped = [n for names in areas.values() for n in names]
    assert list(areas) == AREA_ORDER
    assert len(mapped) == len(set(mapped)), "a card is listed under two areas"
    emitted = _engine_card_names()
    assert emitted, "the scan found no card names; it is reading the wrong code"
    missing = emitted - set(mapped)
    assert not missing, f"card names with no entry in CHECK_AREAS: {sorted(missing)}"
    stale = set(mapped) - emitted
    assert not stale, f"CHECK_AREAS lists names the engine never emits: {sorted(stale)}"


def test_a_full_fixture_audit_emits_only_mapped_names(audit):
    mapped = {n for names in _check_areas().values() for n in names}
    data = _run(audit, f"v=DMARC1; p=none; {RUA}")
    names = {c["name"] for c in data["checks"]}
    assert len(names) == 12, names
    assert names <= mapped, names - mapped


def test_the_doc_mapping_is_the_map():
    assert _check_areas() == {
        "sending": ["DMARC", "SPF", "DKIM", "BIMI"],
        "receiving": ["MX Records", "MTA-STS", "TLS-RPT", "DANE"],
        "dns": ["DNSSEC", "CAA", "Nameservers", "Certificate Transparency"],
    }


def test_one_copy_of_the_map():
    hits = []
    for base, _, files in os.walk(os.path.join(ROOT, "static")):
        for f in files:
            if f.endswith((".js", ".html")):
                text = open(os.path.join(base, f), encoding="utf-8").read()
                if "CHECK_AREAS = " in text or "Receiving your mail" in text:
                    hits.append(f)
    assert hits == ["app.js"], hits


def test_area_copy_has_no_dashes():
    js = _read("static/app.js")
    block = re.search(r"const CHECK_AREAS = \{(.*?)\n\};", js, re.S).group(1)
    assert "—" not in block and "–" not in block and " -- " not in block


# ---------------------------------------------------------------
# Browser: the rendered areas
# ---------------------------------------------------------------

def _data(audit, dmarc, **kw):
    return json.loads(json.dumps(_run(audit, dmarc, **kw), default=str))


AREAS_JS = """() => [...document.querySelectorAll('#results-list > section.check-area')].map(s => {
    const h = document.getElementById(s.getAttribute('aria-labelledby'));
    return {
        id: s.id,
        heading: h && h.tagName === 'H3' ? h.querySelector('.check-area-title').textContent : null,
        status: h ? h.querySelector('.check-area-count').textContent : null,
        counts: JSON.parse(s.dataset.counts),
        cards: [...s.querySelectorAll('.result-card')].map(c => c.id),
    };
})"""

GRID_JS = """() => Object.fromEntries(
    ['pass', 'warn', 'fail', 'absent', 'na', 'unavailable'].map(k =>
        [k, Number(document.getElementById('summary-' + k).textContent)]))"""


@pytest.mark.parametrize("scope", SCOPES)
def test_area_counts_add_up_to_the_summary_grid(browser, audit, scope):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}", scope=scope)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        areas = page.evaluate(AREAS_JS)
        grid = page.evaluate(GRID_JS)
        total = {k: sum(a["counts"][k] for a in areas)
                 for k in ("pass", "warn", "fail", "absent", "not_applicable", "unavailable")}
        total["na"] = total.pop("not_applicable")
        assert total == grid, (scope, total, grid)
        # Every card sits in an area, and no area is empty.
        assert sum(len(a["cards"]) for a in areas) == len(
            page.query_selector_all("#results-list .result-card"))
        assert all(a["cards"] for a in areas)
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("scope,expected", [
    ("dmarc", ["area-sending"]),
    ("transport", ["area-receiving"]),
    ("dns_infra", ["area-receiving", "area-dns"]),
    ("complete", ["area-sending", "area-receiving", "area-dns"]),
])
def test_an_area_the_scope_empties_has_no_heading(browser, audit, scope, expected):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}", scope=scope)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        assert [a["id"] for a in page.evaluate(AREAS_JS)] == expected
        assert not errors, errors
    finally:
        ctx.close()


def test_cards_sort_inside_their_area(browser, audit):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}")
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        areas = page.evaluate(AREAS_JS)
        assert [a["heading"] for a in areas] == [HEADINGS[k] for k in AREA_ORDER]
        assert areas[0]["cards"][:3] == ["check-dmarc", "check-spf", "check-dkim"]
        order = {"fail": 0, "warn": 1, "pass": 2, "absent": 3, "unavailable": 4}
        status = {f"check-{c['name'].lower().replace(' ', '-')}": c["status"] for c in data["checks"]}
        for a in areas:
            rest = a["cards"][3:] if a["id"] == "area-sending" else a["cards"]
            ranks = [order.get(status[c], 3) for c in rest]
            assert ranks == sorted(ranks), (a["id"], rest)
        assert not errors, errors
    finally:
        ctx.close()


def test_status_line_words(browser):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        say = lambda **c: page.evaluate("c => areaStatusText(Object.assign(" \
            "{pass: 0, warn: 0, fail: 0, absent: 0, unavailable: 0, not_applicable: 0}, c))", c)
        assert say() == ""
        assert say(**{"pass": 4}) == "All passing"
        assert say(fail=1, warn=2, **{"pass": 1}) == "1 needs fixing · 2 could be stronger · 1 passing"
        assert say(fail=2) == "2 need fixing"
        assert say(absent=1, not_applicable=2, unavailable=1) == \
            "1 optional, not set up · 2 do not apply · 1 not checked"
        assert say(**{"pass": 3}, not_applicable=1) == "3 passing · 1 does not apply"
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [375, 1280])
def test_areas_render_and_links_land_on_their_card(browser, audit, theme, width):  # noqa: F811
    data = _data(audit, f"v=DMARC1; p=none; {RUA}")
    for target in ("check-dmarc", "check-dnssec"):
        ctx, page, errors = _page(browser, theme, width, path=f"/#{target}")
        try:
            _render(page, data)
            page.wait_for_timeout(900)
            areas = page.evaluate(AREAS_JS)
            assert [a["heading"] for a in areas] == [HEADINGS[k] for k in AREA_ORDER]
            assert all(a["status"] for a in areas)
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth")
            assert page.evaluate(
                "() => [...document.querySelectorAll('.check-area-heading')]"
                ".every(h => h.getBoundingClientRect().width > 0)")
            # The link opened its card and the card is on screen, below the
            # sticky header.
            landed = page.evaluate("""id => {
                const c = document.getElementById(id);
                const r = c.getBoundingClientRect();
                const hdr = document.querySelector('.site-header');
                const top = hdr ? hdr.getBoundingClientRect().bottom : 0;
                return {expanded: c.classList.contains('expanded'),
                        top: r.top, header: top, vh: window.innerHeight};
            }""", target)
            assert landed["expanded"], (target, landed)
            assert landed["top"] < landed["vh"], (target, landed)
            assert landed["top"] >= landed["header"] - 1, (target, landed)

            # And again from a closed card through openCard, the call the plan
            # rows and the technical summary shortcuts make.
            page.evaluate("""id => {
                const c = document.getElementById(id);
                setCardExpanded(c, false);
                window.scrollTo(0, 0);
                openCard(id);
            }""", target)
            page.wait_for_timeout(900)
            again = page.evaluate("""id => {
                const c = document.getElementById(id);
                const r = c.getBoundingClientRect();
                return {expanded: c.classList.contains('expanded'), top: r.top, vh: window.innerHeight};
            }""", target)
            assert again["expanded"] and 0 <= again["top"] < again["vh"], (target, again)
            assert not errors, errors
        finally:
            ctx.close()
