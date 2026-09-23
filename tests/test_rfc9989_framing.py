"""Doc 70: the DMARC card states the RFC 9989 change without overstating it.

Three things the card said around correct facts: an absent pct row showed
"100 (default)" beside a removed badge, the readiness score counted optional
info rows as misses (github.com read "Compatible, 1/4"), and the page called
RFC 7489 obsolete without saying most receivers still run it.
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import DOMAIN, RUA, _card, _pdf_text, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The github.com shape: enforcing, pct=100, no np, no psd.
GITHUB_SHAPE = f"v=DMARC1; p=quarantine; sp=reject; pct=100; {RUA}"
NO_PCT = f"v=DMARC1; p=reject; {RUA}; ruf=mailto:f@{DOMAIN}"
PCT_50 = f"v=DMARC1; p=reject; pct=50; {RUA}"


def _tag(card, name):
    return {t["tag"]: t for t in card["tag_breakdown"]["tags"]}[name]


# ---------------------------------------------------------------
# 1. An absent pct has no value
# ---------------------------------------------------------------

def test_absent_pct_has_no_value_like_rf_and_ri(audit):
    card = _card(_run(audit, NO_PCT))
    pct = _tag(card, "pct")
    assert pct["value"] is None
    assert pct["is_absent"] is True
    assert pct["is_default"] is False
    assert pct["dmarcbis"] == ""
    assert pct["explanation"] == "Not in this record. RFC 9989 removed the tag."
    for sibling in ("rf", "ri"):
        other = _tag(card, sibling)
        assert (other["value"], other["is_default"], other["is_absent"], other["dmarcbis"]) == \
               (pct["value"], pct["is_default"], pct["is_absent"], pct["dmarcbis"])


def test_present_pct_is_unchanged(audit):
    pct = _tag(_card(_run(audit, PCT_50)), "pct")
    assert pct["value"] == "50"
    assert pct["is_absent"] is False
    assert pct["is_default"] is False
    assert pct["dmarcbis"] == "deprecated"


def test_pdf_tag_table_shows_no_value_for_an_absent_pct(audit):
    text = _pdf_text(_run(audit, NO_PCT))
    assert "pct (absent)" in text, text[text.find("Tag-by-Tag"):][:800]
    assert "100 (default)" not in text


# ---------------------------------------------------------------
# 2. The readiness score agrees with its label
# ---------------------------------------------------------------

def test_readiness_score_counts_only_graded_rows(audit):
    result = _run(audit, GITHUB_SHAPE)
    readiness = _card(result)["dmarcbis_readiness"]
    statuses = [c["status"] for c in readiness["checklist"]]
    assert statuses == ["pass", "warn", "info", "info"], statuses
    assert (readiness["pass_count"], readiness["total_count"]) == (1, 2)
    misses = readiness["total_count"] - readiness["pass_count"]
    assert misses == sum(1 for s in statuses if s in ("warn", "fail"))
    assert result["executive_summary"]["dmarcbis_readiness"]["label"] == "Compatible"


@pytest.mark.parametrize("dmarc", [
    GITHUB_SHAPE, NO_PCT, PCT_50,
    f"v=DMARC1; p=none; {RUA}",
    f"v=DMARC1; p=reject; np=reject; psd=n; {RUA}",
    f"v=DMARC1; p=reject; rf=afrf; ri=3600; {RUA}",
])
def test_score_never_implies_more_misses_than_warn_or_fail_rows(audit, dmarc):
    readiness = _card(_run(audit, dmarc))["dmarcbis_readiness"]
    statuses = [c["status"] for c in readiness["checklist"]]
    assert readiness["pass_count"] == statuses.count("pass")
    assert readiness["total_count"] - readiness["pass_count"] == \
        statuses.count("warn") + statuses.count("fail")


def test_readiness_header_carries_the_label_and_no_count(browser, audit):  # noqa: F811
    # Every graded row passes, but the health verdict (t=y lowers reject to
    # quarantine) labels it In progress. A count beside that label would
    # say 2/2.
    data = _result(audit, f"v=DMARC1; p=reject; t=y; {RUA}")
    assert data["executive_summary"]["dmarcbis_readiness"]["label"] == "In progress"
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        header = page.eval_on_selector("#check-dmarc .dbis-header", "e => e.textContent")
        assert "In progress" in header
        assert not re.search(r"\d+\s*/\s*\d+", header), header
        assert not errors, errors
    finally:
        ctx.close()


# ---------------------------------------------------------------
# 3. Publication is not deployment
# ---------------------------------------------------------------

DEPLOYMENT = ("RFC 9989 replaced RFC 7489 in May 2026, but most receivers still "
              "evaluate DMARC the RFC 7489 way")


def _dmarc_card_after(browser, data, mode=None):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        # Open the card, Details and every panel under it, in DOM order.
        page.evaluate("""() => {
            const card = document.getElementById('check-dmarc');
            card.querySelector('.result-header').click();
            card.querySelectorAll('.cd-header').forEach(h => h.click());
        }""")
        if mode:
            page.click(f"#check-dmarc .st-seg[data-mode='{mode}']")
        rows = page.eval_on_selector_all(
            "#check-dmarc .rb-kv-row",
            "els => els.map(e => [e.querySelector('.rb-kv-name').textContent, "
            "e.querySelector('.rb-kv-header').innerText])")
        note = page.eval_on_selector_all(
            "#check-dmarc .st-toggle-note",
            "els => els.map(e => e.offsetParent !== null ? e.innerText : '')")
        text = page.eval_on_selector("#check-dmarc", "e => e.textContent")
        assert not errors, errors
        return dict(rows), note, text
    finally:
        ctx.close()


def _result(audit, dmarc):
    return json.loads(json.dumps(_run(audit, dmarc), default=str))


def test_absent_pct_row_renders_not_set(browser, audit):  # noqa: F811
    rows, _, _ = _dmarc_card_after(browser, _result(audit, NO_PCT))
    assert "not set" in rows["pct="], rows["pct="]
    assert "(default)" not in rows["pct="]
    assert "Removed in RFC 9989" not in rows["pct="]


def test_present_pct_row_renders_value_and_removed_badge(browser, audit):  # noqa: F811
    rows, _, _ = _dmarc_card_after(browser, _result(audit, PCT_50))
    assert "50" in rows["pct="]
    assert "Removed in RFC 9989" in rows["pct="]


@pytest.mark.parametrize("mode", [None, "legacy", "dmarcbis"])
def test_deployment_sentence_in_both_modes_and_no_obsolete(browser, audit, mode):  # noqa: F811
    _, note, text = _dmarc_card_after(browser, _result(audit, GITHUB_SHAPE), mode)
    assert len(note) == 1 and note[0].startswith(DEPLOYMENT), note
    assert "bsolete" not in text


def test_toggle_labels_are_the_plain_rfc_names():
    with open(os.path.join(REPO, "static", "app.js"), encoding="utf-8") as f:
        src = f.read()
    assert 'data-mode="legacy" role="radio" aria-checked="false">RFC 7489</button>' in src
    assert 'data-mode="dmarcbis" role="radio" aria-checked="true">RFC 9989</button>' in src
    assert "problems with the record today" not in src
