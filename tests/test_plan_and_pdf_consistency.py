"""Plan rows and PDF sections that pointed at the wrong thing (review of Docs 63 to 69).

Each DMARC plan row carries the record that does what the row says; a row
built from a card without fix text does not use the card's verdict as its
reason; the PDF labels a first record as a starting point, names only the
appendix sections that rendered, and gives no letter to an empty one.
"""
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import _parse_record_tags, build_security_roadmap
from test_dmarc_grades import DOMAIN, RUA, _card, _pdf_text, _run, _zone


def _rows(result, protocol="DMARC"):
    return {i["action"]: i for i in result["security_roadmap"]["items"]
            if i["protocol"] == protocol}


# ---------------------------------------------------------------
# Each DMARC row's record does what the row says
# ---------------------------------------------------------------

@pytest.mark.parametrize("dmarc, action, tag, want", [
    (f"v=DMARC1; p=quarantine; pct=25; sp=none; {RUA}",
     "Bring the subdomain policy up to p=quarantine", "sp", "quarantine"),
    (f"v=DMARC1; p=reject; np=none; {RUA}",
     "Set np=reject to match the domain's policy", "np", "reject"),
    (f"v=DMARC1; p=reject; {RUA}", "Consider adding an explicit np= tag", "np", "reject"),
])
def test_a_policy_row_record_sets_the_tag_it_names(audit, dmarc, action, tag, want):
    row = _rows(_run(audit, dmarc))[action]
    tags = _parse_record_tags(row["record"])
    assert tags[tag] == want, row["record"]
    # Nothing else in the record moved.
    before = _parse_record_tags(dmarc)
    assert {k: v for k, v in tags.items() if k != tag} == \
        {k: v for k, v in before.items() if k != tag}


def test_explicit_np_row_keeps_what_np_inherits_from_sp(audit):
    # github.com's shape: sp=reject covers non-existent subdomains today, so
    # an explicit np must not be the weaker p=quarantine.
    row = _rows(_run(audit, f"v=DMARC1; p=quarantine; sp=reject; pct=100; {RUA}"))[
        "Consider adding an explicit np= tag"]
    assert _parse_record_tags(row["record"])["np"] == "reject", row["record"]


def test_removed_tags_row_record_drops_only_those_tags(audit):
    row = _rows(_run(audit, f"v=DMARC1; p=reject; pct=100; ri=3600; {RUA}"))[
        "Remove the tags RFC 9989 retired: pct, ri"]
    tags = _parse_record_tags(row["record"])
    assert "pct" not in tags and "ri" not in tags
    assert tags["p"] == "reject" and tags["rua"] == RUA.split("=", 1)[1]


def test_test_mode_row_record_drops_t(audit):
    row = _rows(_run(audit, f"v=DMARC1; p=reject; t=y; {RUA}"))[
        "Remove t=y so p=reject applies in full"]
    assert "t" not in _parse_record_tags(row["record"])


def test_rows_on_one_record_do_not_share_one_record(audit):
    rows = _rows(_run(audit, f"v=DMARC1; p=reject; sp=quarantine; pct=100; {RUA}"))
    records = [r["record"] for r in rows.values() if r.get("record")]
    assert len(records) >= 2
    assert len(set(records)) == len(records), records


# ---------------------------------------------------------------
# A fallback row's reason is not the card verdict
# ---------------------------------------------------------------

def test_fallback_row_does_not_use_the_verdict_as_its_reason(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}", spf="v=spf1 mx ?all")
    verdict = _card(result, "SPF")["verdict"]
    rows = _rows(result, "SPF")
    assert rows, result["security_roadmap"]["items"]
    assert all(r["impact"] != verdict for r in rows.values()), (verdict, rows)


# ---------------------------------------------------------------
# The PDF
# ---------------------------------------------------------------

def test_first_record_is_not_labelled_the_enforcement_end_state(audit):
    text = _pdf_text(_run(audit, None))
    assert "Recommended starting record" in text
    assert "End state: enforcement v=DMARC1; p=none" not in text


def test_pdf_plan_names_no_appendix_letter_for_the_migration_path(audit):
    text = _pdf_text(_run(audit, f"v=DMARC1; p=none; {RUA}"))
    assert "Appendix A carries the migration steps" not in text


def test_appendix_intro_names_only_sections_that_rendered(audit):
    text = _pdf_text(_run(audit, f"v=DMARC1; p=none; {RUA}", scope="transport"))
    start = text.index("This appendix holds")
    intro = text[start:text.index("Nothing in it", start)]
    assert "DMARC" not in intro and "migration path" not in intro, intro
    assert "what each check means" in intro, intro


def test_unavailable_dmarc_gets_no_empty_appendix_section(audit):
    zone = _zone(f"v=DMARC1; p=reject; {RUA}")
    zone.fail(f"_dmarc.{DOMAIN}", "TXT", dns.resolver.NoNameservers())
    result = audit(zone, DOMAIN, dkim_selector="s1")
    assert _card(result)["status"] == "unavailable"
    text = _pdf_text(result)
    assert "DMARC in depth" not in text


def test_deep_analysis_title_names_only_what_it_holds():
    import pdf_report
    data = {"checks": [{"name": "SPF", "status": "unavailable"},
                       {"name": "DKIM", "status": "pass", "dkim_deep": {"keys": []}}]}
    assert pdf_report._deep_analysis_title(data) == "DKIM in depth"
    data["checks"][0] = {"name": "SPF", "status": "pass", "spf_deep": {"x": 1}}
    assert pdf_report._deep_analysis_title(data) == "SPF and DKIM in depth"


# ---------------------------------------------------------------
# The rendered plan
# ---------------------------------------------------------------

from test_ui_consistency_a11y import _page, _render, browser  # noqa: E402,F401


def _plan_rows(browser, data):  # noqa: F811
    import json
    data = json.loads(json.dumps(data, default=str))
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        rows = page.eval_on_selector_all("#priority-list .priority-row", """els => els.map(r => {
            const parts = {};
            r.querySelectorAll('.plan-part').forEach(p => {
                parts[p.querySelector('.plan-part-label').textContent] =
                    p.querySelector('.plan-part-body').textContent.replace(/\\s+/g, ' ').trim();
            });
            const rec = r.querySelector('.record-text');
            return {protocol: r.querySelector('.priority-protocol').textContent,
                    action: r.querySelector('.priority-action').textContent,
                    record: rec ? rec.textContent : null, parts};
        })""")
        assert not errors, errors
        return rows
    finally:
        ctx.close()


def test_rendered_dmarc_rows_show_their_own_records(browser, audit):  # noqa: F811
    rows = _plan_rows(browser, _run(audit, f"v=DMARC1; p=reject; sp=quarantine; pct=100; {RUA}"))
    dmarc = {r["action"]: r["record"] for r in rows if r["protocol"] == "DMARC"}
    assert "sp=reject" in dmarc["Bring the subdomain policy up to p=reject"]
    assert "pct=" not in dmarc["Remove the tag RFC 9989 retired: pct"]
    assert len(set(dmarc.values())) == len(dmarc), dmarc


def test_rendered_rows_do_not_print_the_fix_twice(browser, audit):  # noqa: F811
    rows = _plan_rows(browser, _run(audit, f"v=DMARC1; p=reject; {RUA}"))
    for r in rows:
        why, what = r["parts"].get("Why it matters", ""), r["parts"].get("What to change", "")
        if what and len(what) > 20:
            assert what not in why, r
