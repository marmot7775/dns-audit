"""Records to change: the block that follows What to do, and its PDF table.

The plan rows' records (plan_records.py, #221) are listed in plan order, one
row each: step, add / replace / delete, type, full host name, the exact value
and, for a replace, the value it replaces. These tests cover the three
promises the block makes:

* a value is written out only when DNS gives enough to make it correct, and
  every one parses with the repo's own parsers within the SPF lookup limit;
* an ambiguous input yields no value, only who supplies it;
* a report address nobody confirmed is a marked placeholder, never a
  plausible mailbox.

The browser and PDF cases run the real page and the real PDF.
"""
import io
import os
import re
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import pdf_report  # noqa: E402
import plan_records  # noqa: E402
from result_transformer import build_security_roadmap  # noqa: E402
from spf_recursive import _parse_spf_mechanisms  # noqa: E402
from test_change_set import _entries, _mx, _plan  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401

D = "example.com"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
SPF_KNOWN = {"include", "a", "mx", "ip4", "ip6", "exists", "ptr", "all", "redirect", "no_lookup"}


def _all_entries(rm):
    return rm["change_set"]["entries"]


def _valid_spf(value):
    """A syntactically valid v=spf1 record: version first, every term a known
    mechanism or modifier, one all and it last, and no more than 10 terms
    that cost a lookup (the terms of the record itself; includes add their
    own, which only the audit that follows can count)."""
    terms = value.split()
    assert terms[0] == "v=spf1", value
    kinds = [m["type"] for m in _parse_spf_mechanisms(value)]
    assert all(k in SPF_KNOWN for k in kinds), (value, kinds)
    alls = [t for t in terms if t.lstrip("+-~?").lower() == "all"]
    assert len(alls) <= 1 and (not alls or terms[-1] == alls[0]), value
    assert plan_records.spf_lookup_terms(value) <= plan_records.SPF_LOOKUP_LIMIT, value


def _valid_dmarc(value):
    result = audit_engine._validate_dmarc_strict(value, 1)
    failed = [c for c in result["checks"] if c["status"] == "fail"]
    assert not failed, (value, failed)


def _spf(**kw):
    card = {"name": "SPF", "status": "fail", "record": None}
    card.update(kw)
    if not card["record"]:
        card["pill_label"] = "Multiple records" if card.get("multiple_records") else "Missing"
    return card


# ---------------------------------------------------------------
# Every written-out record parses
# ---------------------------------------------------------------

SPF_CASES = [
    ([_spf(record="v=spf1 include:_spf.google.com +all")], "plus all"),
    ([_spf(record="v=spf1 mx ?all", status="warn", fix="Change ?all to ~all.")], "neutral all"),
    ([_spf(multiple_records=["v=spf1 include:_spf.google.com -all",
                             "v=spf1 include:mailgun.org ~all"])], "duplicates"),
    ([_spf(), _mx("aspmx.l.google.com", providers=["Google Workspace"])], "google"),
    ([_spf(), _mx("a.mail.protection.outlook.com", providers=["Microsoft 365"])], "microsoft"),
    ([_spf(), _mx("a.example.net", "b.example.net",
                  providers=["Google Workspace", "Microsoft 365"])], "both providers"),
]


@pytest.mark.parametrize("checks,label", SPF_CASES, ids=[c[1] for c in SPF_CASES])
def test_every_written_spf_record_parses_within_ten_lookups(checks, label):
    entries = [e for e in _all_entries(_plan(*checks)) if e["protocol"] == "SPF"]
    assert entries, label
    written = [e for e in entries if e["value"]]
    assert written, label
    for e in written:
        _valid_spf(e["value"])


DMARC_CASES = [
    {"name": "DMARC", "status": "fail", "pill_label": "Missing", "record": None,
     "record_builder": {"recommended_record": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{D}",
                        "deploy": {"host": f"_dmarc.{D}"}}},
    {"name": "DMARC", "status": "warn", "record": "v=DMARC1; p=reject; sp=none; pct=100",
     "tag_breakdown": {"config_warnings": [{"title": "No aggregate reporting"}],
                       "health": {"status": "compatible", "reasons": []}}},
    {"name": "DMARC", "status": "warn", "record": "v=DMARC1; p=quarantine; pct=50; rua=mailto:r@example.com",
     "tag_breakdown": {"config_warnings": [], "health": {"status": "compatible", "reasons": []}}},
]


@pytest.mark.parametrize("card", DMARC_CASES, ids=["missing", "rua sp pct", "partial pct"])
def test_every_written_dmarc_record_parses(card):
    written = [e for e in _entries(_plan(card), "DMARC") if e["value"] and e["type"] == "TXT"]
    assert written
    for e in written:
        if e["host"].startswith("_dmarc."):
            _valid_dmarc(e["value"])


def test_spf_merge_and_replace_never_exceed_the_limit_in_their_own_terms():
    many = " ".join(f"include:s{n}.example.net" for n in range(10))
    assert plan_records.spf_merge([f"v=spf1 {many} -all", "v=spf1 mx -all"]) is None
    ok = plan_records.spf_merge(["v=spf1 include:a.test -all", "v=spf1 include:b.test ~all"])
    assert ok == "v=spf1 include:a.test include:b.test -all"
    assert plan_records.SPF_LOOKUP_LIMIT == 10


# ---------------------------------------------------------------
# Ambiguous input yields no record
# ---------------------------------------------------------------

def _no_value(rm, protocol):
    entries = _entries(rm, protocol)
    assert entries
    for e in entries:
        assert e["value"] is None, e
        assert e["value_from"], e


def test_spf_duplicates_with_a_redirect_yield_no_record():
    _no_value(_plan(_spf(multiple_records=["v=spf1 redirect=_spf.example.net", "v=spf1 mx -all"])), "SPF")


def test_spf_duplicates_past_the_lookup_limit_yield_no_record():
    many = " ".join(f"include:s{n}.example.net" for n in range(10))
    _no_value(_plan(_spf(multiple_records=[f"v=spf1 {many} -all", "v=spf1 mx -all"])), "SPF")


def test_missing_spf_with_an_unknown_provider_yields_no_record():
    _no_value(_plan(_spf(), _mx(f"mx.{D}")), "SPF")


def test_spf_over_the_limit_yields_no_record():
    _no_value(_plan(_spf(status="fail", record="v=spf1 include:a.test ~all",
                         spf_deep={"lookup_count": 12})), "SPF")


def test_duplicate_dmarc_records_yield_no_record():
    rm = _plan({"name": "DMARC", "status": "fail", "pill_label": "Multiple records", "record": None,
                "multiple_records": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
    entries = _entries(rm, "DMARC")
    assert entries and all(e["value"] is None for e in entries)
    keep = next(e for e in entries if e["op"] == "replace")
    assert keep["current"] == "v=DMARC1; p=none\nv=DMARC1; p=reject"


def test_a_new_dkim_key_is_the_providers_and_the_row_names_the_host():
    rm = _plan({"name": "DKIM", "status": "warn", "record": "",
                "dkim_selectors": [{"selector": "s1", "record": "v=DKIM1; p=ABC", "cname_target": None}],
                "dkim_deep": {"has_weak": True, "keys": [
                    {"selector": "s1", "bits": 1024, "rating": "amber", "revoked": False}]}})
    [e] = _entries(rm, "DKIM")
    assert e["value"] is None
    assert e["host"] == f"s1._domainkey.{D}"
    assert "email provider" in e["value_from"]


def test_no_domain_means_no_records_at_all():
    rm = build_security_roadmap([_spf(record="v=spf1 +all")], domain="", now=NOW)
    assert rm["change_set"]["entries"] == []


# ---------------------------------------------------------------
# Report addresses: the domain's own, or a flagged placeholder
# ---------------------------------------------------------------

def test_a_missing_dmarc_record_carries_the_flagged_placeholder():
    [e] = _entries(_plan(DMARC_CASES[0]), "DMARC")
    assert e["value"] == f"v=DMARC1; p=none; rua=mailto:{plan_records.RUA_PLACEHOLDER}@{D}"
    assert e["placeholder"] is True
    assert "dmarc-reports@" not in e["value"]


def test_a_new_tls_rpt_record_carries_the_flagged_placeholder():
    rm = _plan({"name": "TLS-RPT", "status": "absent", "pill_label": "Optional, not set up"})
    [e] = _entries(rm, "TLS-RPT")
    assert e["placeholder"] is True and plan_records.RUA_PLACEHOLDER in e["value"]
    assert "tls-reports@" not in e["value"]


def test_the_placeholder_is_flagged_in_the_summary_counts():
    rm = _plan(DMARC_CASES[0], {"name": "TLS-RPT", "status": "absent", "pill_label": "Optional, not set up"})
    assert rm["change_set"]["placeholders"] == 2


def test_a_merged_rua_edit_stays_flagged():
    [e] = _entries(_plan(DMARC_CASES[1]), "DMARC")
    assert e["placeholder"] is True
    assert e["value"].count(plan_records.RUA_PLACEHOLDER) == 1


def test_the_domains_existing_rua_is_kept_and_not_flagged():
    rm = _plan({"name": "TLS-RPT", "status": "fail",
                "record": "v=TLSRPTv1; rua=mailto:tls@mail.example.com, https://r.example.com/x",
                "verdict": "bad"})
    entries = _entries(rm, "TLS-RPT")
    assert entries
    for e in entries:
        assert not e["placeholder"]
        assert plan_records.RUA_PLACEHOLDER not in (e["value"] or "")


def test_no_record_invents_an_address():
    cards = [DMARC_CASES[0], DMARC_CASES[1],
             {"name": "TLS-RPT", "status": "absent", "pill_label": "Optional, not set up"}]
    for e in _all_entries(_plan(*cards)):
        assert not re.search(r"(dmarc|tls)-reports@", e["value"] or "")


# ---------------------------------------------------------------
# Replace shows what it replaces; delete says what goes
# ---------------------------------------------------------------

def test_a_replace_shows_the_current_value():
    [e] = _entries(_plan(_spf(record="v=spf1 include:_spf.google.com +all")), "SPF")
    assert e["op"] == "replace"
    assert e["current"] == "v=spf1 include:_spf.google.com +all"
    assert e["value"] == "v=spf1 include:_spf.google.com ~all"


def test_a_merged_dmarc_replace_shows_the_published_record():
    [e] = _entries(_plan(DMARC_CASES[1]), "DMARC")
    assert e["current"] == "v=DMARC1; p=reject; sp=none; pct=100"


def test_removing_a_dangling_record_is_a_delete_with_its_target():
    rm = _plan({"name": "DKIM", "status": "fail", "record": "", "dkim_selectors": [],
                "dangling_selectors": [{"selector": "old", "cname_target": "old.gone.test",
                                        "status": "unregistered"}]})
    e = next(x for x in _entries(rm, "DKIM") if x["op"] == "delete")
    assert (e["type"], e["host"]) == ("CNAME", f"old._domainkey.{D}")
    assert e["value"] is None and e["current"] == "old.gone.test"


def test_a_new_record_has_nothing_to_replace():
    [e] = _entries(_plan(DMARC_CASES[0]), "DMARC")
    assert e["op"] == "add" and not e.get("current")


# ---------------------------------------------------------------
# Order, wording
# ---------------------------------------------------------------

def test_steps_follow_the_plans_priority_order():
    rm = _plan(_spf(record="v=spf1 +all"), DMARC_CASES[0])
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    order = [rank[next(i for i in rm["items"] if i["protocol"] == e["protocol"])["priority"]]
             for e in _all_entries(rm)]
    assert order == sorted(order)
    assert [e["step"] for e in _all_entries(rm)] == list(range(1, len(order) + 1))


def test_no_em_dash_or_double_hyphen_in_the_blocks_words():
    rm = _plan(DMARC_CASES[0], DMARC_CASES[1],
               {"name": "TLS-RPT", "status": "absent", "pill_label": "Optional, not set up"},
               {"name": "MTA-STS", "status": "absent", "pill_label": "Optional, not set up"},
               _mx("mx1.example.com"))
    for e in _all_entries(rm):
        words = " ".join([e.get("value_from") or "", *e["notes"], *e["why"]])
        assert "—" not in words and " -- " not in words, words
    js = open(os.path.join(os.path.dirname(__file__), "..", "static", "app.js"), encoding="utf-8").read()
    block = js[js.index("const RC_PLACEHOLDER_WARNING"):js.index("function wireChangeSet")]
    assert "—" not in block and " -- " not in block.replace("// ", "")


# ---------------------------------------------------------------
# The page
# ---------------------------------------------------------------

def _long_value_result(fixture_result):  # noqa: F811
    """The fixture audit with one record whose value is 600 unbroken
    characters, the way a DKIM public key arrives."""
    import copy
    res = copy.deepcopy(fixture_result)
    first = res["security_roadmap"]["change_set"]["entries"][0]
    first["value"] = "v=DKIM1; k=rsa; p=" + "A" * 600
    first["current"] = "v=DKIM1; k=rsa; p=" + "B" * 300
    first["op"] = "replace"
    return res


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [320, 375, 1280])
def test_the_block_fits_the_screen_with_44px_targets(browser, fixture_result, theme, width):  # noqa: F811
    ctx, pg, errors = _page(browser, theme, width)
    _render(pg, _long_value_result(fixture_result))
    block = pg.locator("#records-to-change")
    assert block.is_visible()
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    # Long values wrap or scroll inside their own box, never past the card.
    over = pg.evaluate("""() => {
        const b = document.querySelector('#records-to-change').getBoundingClientRect();
        return [...document.querySelectorAll('#records-to-change .rtc-row')]
            .filter(r => r.getBoundingClientRect().right > b.right + 1).length;
    }""")
    assert over == 0
    for btn in block.locator("button").all():
        assert btn.bounding_box()["height"] >= 43.5, btn.inner_text()
        assert btn.bounding_box()["width"] >= 43.5
    assert not errors, errors
    ctx.close()


def test_the_dns_host_steps_sit_above_the_block_and_the_recheck_follows(browser, fixture_result):  # noqa: F811
    ctx, pg, errors = _page(browser, "dark", 1280)
    res = _render_with_host(pg, fixture_result)
    order = pg.evaluate("""() => {
        const q = s => document.querySelector(s);
        const pos = e => e ? e.getBoundingClientRect().top + scrollY : null;
        return [pos(q('#priority-list .priority-item, #priority-list .priority-row')),
                pos(q('#records-to-change .dns-host')), pos(q('#records-to-change .rtc-list')),
                pos(q('#records-to-change .rtc-recheck'))];
    }""")
    assert order[1] is not None and order[1] < order[2] < order[3]
    assert pg.locator(".dns-host").count() == 1
    assert pg.locator("#records-to-change .rtc-rerun").count() == 1
    assert not errors, errors
    ctx.close()
    assert res


def _render_with_host(pg, fixture_result):  # noqa: F811
    import copy
    res = copy.deepcopy(fixture_result)
    res["dns_host"] = res.get("dns_host") or {
        "name": "Example Host", "steps": ["Open DNS.", "Add the record."],
        "name_tip": None, "value_tip": None, "warning": None,
        "source": "https://example.com/help"}
    _render(pg, res)
    return res


def test_copy_all_lists_every_step_with_its_value_or_its_source(browser, fixture_result):  # noqa: F811
    ctx, pg, errors = _page(browser, "dark", 1280)
    _render(pg, fixture_result)
    cs = fixture_result["security_roadmap"]["change_set"]
    text = pg.evaluate("cs => rcCopyAllText(cs)", cs)
    for e in cs["entries"]:
        assert re.search(rf"^{e['step']}\. ", text, re.M)
        assert e["host"] in text
        if e["value"]:
            assert e["value"] in text
        elif e["op"] != "delete":
            assert "Value from:" in text
    assert text.count("\n\n") == len(cs["entries"]) - 1
    assert not errors, errors
    ctx.close()


def test_each_value_has_its_own_copy_button(browser, fixture_result):  # noqa: F811
    ctx, pg, errors = _page(browser, "dark", 375)
    _render(pg, fixture_result)
    cs = fixture_result["security_roadmap"]["change_set"]["entries"]
    with_value = [e for e in cs if e["value"] is not None and e["op"] != "delete"]
    assert pg.locator("#records-to-change .rtc-row .copy-btn").count() == len(with_value)
    assert not errors, errors
    ctx.close()


def test_a_placeholder_row_says_so_on_the_page(browser, fixture_result):  # noqa: F811
    import copy
    res = copy.deepcopy(fixture_result)
    e = res["security_roadmap"]["change_set"]["entries"][0]
    e["value"] = f"v=DMARC1; p=none; rua=mailto:{plan_records.RUA_PLACEHOLDER}@{D}"
    e["placeholder"] = True
    res["security_roadmap"]["change_set"]["placeholders"] = 1
    ctx, pg, errors = _page(browser, "dark", 375)
    _render(pg, res)
    row = pg.locator("#records-to-change .rtc-row").first
    assert "Replace REPLACE-WITH-YOUR-ADDRESS" in row.locator(".rtc-placeholder").inner_text()
    assert "an address for you to fill in" in pg.locator(".records-title").inner_text()
    assert not errors, errors
    ctx.close()


# ---------------------------------------------------------------
# The PDF
# ---------------------------------------------------------------

def _pdf_text(result):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)


def test_the_pdf_has_the_records_table_with_every_host_and_step(fixture_result):  # noqa: F811
    text = _pdf_text(fixture_result)
    assert "Records to change" in text
    for e in fixture_result["security_roadmap"]["change_set"]["entries"]:
        assert e["host"] in text.replace(" ", "") or e["host"] in text, e["host"]


def test_the_pdf_survives_a_very_long_value_and_prints_all_of_it(fixture_result):  # noqa: F811
    res = _long_value_result(fixture_result)
    text = _pdf_text(res).replace(" ", "")
    assert "A" * 600 in text
    assert "B" * 300 in text


def test_the_pdf_has_no_toggle_words_and_points_at_the_recheck(fixture_result):  # noqa: F811
    text = _pdf_text(fixture_result)
    assert "Show" not in text.split("Records to change", 1)[1][:200]
    assert "run the audit again" in text


def test_the_pdf_flags_a_placeholder(fixture_result):  # noqa: F811
    import copy
    res = copy.deepcopy(fixture_result)
    e = res["security_roadmap"]["change_set"]["entries"][0]
    e["value"] = f"v=DMARC1; p=none; rua=mailto:{plan_records.RUA_PLACEHOLDER}@{D}"
    e["placeholder"] = True
    assert "Replace REPLACE-WITH-YOUR-ADDRESS" in _pdf_text(res)


def test_the_block_does_not_name_the_address_it_replaced():
    rm = _plan({"name": "TLS-RPT", "status": "absent", "pill_label": "Optional, not set up"},
               DMARC_CASES[0])
    for e in _all_entries(rm):
        assert not re.search(r"(dmarc|tls)-reports@", " ".join(e["notes"]) + (e["value"] or ""))
