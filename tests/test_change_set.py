"""The change set: every DNS record the plan asks for, in order.

Plan rows for SPF, DKIM, MTA-STS, TLS-RPT and BIMI carry records like the
DMARC rows do (plan_records.py): the exact value where DNS tells us it,
otherwise None and who supplies it. The change set lists them in plan
order, folding rows that edit one record into one entry. Every test runs
offline: unit cases on hand-built cards, then one audit of the Doc 38
fixture zone through the page and the PDF.
"""
import io
import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report  # noqa: E402
import plan_records  # noqa: E402
from result_transformer import build_security_roadmap  # noqa: E402
from test_ui_consistency_a11y import (  # noqa: E402,F401
    DOMAIN as UI_DOMAIN,
    _page,
    _render,
    _run,
    _zone,
    browser,
)

D = "example.com"
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
ABSENT = "Optional, not set up"


def _plan(*checks, now=NOW):
    return build_security_roadmap(list(checks), domain=D, now=now)


def _rows(rm, protocol):
    return [i for i in rm["items"] if i["protocol"] == protocol]


def _entries(rm, protocol=None):
    return [e for e in rm["change_set"]["entries"]
            if protocol is None or e["protocol"] == protocol]


def _mx(*hosts, providers=()):
    return {"name": "MX Records", "status": "pass", "mx_hosts": list(hosts),
            "providers": list(providers),
            "record": "\n".join(f"{10 * (n + 1)} {h}" for n, h in enumerate(hosts))}


# ---------------------------------------------------------------
# DMARC: rows that edit one record become one entry
# ---------------------------------------------------------------

def test_dmarc_edits_to_one_record_are_one_entry_with_every_edit():
    rm = _plan({"name": "DMARC", "status": "warn",
                "record": "v=DMARC1; p=reject; sp=none; pct=100",
                "tag_breakdown": {"config_warnings": [{"title": "No aggregate reporting"}],
                                  "health": {"status": "compatible", "reasons": []}}})
    assert len(_rows(rm, "DMARC")) == 3
    [entry] = _entries(rm, "DMARC")
    assert entry["op"] == "replace" and entry["type"] == "TXT"
    assert entry["host"] == f"_dmarc.{D}"
    assert entry["value"] == f"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@{D}"
    assert len(entry["actions"]) == 3 and len(entry["why"]) == 3


def test_missing_dmarc_offers_the_first_record():
    rm = _plan({"name": "DMARC", "status": "fail", "pill_label": "Missing", "record": None,
                "record_builder": {"recommended_record": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{D}",
                                   "deploy": {"host": f"_dmarc.{D}"}}})
    [entry] = _entries(rm, "DMARC")
    assert entry["op"] == "add"
    assert entry["value"] == f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{D}"
    assert any(f"Replace dmarc-reports@{D}" in n for n in entry["notes"])


def test_unauthorized_report_destination_is_published_by_the_receiver():
    rm = _plan({"name": "DMARC", "status": "warn", "record": "v=DMARC1; p=reject; rua=mailto:r@reports.example.net",
                "unauthorized_reports": [{"domain": "example.net", "address": "r@reports.example.net",
                                          "auth_host": f"{D}._report._dmarc.example.net"}]})
    entry = next(e for e in _entries(rm, "DMARC") if e.get("by"))
    assert entry["host"] == f"{D}._report._dmarc.example.net"
    assert entry["value"] == "v=DMARC1"
    assert entry["by"] == "example.net"


# ---------------------------------------------------------------
# SPF
# ---------------------------------------------------------------

def test_plus_all_becomes_softfail_with_the_rest_kept():
    rm = _plan({"name": "SPF", "status": "fail", "record": "v=spf1 include:_spf.google.com +all"})
    [entry] = _entries(rm, "SPF")
    assert entry["host"] == D
    assert entry["value"] == "v=spf1 include:_spf.google.com ~all"


def test_duplicate_spf_records_are_merged():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Multiple records", "record": None,
                "multiple_records": ["v=spf1 include:_spf.google.com -all",
                                     "v=spf1 include:mailgun.org include:_spf.google.com ~all"]})
    [entry] = _entries(rm, "SPF")
    assert entry["value"] == "v=spf1 include:_spf.google.com include:mailgun.org -all"
    assert "Delete the 2 v=spf1 records" in entry["notes"][0]


def test_duplicate_spf_records_with_redirect_are_left_to_the_owner():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Multiple records", "record": None,
                "multiple_records": ["v=spf1 redirect=_spf.example.net", "v=spf1 mx -all"]})
    [entry] = _entries(rm, "SPF")
    assert entry["value"] is None and "redirect=" in entry["value_from"]


def test_missing_spf_uses_the_mx_providers_include():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Missing", "record": None},
               _mx("aspmx.l.google.com", providers=["Google Workspace"]))
    [entry] = _entries(rm, "SPF")
    assert entry["value"] == "v=spf1 include:_spf.google.com ~all"
    assert "every other service" in entry["notes"][0]


def test_missing_spf_without_a_known_provider_says_who_has_the_value():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Missing", "record": None},
               _mx(f"mx.{D}"))
    [entry] = _entries(rm, "SPF")
    assert entry["value"] is None
    assert entry["value_from"].startswith("Your email provider")


def test_too_many_lookups_has_no_single_record():
    rm = _plan({"name": "SPF", "status": "fail", "record": "v=spf1 include:a.test ~all",
                "spf_deep": {"lookup_count": 12}})
    [entry] = _entries(rm, "SPF")
    assert entry["value"] is None and "No single record" in entry["value_from"]


def test_null_spf_from_the_card_is_carried():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Missing", "record": None,
                "fix_records": [{"type": "TXT", "host": D, "value": "v=spf1 -all",
                                 "comment": "Null SPF: declares this domain does not send email"}]})
    [entry] = _entries(rm, "SPF")
    assert entry["value"] == "v=spf1 -all"


# ---------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------

def _dkim(**kw):
    card = {"name": "DKIM", "status": "warn", "record": "",
            "dkim_selectors": [{"selector": "s1", "record": "k=rsa; v=DKIM1; t=y; p=ABC",
                                "cname_target": None}]}
    card.update(kw)
    return card


def test_two_edits_to_one_key_are_one_entry():
    rm = _plan(_dkim(dkim_test_mode=["s1"], dkim_version_not_first=["s1"]))
    assert len(_rows(rm, "DKIM")) == 2
    [entry] = _entries(rm, "DKIM")
    assert entry["host"] == f"s1._domainkey.{D}"
    assert entry["value"] == "v=DKIM1; k=rsa; p=ABC"


def test_test_mode_keeps_other_flags():
    rm = _plan(_dkim(dkim_test_mode=["s1"], dkim_selectors=[
        {"selector": "s1", "record": "v=DKIM1; t=y:s; p=ABC", "cname_target": None}]))
    assert _entries(rm, "DKIM")[0]["value"] == "v=DKIM1; t=s; p=ABC"


def test_sha1_only_key_gets_sha256():
    rm = _plan(_dkim(status="fail", dkim_sha1_only=["s1"], dkim_selectors=[
        {"selector": "s1", "record": "v=DKIM1; h=sha1; p=ABC", "cname_target": None}]))
    assert _entries(rm, "DKIM")[0]["value"] == "v=DKIM1; h=sha256; p=ABC"


def test_a_key_behind_a_cname_comes_from_its_owner():
    rm = _plan(_dkim(dkim_test_mode=["s1"], dkim_selectors=[
        {"selector": "s1", "record": "v=DKIM1; t=y; p=ABC",
         "cname_target": "s1.dkim.esp.example.net"}]))
    [entry] = _entries(rm, "DKIM")
    assert entry["value"] is None and "s1.dkim.esp.example.net" in entry["value_from"]


def test_weak_key_names_the_selector_and_leaves_the_value_to_the_provider():
    rm = _plan(_dkim(dkim_deep={"has_weak": True, "keys": [
        {"selector": "s1", "bits": 1024, "rating": "amber", "revoked": False}]}))
    [entry] = _entries(rm, "DKIM")
    assert entry["host"] == f"s1._domainkey.{D}"
    assert entry["value"] is None and "2048-bit" in entry["value_from"]


def test_unregistered_target_is_a_cname_to_delete():
    rm = _plan(_dkim(status="fail", dangling_selectors=[
        {"selector": "old", "cname_target": "old.gone.test", "status": "unregistered"}]))
    entry = next(e for e in _entries(rm, "DKIM") if e["op"] == "delete")
    assert entry["type"] == "CNAME" and entry["host"] == f"old._domainkey.{D}"
    assert entry["value"] == "old.gone.test"


# ---------------------------------------------------------------
# MTA-STS and TLS-RPT
# ---------------------------------------------------------------

def test_new_mta_sts_is_file_then_host_then_txt_after_tls_rpt():
    rm = _plan(_mx("mx1.example.com", "mx2.example.com"),
               {"name": "MTA-STS", "status": "absent", "pill_label": ABSENT},
               {"name": "TLS-RPT", "status": "absent", "pill_label": ABSENT})
    kinds = [(e["protocol"], e["type"]) for e in _entries(rm)]
    assert kinds == [("TLS-RPT", "TXT"), ("MTA-STS", "Policy file"),
                     ("MTA-STS", "A or CNAME"), ("MTA-STS", "TXT")]
    rpt, policy, host, txt = _entries(rm)
    assert rpt["value"] == f"v=TLSRPTv1; rua=mailto:tls-reports@{D}"
    assert policy["host"] == f"https://mta-sts.{D}/.well-known/mta-sts.txt"
    assert policy["value"] == ("version: STSv1\nmode: testing\nmx: mx1.example.com\n"
                               "mx: mx2.example.com\nmax_age: 604800")
    assert host["value"] is None
    assert txt["value"] == "v=STSv1; id=2026102501"
    assert all(e["optional"] for e in _entries(rm))


def test_testing_mode_moves_to_enforce_with_a_new_id():
    rm = _plan(_mx("mx1.example.com"),
               {"name": "MTA-STS", "status": "warn", "record": "v=STSv1; id=2026102501",
                "policy_mode": "testing", "policy_mx": ["*.example.com"], "policy_max_age": 86400,
                "fix": "Move to mode=enforce once TLS-RPT reports confirm reliable TLS delivery."})
    policy, txt = _entries(rm, "MTA-STS")
    assert policy["value"] == "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400"
    assert txt["value"] == "v=STSv1; id=2026102502"


def test_malformed_tls_rpt_keeps_its_address():
    rm = _plan(_mx("mx1.example.com"),
               {"name": "TLS-RPT", "status": "fail", "record": f"v=tlsrptv1; rua=mailto:tls@{D}",
                "fix": "Republish the record."})
    [entry] = _entries(rm, "TLS-RPT")
    assert entry["value"] == f"v=TLSRPTv1; rua=mailto:tls@{D}"


# ---------------------------------------------------------------
# BIMI
# ---------------------------------------------------------------

def test_bimi_without_a_certificate_names_who_issues_it():
    rm = _plan({"name": "BIMI", "status": "warn", "records_found": 1,
                "record": f"v=BIMI1; l=https://{D}/logo.svg",
                "fix": "Add a certificate."})
    [entry] = _entries(rm, "BIMI")
    assert entry["host"] == f"default._bimi.{D}"
    assert entry["value"] is None
    assert f"l=https://{D}/logo.svg; a=<certificate URL>" in entry["value_from"]


# ---------------------------------------------------------------
# Shape
# ---------------------------------------------------------------

def test_steps_count_up_and_no_internal_keys_leak():
    rm = _plan({"name": "SPF", "status": "fail", "record": "v=spf1 +all"},
               _dkim(dkim_test_mode=["s1"]),
               _mx("mx1.example.com"),
               {"name": "TLS-RPT", "status": "absent", "pill_label": ABSENT})
    cs = rm["change_set"]
    assert [e["step"] for e in cs["entries"]] == list(range(1, len(cs["entries"]) + 1))
    assert cs["exact"] + cs["from_provider"] == len(cs["entries"])
    for item in rm["items"]:
        assert not [k for k in item if k.startswith("_")], item
        for rec in item.get("records") or []:
            assert "edit" not in rec
    for e in cs["entries"]:
        assert (e["value"] is None) == bool(e["value_from"])


def test_edit_tag_list_keeps_order_and_moves_v_first():
    assert plan_records.edit_tag_list("k=rsa; v=DKIM1; p=A", first="v") == "v=DKIM1; k=rsa; p=A"
    assert plan_records.edit_tag_list("v=DKIM1; p=A", {"h": "sha256"}) == "v=DKIM1; p=A; h=sha256"
    assert plan_records.edit_tag_list(None, {"a": "b"}) is None


def test_copy_has_no_dashes():
    rm = _plan({"name": "SPF", "status": "fail", "pill_label": "Missing", "record": None},
               _dkim(dkim_test_mode=["s1"], dkim_deep={"has_weak": True, "keys": [
                   {"selector": "s1", "bits": 1024, "rating": "amber", "revoked": False}]}),
               _mx("mx1.example.com"),
               {"name": "MTA-STS", "status": "absent", "pill_label": ABSENT},
               {"name": "TLS-RPT", "status": "absent", "pill_label": ABSENT})
    copy = json.dumps([[e["value_from"], e["notes"]] for e in _entries(rm)])
    for bad in ("—", "–", " -- "):
        assert bad not in copy


# ---------------------------------------------------------------
# One audit, the page and the PDF
# ---------------------------------------------------------------

@pytest.fixture(scope="module")
def fixture_result():
    # Doc 38's zone: DMARC p=none pct=50, two MX, no MTA-STS or TLS-RPT.
    return json.loads(json.dumps(_run(_zone()), default=str))


def test_the_audit_carries_the_change_set(fixture_result):
    entries = fixture_result["security_roadmap"]["change_set"]["entries"]
    by = {(e["protocol"], e["type"]) for e in entries}
    assert ("MTA-STS", "Policy file") in by and ("TLS-RPT", "TXT") in by
    # The pct edit is exact; moving to enforcement is the owner's call and
    # comes after it on the same record.
    dmarc = [e for e in entries if e["protocol"] == "DMARC"]
    assert [e["value"] is None for e in dmarc] == [False, True]
    policy = next(e for e in entries if e["type"] == "Policy file")
    assert f"mx: mx1.{UI_DOMAIN}\nmx: mx2.{UI_DOMAIN}" in policy["value"]


def test_the_pdf_prints_the_change_set(fixture_result):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(fixture_result)))
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)
    assert "DNS changes, in order" in text
    assert f"_smtp._tls.{UI_DOMAIN}" in text
    assert "Publish the policy file at" in text


def test_the_page_shows_the_change_set(browser, fixture_result):  # noqa: F811
    for width in (1280, 375):
        ctx, pg, errors = _page(browser, "dark", width)
        _render(pg, fixture_result)
        toggle = pg.locator(".change-set .plan-optional-toggle")
        assert toggle.count() == 1
        assert "DNS changes, in order" in toggle.inner_text()
        toggle.click()
        steps = pg.locator(".cs-entry")
        assert steps.count() == len(fixture_result["security_roadmap"]["change_set"]["entries"])
        assert steps.first.is_visible()
        box = toggle.bounding_box()
        assert box["height"] >= 44
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not errors, errors
        ctx.close()
