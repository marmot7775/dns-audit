"""APRF (draft-brotman-aggregate-performance-reporting-01): informational only.

The check looks for the record a mailbox provider reads to find where to send
an aggregate performance report, keyed on the DKIM signature: a selector
record, a wildcard to the left of _aprf, or the bare _aprf._domainkey name,
most specific first. It never touches a count: the card lives in the
response's draft_standards list, not in checks. Every test runs offline on a
declared zone.
"""
import datetime
import io
import json
import os
import sys
from unittest.mock import patch

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import pdf_report
import result_transformer
from conftest import FakeZone, fake_dns
from test_ui_consistency_a11y import (  # noqa: F401
    DOMAIN as UI_DOMAIN,
    _page,
    _render,
    _zone as _ui_zone,
    browser,
)

DOMAIN = "aprf.test"
BARE = f"_aprf._domainkey.{DOMAIN}"
WILD = f"*._aprf._domainkey.{DOMAIN}"
DKIM_P = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
LIVE_DKIM = {"found_selectors": [
    {"selector": "s1", "record": f"v=DKIM1; k=rsa; p={DKIM_P}"},
    {"selector": "old", "record": "v=DKIM1; k=rsa; p="},
]}


class WildZone(FakeZone):
    """FakeZone plus DNS wildcards: an undeclared name is answered by the
    closest *.<ancestor> declared for the type, as a resolver would."""

    def resolve(self, name, rdtype="A", *args, **kwargs):
        try:
            return super().resolve(name, rdtype, *args, **kwargs)
        except dns.resolver.NXDOMAIN:
            labels = str(name).rstrip(".").lower().split(".")
            for i in range(1, len(labels)):
                wild = "*." + ".".join(labels[i:])
                if self._key(wild, rdtype) in self._records:
                    return super().resolve(wild, rdtype, *args, **kwargs)
            raise


def _check(records, raw_dkim=LIVE_DKIM, domain=DOMAIN):
    zone = records if isinstance(records, FakeZone) else WildZone(
        {name: {"TXT": txt if isinstance(txt, list) else [txt]} for name, txt in records.items()})
    with fake_dns(zone):
        raw = audit_engine._raw_check_aprf(domain, raw_dkim)
    return raw, result_transformer.transform_aprf(raw, domain), zone


def _text(card):
    return " ".join(card["paragraphs"])


def _queried(zone, needle):
    return [name for name, rtype in zone.queries if needle in name]


# 1
def test_bare_record_is_reported_with_its_location():
    raw, card, _ = _check({BARE: f"v=APRFv1; rua=mailto:aprf@{DOMAIN}"})
    assert card["aprf_state"] == "published"
    assert card["pill_label"] == "Published"
    assert card["record_location"] == BARE
    assert card["record"] == f"v=APRFv1; rua=mailto:aprf@{DOMAIN}"
    assert f"An APRF record is published at {BARE}. Reports go to aprf@{DOMAIN}." in _text(card)
    assert f"Reports cover only mail signed with DKIM as {DOMAIN}." in _text(card)


# 2
def test_wildcard_is_found_through_the_random_label_probe():
    raw, card, zone = _check({WILD: f"v=APRFv1; rua=mailto:aprf@{DOMAIN}"})
    assert card["aprf_state"] == "published"
    assert card["record_location"] == WILD
    probes = [n for n in _queried(zone, "._aprf._domainkey.")
              if n.split(".")[0] not in ("_aprf", "s1", "*")]
    assert len(probes) == 1 and probes[0].startswith("dnsaudit")
    # The s1 name answers too, with the wildcard's own record. That is the
    # wildcard, not a selector record.
    assert [r["kind"] for r in raw["records"]] == ["wildcard"]
    assert audit_engine._aprf_random_label() != audit_engine._aprf_random_label()


# 3
def test_selector_record_wins_over_wildcard_and_bare():
    raw, card, zone = _check({
        BARE: f"v=APRFv1; rua=mailto:bare@{DOMAIN}",
        WILD: f"v=APRFv1; rua=mailto:wild@{DOMAIN}",
        f"s1.{BARE}": f"v=APRFv1; rua=mailto:sel@{DOMAIN}",
    })
    assert [r["kind"] for r in raw["records"]] == ["selector", "wildcard", "bare"]
    assert card["record_location"] == f"s1.{BARE}"
    assert card["record"] == f"v=APRFv1; rua=mailto:sel@{DOMAIN}"
    assert card["verdict"] == f"Published at s1.{BARE}"
    # The revoked selector is never asked about.
    assert not _queried(zone, f"old.{BARE}")


# 4
@pytest.mark.parametrize("record", [f"rua=mailto:aprf@{DOMAIN}",
                                    f"v=APRFv2; rua=mailto:aprf@{DOMAIN}"])
def test_missing_or_wrong_v_tag_is_ignored(record):
    _, card, _ = _check({BARE: record})
    assert card["aprf_state"] == "ignored"
    assert card["pill_label"] == "Ignored"
    assert (f"A record exists at {BARE}, but a provider following the draft would "
            "ignore it because its v tag is missing or is not APRFv1.") in _text(card)


# 5
def test_missing_rua_is_ignored():
    _, card, _ = _check({BARE: "v=APRFv1; sdi=Signer-Info,^"})
    assert card["aprf_state"] == "ignored"
    assert "because its rua tag has no mailto destination." in _text(card)


# 6
def test_two_rua_destinations_are_both_listed():
    _, card, _ = _check({BARE: f"v=APRFv1; rua=mailto:a@{DOMAIN},mailto:b@{DOMAIN}"})
    assert f"Reports go to a@{DOMAIN} and b@{DOMAIN}." in _text(card)


# 7
def test_same_organization_destination_needs_no_authorization_lookup():
    raw, card, zone = _check({BARE: f"v=APRFv1; rua=mailto:aprf@reports.{DOMAIN}"})
    assert raw["destinations"] == []
    assert not _queried(zone, f".{DOMAIN}._aprf.")
    assert "different domain" not in _text(card)


# 8
def test_cross_domain_destination_without_the_section_9_record():
    raw, card, zone = _check({BARE: "v=APRFv1; rua=mailto:r@reports.example.net"})
    assert len(_queried(zone, f".{DOMAIN}._aprf.reports.example.net")) == 1
    assert ("Reports are set to go to r@reports.example.net, which is on a different "
            f"domain. Under the draft, that domain should publish a record allowing "
            f"reports for {DOMAIN}. None was found, so providers may not send reports "
            "there.") in _text(card)


def test_cross_domain_destination_with_the_section_9_record():
    _, card, zone = _check({
        f"s1.{BARE}": "v=APRFv1; rua=mailto:r@reports.example.net",
        f"s1.{DOMAIN}._aprf.reports.example.net": "v=APRFv1;",
    })
    # The real selector, not a random label, for a selector record.
    assert _queried(zone, f"s1.{DOMAIN}._aprf.reports.example.net")
    assert "That domain publishes a record allowing reports" in _text(card)
    assert "None was found" not in _text(card)


def test_wildcard_authorization_covers_a_bare_record():
    _, card, _ = _check({
        BARE: "v=APRFv1; rua=mailto:r@reports.example.net",
        f"*.{DOMAIN}._aprf.reports.example.net": "v=APRFv1",
    })
    assert "That domain publishes a record allowing reports" in _text(card)


# 9
def test_dkim_timed_out_skips_selector_lookups_and_says_so():
    raw, card, zone = _check({BARE: f"v=APRFv1; rua=mailto:aprf@{DOMAIN}"},
                             raw_dkim={"found_selectors": [], "timed_out": True})
    names = {n for n, _ in zone.queries}
    assert names == {BARE, next(n for n in names if n.startswith("dnsaudit"))}
    assert ("Selector specific records were not checked, because the DKIM check "
            "did not finish.") in _text(card)
    assert card["aprf_state"] == "published"


def test_no_live_selectors_says_so():
    _, card, _ = _check({}, raw_dkim={"found_selectors": [LIVE_DKIM["found_selectors"][1]]})
    assert card["aprf_state"] == "none"
    assert "because the DKIM check found no live selectors." in _text(card)


# 10
def test_servfail_on_the_bare_name_is_unavailable_not_absent():
    zone = WildZone({}).fail(BARE, "TXT")
    _, card, _ = _check(zone)
    assert card["status"] == "unavailable"
    assert card["aprf_state"] == "unavailable"
    assert card["pill_label"] == "Not checked"
    assert card["what_this_is"] == result_transformer.APRF_NOTE
    assert "No APRF record found" not in _text(card) + card["verdict"]


def test_timeout_on_a_selector_name_is_unavailable():
    import dns.exception
    zone = WildZone({}).fail(f"s1.{BARE}", "TXT", dns.exception.Timeout())
    _, card, _ = _check(zone)
    assert card["aprf_state"] == "unavailable"


def test_a_dkim_wildcard_answer_is_not_an_aprf_record():
    _, card, _ = _check({f"*._domainkey.{DOMAIN}": f"v=DKIM1; k=rsa; p={DKIM_P}"})
    assert card["aprf_state"] == "none"


# 11
def _ui_run(zone, aprf_on):
    scopes = audit_engine.APRF_SCOPES if aprf_on else set()
    with patch.object(audit_engine, "APRF_SCOPES", scopes), fake_dns(zone):
        result = audit_engine.run_full_audit(UI_DOMAIN, dkim_selector="s1", scope="complete")
    return json.loads(json.dumps(result, default=str))


@pytest.fixture(scope="module")
def with_and_without():
    extra = {f"_aprf._domainkey.{UI_DOMAIN}": {"TXT": [f"v=APRFv1; rua=mailto:r@{UI_DOMAIN}"]}}
    return (_ui_run(_ui_zone(extra=extra), True), _ui_run(_ui_zone(extra=extra), False))


def _pdf_pages(result):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return [" ".join((p.extract_text() or "").split()) for p in reader.pages]


def test_the_card_changes_no_count_in_the_result_or_the_pdf(with_and_without):
    on, off = with_and_without
    assert [c["aprf_state"] for c in on["draft_standards"]] == ["published"]
    assert off["draft_standards"] == []
    assert "APRF" not in {c["name"] for c in on["checks"]}
    for key in ("checks", "security_roadmap", "executive_summary"):
        assert on[key] == off[key], key
    assert pdf_report._tally(on["checks"]) == pdf_report._tally(off["checks"])

    pages_on, pages_off = _pdf_pages(on), _pdf_pages(off)
    assert pages_on[0] == pages_off[0]  # the cover: tally, coverage, biggest risk
    text_on, text_off = " ".join(pages_on), " ".join(pages_off)
    assert "Draft standards" in text_on and "Draft standards" not in text_off
    card = on["draft_standards"][0]
    for words in [card["verdict"], "APRF is a working group draft, not yet a standard.",
                  f"Reports go to r@{UI_DOMAIN}."]:
        assert words in text_on, words
    contents = text_on[text_on.index("Part 1"):][:600] if "Part 1" in text_on else text_on
    assert "Draft standards" not in contents.split("Part 2")[0]


_COUNTS_JS = """() => ({
    tiles: [...document.querySelectorAll('#summary-grid .summary-value')].map(e => e.textContent),
    heading: document.getElementById('results-heading').textContent,
    title: document.title,
    plan: document.getElementById('priority-list').textContent,
    summary: document.getElementById('executive-summary-slot').textContent,
    cards: [...document.querySelectorAll('#results-list .result-card')].map(e => e.id),
    draft: [...document.querySelectorAll('#draft-standards-list .result-card')].map(e => e.id),
    draftHidden: document.getElementById('draft-standards-section').classList.contains('is-hidden'),
    draftText: document.getElementById('draft-standards-section').textContent,
})"""


def test_the_card_changes_no_count_on_the_web_page(browser, with_and_without):  # noqa: F811
    seen = []
    for result in with_and_without:
        ctx, pg, errors = _page(browser, "dark", 1280)
        _render(pg, result)
        seen.append(pg.evaluate(_COUNTS_JS))
        assert not errors, errors
        ctx.close()
    on, off = seen
    for key in ("tiles", "heading", "title", "plan", "summary", "cards"):
        assert on[key] == off[key], key
    assert on["draft"] == ["check-aprf"] and not on["draftHidden"]
    assert off["draft"] == [] and off["draftHidden"]
    assert "APRF (draft standard)" in on["draftText"]
    assert result_transformer.APRF_NOTE in on["draftText"]


# 12
@pytest.mark.parametrize("scope", ["dmarc", "transport", "dns_infra", "security_scan"])
def test_out_of_scope_runs_make_no_aprf_queries(scope):
    zone = _ui_zone(extra={f"_aprf._domainkey.{UI_DOMAIN}": {"TXT": ["v=APRFv1; rua=mailto:r@x.test"]}})
    with fake_dns(zone):
        result = audit_engine.run_full_audit(UI_DOMAIN, dkim_selector="s1", scope=scope)
    assert not [n for n, _ in zone.queries if "_aprf" in n]
    assert result["draft_standards"] == []


# 13
def test_the_provider_support_note_has_been_reviewed_in_the_last_90_days():
    reviewed = datetime.date.fromisoformat(result_transformer.APRF_NOTE_REVIEWED)
    assert datetime.date.today() <= reviewed + datetime.timedelta(days=90), (
        f"APRF_NOTE was last reviewed on {reviewed}. Recheck which mailbox "
        "providers send APRF reports and the draft's status, then update "
        "APRF_NOTE and APRF_NOTE_REVIEWED in result_transformer.py together."
    )


# 14
def _every_state():
    yield _check({})[1]
    yield _check({BARE: f"v=APRFv1; rua=mailto:a@{DOMAIN},mailto:r@reports.example.net"})[1]
    yield _check({BARE: "v=APRFv1; rua=mailto:r@reports.example.net",
                  f"*.{DOMAIN}._aprf.reports.example.net": "v=APRFv1"})[1]
    yield _check({BARE: f"v=APRFv2; rua=mailto:a@{DOMAIN}"})[1]
    yield _check({BARE: "v=APRFv1"})[1]
    yield _check(WildZone({}).fail(BARE, "TXT"))[1]
    yield _check({}, raw_dkim={"found_selectors": [], "timed_out": True})[1]
    yield _check({}, raw_dkim={"found_selectors": []})[1]


def test_card_copy_has_no_dashes_and_no_quotation_marks():
    for card in _every_state():
        copy = " ".join([card["what_this_is"], card["verdict"], card["pill_label"],
                         card["plain_name"]] + card["paragraphs"])
        for bad in ("—", "–", " - ", "--", '"', "“", "”", "‘", "’"):
            assert bad not in copy, (bad, copy)


def test_no_state_carries_a_fix_or_a_plan_row():
    for card in _every_state():
        assert card["fix"] is None and card["fix_records"] is None
        assert card["informational"] is True
        assert card["status"] in ("absent", "unavailable")


def test_no_record_advice_matches_the_article():
    # /articles/aprf: publish if your own domain signs, skip if the platform
    # signs with its own domain. Comcast is the first provider, not the test.
    text = " ".join(_check({})[1]["paragraphs"])
    assert "who signs your mail" in text
    assert "meaningful share" not in text
    assert "Comcast" not in text
