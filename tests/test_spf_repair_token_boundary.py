"""Regression test: the malformed record repair must not mangle a token that
merely ends in a qualified 'all'.

repair_spf_missing_spaces used (?<=\\S)([~?+\\-]all(?=\\s|$)) with no token
boundary guard, so

    v=spf1 ip4:1.2.3.4 include:mail-all ~all

became

    v=spf1 ip4:1.2.3.4 include:mail -all ~all

The include target silently lost its last label, a -all the operator never
published was injected mid record, and a perfectly valid record was reported
as malformed. "mail-all" is an ordinary hostname label.

The repair itself is worth keeping: ip4:1.2.3.4~all really is a jammed
multi string TXT record and really does need the space put back.

Doc 62 is the same bug one character earlier: the lookbehind was (?<=\\S) and
a qualifier is not whitespace, so "+include:example.com" was split into
"+ include:example.com", the stray qualifier parsed as an empty mechanism and
bbc.co.uk was graded fail for a record that is valid RFC 7208.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer
from conftest import FakeZone, fake_dns
from spf_recursive import repair_spf_missing_spaces


def test_include_ending_in_all_is_left_alone():
    record = "v=spf1 ip4:1.2.3.4 include:mail-all ~all"
    repaired, malformed = repair_spf_missing_spaces(record)

    assert repaired == record, (
        f"mail-all is a hostname label, not a jammed -all. Got {repaired!r}"
    )
    assert malformed is False, (
        "A valid record must not be reported as malformed"
    )


def test_other_tokens_ending_in_all_are_left_alone():
    for record in (
        "v=spf1 a:catch-all.example.com -all",
        "v=spf1 include:spf-all.example.net include:send-all.example.net ~all",
        "v=spf1 exists:%{i}.deny-all.example.com -all",
    ):
        repaired, malformed = repair_spf_missing_spaces(record)
        assert repaired == record, f"{record!r} became {repaired!r}"
        assert malformed is False


def test_a_genuinely_jammed_all_is_still_repaired():
    repaired, malformed = repair_spf_missing_spaces("v=spf1 ip4:1.2.3.4~all")
    assert repaired == "v=spf1 ip4:1.2.3.4 ~all"
    assert malformed is True

    repaired, malformed = repair_spf_missing_spaces(
        "v=spf1ip4:1.2.3.0/22include:example.com~all"
    )
    assert repaired == "v=spf1 ip4:1.2.3.0/22 include:example.com ~all"
    assert malformed is True


def test_the_card_does_not_call_a_mail_all_include_malformed():
    domain = "mailall.example.test"
    record = "v=spf1 ip4:1.2.3.4 include:mail-all.example.net ~all"
    zone = {
        domain: {"TXT": [record]},
        "mail-all.example.net": {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]},
    }
    with fake_dns(FakeZone(zone)):
        raw = audit_engine._raw_check_spf(domain)
    card = result_transformer.transform_spf(raw, has_mx=True)

    assert raw["record"] == record, (
        f"The card must show what the domain actually publishes. Got "
        f"{raw['record']!r}"
    )
    issue_texts = " ".join(i["issue"] for i in raw["issues"]).lower()
    assert "not space-delimited" not in issue_texts, (
        f"Nothing here is jammed together; got {issue_texts!r}"
    )
    # warn, not pass: ~all is one of Doc 38's warn rules (Doc 44 item 7).
    # What this test guards is the absence of a malformed finding above.
    assert card["status"] == "warn"


# ---------------------------------------------------------------
# Doc 62: an explicit qualifier is not a missing space
# ---------------------------------------------------------------
#
# The repair's lookbehind was (?<=\S), and a qualifier is not whitespace, so
# "+include:spf.sis.bbc.co.uk" was split into "+ include:spf.sis.bbc.co.uk".
# The stray "+" then parsed as an empty mechanism and bbc.co.uk, whose record
# is valid RFC 7208, was graded fail as a malformed record.

BBC_RECORD = (
    "v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16 "
    "+include:spf.sis.bbc.co.uk +include:spf.messagelabs.com ~all"
)


def test_an_explicit_qualifier_on_include_is_left_alone():
    repaired, malformed = repair_spf_missing_spaces(BBC_RECORD)

    assert repaired == BBC_RECORD, (
        f"An explicit + on include: is legal RFC 7208. Got {repaired!r}"
    )
    assert malformed is False


def test_every_qualifier_on_every_lookup_mechanism_is_left_alone():
    record = (
        "v=spf1 -ip4:1.2.3.4 ?include:x.com ~exists:%{i}.x.com +redirect=y.com"
    )
    repaired, malformed = repair_spf_missing_spaces(record)

    assert repaired == record, f"{record!r} became {repaired!r}"
    assert malformed is False


def _bbc_style_zone():
    """The Doc 48 fixture zone, publishing the bbc.co.uk SPF record."""
    from test_ui_consistency_a11y import _zone

    return _zone(spf=BBC_RECORD, extra={
        "spf.sis.bbc.co.uk": {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]},
        "spf.messagelabs.com": {"TXT": ["v=spf1 ip4:198.51.100.2 -all"]},
    })


def _bbc_style_result():
    from test_ui_consistency_a11y import _run

    return _run(_bbc_style_zone())


def test_the_card_grades_a_qualified_record_on_what_it_says():
    result = _bbc_style_result()
    card = next(c for c in result["checks"] if c["name"] == "SPF")

    assert card["record"] == BBC_RECORD, (
        f"The card must show what the domain publishes. Got {card['record']!r}"
    )
    # ~all is Doc 38's warn rule; the /16 is a breadth warning. Neither is a
    # malformed record, so the card must not fail.
    assert card["status"] == "warn", card["status"]

    issues = " ".join(
        (i.get("issue", "") + " " + i.get("detail", "")).lower()
        for i in card.get("issues", [])
    )
    assert "jammed together" not in issues, issues
    assert "not space-delimited" not in issues, issues
    assert "not a recognized spf mechanism" not in issues, issues
    assert "empty include" not in issues, issues

    actions = " ".join(
        (i.get("action", "") + " " + i.get("title", "")).lower()
        for i in result["security_roadmap"]["items"]
    )
    assert "separated by a space" not in actions, actions


def test_a_qualified_include_still_counts_as_a_lookup():
    result = _bbc_style_result()
    card = next(c for c in result["checks"] if c["name"] == "SPF")
    deep = card["spf_deep"]

    includes = [m for m in deep["mechanisms"] if m["type"] == "include"]
    assert [m["value"] for m in includes] == [
        "spf.sis.bbc.co.uk", "spf.messagelabs.com"
    ], deep["mechanisms"]
    assert all(m["cost"] == 1 for m in includes), includes
    assert deep["lookup_count"] == 2, deep["lookup_count"]
    assert deep["all_mechanism"] == "~all"


def test_the_pdf_has_no_mechanism_row_that_is_a_bare_qualifier():
    import io

    import pdf_report
    from pypdf import PdfReader

    result = _bbc_style_result()
    deep = next(c for c in result["checks"] if c["name"] == "SPF")["spf_deep"]

    # One PDF table row per mechanism, its first cell the raw token.
    for mech in deep["mechanisms"]:
        assert mech["raw"].strip("+-~?"), (
            f"Mechanism row {mech['raw']!r} is a bare qualifier"
        )
        assert mech["type"] != "unknown", mech

    pdf = pdf_report.generate_pdf(result)
    text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf)).pages)
    assert "+include:spf.sis.bbc.co.uk" in text, (
        "The mechanism table should print the token as published"
    )
