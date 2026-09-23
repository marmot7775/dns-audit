"""Doc 65: the PDF has the same shape as the results page.

Part 1 is the report: summary, what to do, checks. Part 2 is the appendix,
lettered, holding the evidence. A PDF cannot collapse, so the hierarchy is
order plus a divider page, and every plan item carries the record to
publish rather than a table row with a business impact column.
"""
import io
import os
import re
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import pdf_report  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402

DOMAIN = "doc65.test"


def _rsa_key_record():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


@pytest.fixture(scope="module")
def key_record():
    return _rsa_key_record()


def _zone(key_record, dmarc="v=DMARC1; p=none; pct=50; rua=mailto:d@" + DOMAIN):
    records = {
        DOMAIN: {"MX": [(10, f"mx1.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.65"], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"s1._domainkey.{DOMAIN}": {"TXT": [key_record]},
        f"mx1.{DOMAIN}": {"A": ["203.0.113.66"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    }
    if dmarc:
        records[f"_dmarc.{DOMAIN}"] = {"TXT": [dmarc]}
    return FakeZone(records)


def _pages(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return [p.extract_text() or "" for p in reader.pages]


def _flat(pages):
    return " ".join(" ".join(pages).split())


def _run(zone, scope="complete", selector="s1"):
    with fake_dns(zone):
        return audit_engine.run_full_audit(DOMAIN, scope=scope, dkim_selector=selector)


@pytest.fixture(scope="module")
def complete(key_record):
    """One complete run for the whole module; every test reads the same PDF."""
    return _run(_zone(key_record))


# ---------------------------------------------------------------
# It builds
# ---------------------------------------------------------------

def test_the_pdf_builds_for_a_complete_run(complete):
    pages = _pages(complete)
    assert len(pages) > 5
    assert "DNS Security Audit Report" in pages[0]


def test_the_pdf_builds_for_a_scoped_run(key_record):
    pages = _pages(_run(_zone(key_record), scope="dmarc"))
    text = _flat(pages)
    assert "1. Summary" in text and "3. Checks" in text


def test_the_pdf_builds_for_a_domain_with_no_dmarc_record(key_record):
    result = _run(_zone(key_record, dmarc=None))
    text = _flat(_pages(result))
    assert "Publish a DMARC record" in text
    # The no-record case is the record builder's first_record mode.
    assert "v=DMARC1; p=none; rua=mailto:dmarc@" in text


# ---------------------------------------------------------------
# The contents page
# ---------------------------------------------------------------

def test_the_contents_page_lists_both_parts_in_order(complete):
    cover = _pages(complete)[0]
    expected = ["1. Summary", "2. What to do", "3. Checks",
                "Part 2", "A. DMARC in depth", "B. Attack surface and subdomains",
                "C. SPF and DKIM in depth", "D. Migration path", "E. About this report"]
    positions = [cover.find(e) for e in expected]

    assert all(p >= 0 for p in positions), list(zip(expected, positions))
    assert positions == sorted(positions)
    assert "Part 1 is the report. Part 2 holds the detail behind it." in cover


def test_a_section_that_did_not_render_gets_no_contents_line(key_record):
    # dns_infra runs no DMARC, SPF or DKIM card, so Appendix A, B, C and D
    # have nothing to build and the letters close up.
    cover = _pages(_run(_zone(key_record), scope="dns_infra", selector=None))[0]

    assert "A. What each check means" in cover
    assert "B. About this report" in cover
    for absent in ("DMARC in depth", "Attack surface and subdomains", "Migration path"):
        assert absent not in cover, absent


# ---------------------------------------------------------------
# What to do
# ---------------------------------------------------------------

def test_every_plan_item_carries_the_three_parts(complete):
    text = _flat(_pages(complete))
    items = complete["security_roadmap"]["items"]

    assert items, "the fixture produced no plan items"
    for part in ("What to change", "How to confirm"):
        assert text.count(part) >= len(items), (part, text.count(part), len(items))
    # "Why it matters" is the item's impact, and a row that falls back to a
    # card's own fix text has none: the action is that sentence already
    # (Doc 64). Every item that has one prints it.
    with_impact = [i for i in items if i.get("impact")]
    assert with_impact
    assert text.count("Why it matters") >= len(with_impact)
    for item in items:
        assert item["action"] in text, item["action"]
        if item.get("impact"):
            assert item["impact"][:60] in text, item["impact"]


def test_the_dmarc_plan_item_carries_its_own_record(complete):
    # Each DMARC row carries the record that does what it says; the
    # readiness panel's one record used to go on every row.
    text = _flat(_pages(complete))
    rows = [i for i in complete["security_roadmap"]["items"]
            if i["protocol"] == "DMARC" and i.get("record")]

    assert rows
    assert f"TXT record at _dmarc.{DOMAIN}" in text
    for row in rows:
        assert row["record"] in text, row


def test_the_plan_lost_the_business_impact_column_and_the_address_label(complete):
    text = _flat(_pages(complete))

    assert "Business Impact" not in text
    assert "Address:" not in text


# ---------------------------------------------------------------
# Part 1 before Part 2
# ---------------------------------------------------------------

def _divider_index(pages):
    """The divider page, not the contents line that names it."""
    return next(i for i, p in enumerate(pages)
                if "Nothing in it changes the plan in Part 1." in p)


def test_the_dmarc_check_comes_before_the_divider_and_its_validation_after(complete):
    pages = _pages(complete)
    divider = _divider_index(pages)
    checks_page = next(i for i, p in enumerate(pages) if re.search(r"3\s*Checks", p))
    validation = next(i for i, p in enumerate(pages)
                      if "RFC 9989 Strict Validation" in p or "Strict Record Validation" in p)

    assert checks_page < divider < validation, (checks_page, divider, validation)
    # The DMARC card itself is in Part 1.
    part1 = " ".join(pages[:divider])
    assert "p=none (monitoring only, no enforcement)" in " ".join(part1.split())


def test_part_one_stays_within_eleven_pages(complete):
    # Doc 65 set this at eight. Doc 67 gave every check a two-sentence line
    # saying what its protocol is, in the Checks section, which is two pages
    # of report the reader now gets before the appendix starts. The plan then
    # gained a row this fixture never had: p=none with pct=50 had no row to
    # remove pct, because the removed-tags row came only from a Compatible
    # verdict. That row and its record are the eleventh page. The budget
    # moved by exactly what was added and no further.
    pages = _pages(complete)
    divider = _divider_index(pages)

    assert divider <= 11, f"Part 1 runs to {divider} pages"


def test_each_check_points_at_the_appendix_that_holds_its_detail(complete):
    text = _flat(_pages(complete))

    assert "Detail in Appendix A and Appendix C." in text  # DMARC
    assert text.count("Detail in Appendix C.") >= 2  # SPF, DKIM and the rest


# ---------------------------------------------------------------
# The appendix
# ---------------------------------------------------------------

def test_the_appendix_labels_both_dmarc_records(complete):
    text = _flat(_pages(complete))

    assert "End state: enforcement" in text
    assert "Next edit: clean up the record, same policy" in text
    assert ("Reach this through the migration steps, moving only when your "
            "aggregate reports show every legitimate sender aligned.") in text
    assert "Recommended RFC 9989-Ready record" not in text


def test_the_appendix_keeps_the_subdomain_rows_and_the_deep_tables(complete):
    text = _flat(_pages(complete))

    assert "SPF Mechanism Breakdown" in text or "SPF in depth" in text
    assert "DKIM in depth" in text
    assert "What each check means" in text
    # The subdomain table's rows survived the move.
    subdomains = complete.get("subdomain_audit") or {}
    for row in (subdomains.get("subdomains") or [])[:3]:
        assert row["subdomain"] in text, row["subdomain"]


def test_no_page_carries_an_em_dash_or_a_double_hyphen(complete):
    for i, page in enumerate(_pages(complete), 1):
        assert "—" not in page, f"page {i} has an em dash"
        assert " -- " not in page, f"page {i} has a double hyphen"
