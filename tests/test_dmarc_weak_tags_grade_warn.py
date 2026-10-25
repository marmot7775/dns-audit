"""DMARC cards that carried a weakness in their own rows and still said pass.

- A subdomain inheriting p=quarantine or p=reject ignored the parent's pct
  and t. pct below 100 is amber at the parent (CLAUDE.md, Doc 38), and the
  same record applies to the subdomain.
- An enforcing record with t=y asks receivers for one level less than p
  (RFC 9989 section 4.7). The card showed the warning row and graded pass.
- A rua or ruf without mailto: gets no reports. The engine filed a warning,
  the transformer only tested rua for truthiness and graded pass.
"""
import dns.resolver
import pytest

from conftest import FakeZone

ORG = "weaktags.example"
SUB = f"mail.{ORG}"
RUA = f"rua=mailto:dmarc@{ORG}"


def _zone(dmarc_at_org, sub=False):
    records = {
        ORG: {"NS": [f"ns1.{ORG}", f"ns2.{ORG}"], "MX": [(10, f"mx1.{ORG}")],
              "TXT": ["v=spf1 mx -all"]},
        f"mx1.{ORG}": {"A": ["203.0.113.11"]},
        f"ns1.{ORG}": {"A": ["203.0.113.21"]},
        f"ns2.{ORG}": {"A": ["203.0.113.22"]},
        f"_dmarc.{ORG}": {"TXT": [dmarc_at_org]},
    }
    if sub:
        records[SUB] = {"A": ["203.0.113.10"], "MX": [(10, f"mx1.{ORG}")],
                        "TXT": ["v=spf1 mx -all"]}
    zone = FakeZone(records)
    if sub:
        zone.fail(SUB, "SOA", dns.resolver.NoAnswer())
    return zone


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


@pytest.mark.parametrize("parent", [
    f"v=DMARC1; p=quarantine; pct=10; {RUA}",
    f"v=DMARC1; p=reject; pct=0; {RUA}",
    f"v=DMARC1; p=quarantine; t=y; {RUA}",
])
def test_inherited_pct_or_testing_flag_is_amber(audit, parent):
    card = _dmarc(audit(_zone(parent, sub=True), SUB, scope="complete"))
    assert card["status"] == "warn", (card["status"], card.get("verdict"))


def test_inherited_full_enforcement_still_passes(audit):
    card = _dmarc(audit(_zone(f"v=DMARC1; p=reject; {RUA}", sub=True), SUB,
                        scope="complete"))
    assert card["status"] == "pass"


@pytest.mark.parametrize("record", [
    f"v=DMARC1; p=quarantine; t=y; {RUA}",
    f"v=DMARC1; p=reject; t=y; {RUA}",
    f"v=DMARC1; p=reject; rua=dmarc@{ORG}",
    f"v=DMARC1; p=reject; {RUA}; ruf=forensic@{ORG}",
])
def test_enforcing_record_with_a_weak_tag_is_amber(audit, record):
    card = _dmarc(audit(_zone(record), ORG, scope="complete"))
    assert card["status"] == "warn", (card["status"], card.get("verdict"))


def test_p_none_with_rua_lacking_mailto_is_amber_for_deliverability(audit):
    card = _dmarc(audit(_zone(f"v=DMARC1; p=none; rua=dmarc@{ORG}"), ORG,
                        scope="deliverability"))
    assert card["status"] == "warn"


@pytest.mark.parametrize("record", [
    f"v=DMARC1; p=reject; {RUA}",
    f"v=DMARC1; p=reject; t=n; {RUA}",
])
def test_clean_enforcing_record_still_passes(audit, record):
    assert _dmarc(audit(_zone(record), ORG, scope="complete"))["status"] == "pass"
