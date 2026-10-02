"""The executive summary verdict agrees with the DMARC, SPF and DKIM cards.

gitlab.com publishes p=reject and an SPF record that needs 13 DNS lookups,
which is a PermError and a red SPF card. The verdict above that card read
"Your domain blocks spoofed email across all vectors, with minor improvements
available.", because the vector count reads the DMARC policy alone. A broken
record now gets its own sentence.

example.com publishes a null MX, v=spf1 -all and p=reject: a domain that
sends and receives no mail. Its verdict read the same "minor improvements"
sentence as a sending domain with work left to do.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone
from test_dmarc_grades import _DKIM_P

DOMAIN = "gitlab-shape.test"
RUA = f"rua=mailto:d@{DOMAIN}"
OVERCLAIMS = ("across all vectors", "minor improvements", "blocked at every level",
              "most attack vectors covered", "smaller improvements",
              "refuse mail that pretends", "most forged mail")


def _zone(dmarc, spf, domain=DOMAIN, extra=None, null_mx=False):
    records = {
        domain: {"MX": [(0, ".")] if null_mx else [(10, f"mx1.{domain}")],
                 "TXT": [spf], "A": ["203.0.113.10"],
                 "NS": [f"ns1.{domain}", f"ns2.{domain}"]},
        f"_dmarc.{domain}": {"TXT": [dmarc]},
        f"mx1.{domain}": {"A": ["203.0.113.11"]},
        f"ns1.{domain}": {"A": ["203.0.113.53"]},
        f"ns2.{domain}": {"A": ["198.51.100.53"]},
    }
    if not null_mx:
        records[f"s1._domainkey.{domain}"] = {"TXT": ["v=DKIM1; k=rsa; p=" + _DKIM_P]}
    records.update(extra or {})
    return FakeZone(records)


def _over_limit_spf(n=13):
    """An SPF record of n includes, each costing one lookup."""
    includes = {f"i{k}.{DOMAIN}": {"TXT": [f"v=spf1 ip4:198.51.100.{k} ~all"]}
                for k in range(n)}
    spf = "v=spf1 " + " ".join(f"include:i{k}.{DOMAIN}" for k in range(n)) + " -all"
    return spf, includes


def _cards(result):
    return {c["name"]: c for c in result["checks"]}


def test_a_red_spf_card_is_named_in_the_verdict(audit):
    spf, includes = _over_limit_spf()
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}", spf, extra=includes),
                   DOMAIN, dkim_selector="s1")
    assert _cards(result)["SPF"]["status"] == "fail"

    verdict = result["executive_summary"]["verdict"]
    assert verdict == "Receivers are asked to refuse forged mail, but one record is broken: SPF."
    for claim in OVERCLAIMS:
        assert claim not in verdict


def test_the_minor_improvements_shape_is_covered_too(audit):
    # pct=100 keeps the record "Compatible", the health status that produced
    # gitlab.com's exact "minor improvements available" sentence.
    spf, includes = _over_limit_spf()
    result = audit(_zone(f"v=DMARC1; p=reject; pct=100; {RUA}", spf, extra=includes),
                   DOMAIN, dkim_selector="s1")

    verdict = result["executive_summary"]["verdict"]
    assert "one record is broken: SPF" in verdict, verdict
    for claim in OVERCLAIMS:
        assert claim not in verdict


def test_quarantine_is_not_described_as_refusing(audit):
    spf, includes = _over_limit_spf()
    result = audit(_zone(f"v=DMARC1; p=quarantine; {RUA}", spf, extra=includes),
                   DOMAIN, dkim_selector="s1")

    verdict = result["executive_summary"]["verdict"]
    assert verdict == ("Receivers are asked to send forged mail to spam, but one record "
                       "is broken: SPF.")


def test_without_rua_the_broken_record_still_wins(audit):
    # The "no visibility" sentence used to overwrite every verdict on an
    # enforcing record without rua, and must not overwrite this one.
    spf, includes = _over_limit_spf()
    result = audit(_zone("v=DMARC1; p=reject", spf, extra=includes),
                   DOMAIN, dkim_selector="s1")

    verdict = result["executive_summary"]["verdict"]
    assert "one record is broken: SPF" in verdict, verdict


def test_a_healthy_record_keeps_its_verdict(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}", "v=spf1 mx -all"),
                   DOMAIN, dkim_selector="s1")

    verdict = result["executive_summary"]["verdict"]
    assert "broken" not in verdict
    assert verdict.startswith("Receivers are asked to refuse mail that pretends"), verdict


# ---------------------------------------------------------------
# example.com: a domain that sends and receives no mail
# ---------------------------------------------------------------

NO_MAIL = "example-shape.test"


def test_a_no_mail_domain_says_so(audit):
    zone = _zone("v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s", "v=spf1 -all",
                 domain=NO_MAIL, null_mx=True)
    result = audit(zone, NO_MAIL)
    assert result["defensive_dns"] is True

    verdict = result["executive_summary"]["verdict"]
    assert verdict == ("This domain is set up to send and receive no email, and asks "
                       "receivers to refuse any mail that uses its name. Nothing to fix.")


def test_a_no_mail_domain_with_a_red_card_keeps_the_existing_logic(audit):
    # Two SPF records are a PermError and a red card; "Nothing to fix" would
    # contradict it.
    zone = _zone("v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s", "v=spf1 -all",
                 domain=NO_MAIL, null_mx=True)
    zone.add(NO_MAIL, "TXT", ["v=spf1 -all", "v=spf1 ip4:203.0.113.9 -all"])
    result = audit(zone, NO_MAIL)
    assert "fail" in [c["status"] for c in result["checks"]]
    assert result["defensive_dns"] is True, "the null MX alone keeps it defensive"

    verdict = result["executive_summary"]["verdict"]
    assert "Nothing to fix" not in verdict
    assert "send and receive no email" not in verdict


def test_a_domain_that_still_receives_mail_is_not_called_no_mail(audit):
    """Null SPF plus p=reject marks the domain defensive even with a working
    MX, but it still receives mail, so the no-mail sentence does not apply."""
    zone = _zone("v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s", "v=spf1 -all",
                 domain=NO_MAIL, null_mx=False)
    result = audit(zone, NO_MAIL)
    assert "send and receive no email" not in result["executive_summary"]["verdict"]
