"""Two grading calls settled after the 2026-10-25 bug hunt.

- MTA-STS mode: none withdraws the policy (RFC 8461 section 5). It graded
  green Pass beside an explanation saying it has no protective effect. It is
  grey now, with its own pill, and never counts as a warning.
- An inherited sp= (or np=) that is not a valid policy reached the card as
  the policy "bogus" and graded red. RFC 7489 section 6.6.3 step 6 reads a
  record with an invalid p or sp as p=none when rua holds a valid URI, which
  is what the apex already did for its own p=.
"""
import dns.resolver
import pytest

from conftest import FakeZone
from test_dmarc_grades import DOMAIN, RUA, _card, _run

POLICY = f"version: STSv1\nmode: none\nmx: mx1.{DOMAIN}\nmx: mx2.{DOMAIN}\nmax_age: 86400\n"
STS_TXT = {f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20261025"]}}


def test_mta_sts_mode_none_is_grey_not_green(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}", mta_sts_policy=POLICY, extra=STS_TXT)
    card = _card(result, "MTA-STS")
    assert card["status"] == "absent", card["status"]
    assert card["pill_label"] == "Turned off"


def test_mta_sts_enforce_still_passes(audit):
    policy = POLICY.replace("mode: none", "mode: enforce").replace("86400", "604800")
    card = _card(_run(audit, f"v=DMARC1; p=reject; {RUA}", mta_sts_policy=policy,
                      extra=STS_TXT), "MTA-STS")
    assert card["status"] == "pass"


ORG = "parent.example"
SUB = f"mail.{ORG}"


def _sub_zone(parent):
    zone = FakeZone({
        ORG: {"NS": [f"ns1.{ORG}", f"ns2.{ORG}"], "MX": [(10, f"mx1.{ORG}")],
              "TXT": ["v=spf1 mx -all"]},
        f"mx1.{ORG}": {"A": ["203.0.113.11"]},
        f"_dmarc.{ORG}": {"TXT": [parent]},
        SUB: {"A": ["203.0.113.10"], "MX": [(10, f"mx1.{ORG}")], "TXT": ["v=spf1 mx -all"]},
    })
    zone.fail(SUB, "SOA", dns.resolver.NoAnswer())
    return zone


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


@pytest.mark.parametrize("tag", ["sp=bogus", "sp=", "np=bogus"])
def test_an_invalid_inherited_policy_with_rua_reads_as_p_none(audit, tag):
    card = _dmarc(audit(_sub_zone(f"v=DMARC1; p=reject; {tag}; rua=mailto:d@{ORG}"),
                        SUB, scope="complete"))
    if tag.startswith("np"):
        # np applies to names that do not exist; this subdomain exists, so p applies.
        assert card["status"] == "pass", card.get("verdict")
        return
    if tag == "sp=":
        # An empty sp is no sp: p=reject applies.
        assert card["status"] == "pass", card.get("verdict")
        return
    assert card["status"] == "warn", card.get("verdict")
    assert card["verdict"].startswith("Inherited: none"), card["verdict"]


def test_an_invalid_inherited_policy_without_rua_still_fails(audit):
    card = _dmarc(audit(_sub_zone("v=DMARC1; p=reject; sp=bogus"), SUB, scope="complete"))
    assert card["status"] == "fail"
