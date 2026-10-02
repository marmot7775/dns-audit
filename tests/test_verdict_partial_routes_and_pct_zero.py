"""The verdict says "block most forged mail" only when the other routes are blocked.

london.gov.uk publishes "p=quarantine; pct=0". Its verdict read "Your settings
block most forged mail, but not your exact domain." while the direct route was
exposed and both subdomain routes were partial: nothing is blocked. The one
exposed route branch ignored partial routes, and pct=0 was not read as a
policy that enforces nothing at RFC 7489 receivers.
"""
import itertools
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import build_executive_summary, build_security_roadmap
from test_verdict_names_broken_records import _zone

DOMAIN = "london-shape.test"
ROUTES = ("Direct Domain Spoofing", "Subdomain Spoofing", "Non-Existent Subdomain Spoofing")


def _checks(statuses, record="v=DMARC1; p=reject; rua=mailto:a@example.com"):
    return [
        {"name": "DMARC", "status": "warn", "configured": True, "record": record,
         "effective_policy": "reject",
         "tag_breakdown": {"health": {"status": "compatible"}, "config_warnings": []},
         "attack_surface": {"vectors": [{"name": n, "status": s}
                                        for n, s in zip(ROUTES, statuses)]}},
        {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
        {"name": "DKIM", "status": "pass", "configured": True},
    ]


def _verdict(checks):
    return build_executive_summary(checks, build_security_roadmap(checks))["verdict"]


@pytest.mark.parametrize("statuses", sorted(set(
    itertools.product(("protected", "partial", "exposed"), repeat=3))))
def test_block_most_only_when_every_other_route_is_protected(statuses):
    verdict = _verdict(_checks(statuses))
    others_protected = statuses.count("exposed") == 1 and statuses.count("protected") == 2
    if "block most" in verdict:
        assert others_protected, (statuses, verdict)
    if statuses.count("exposed") == 1 and "partial" in statuses:
        assert "weaker for" in verdict, (statuses, verdict)


def test_one_exposed_and_two_partial_routes_names_both():
    verdict = _verdict(_checks(("exposed", "partial", "partial")))
    assert verdict == ("Your settings do not ask receivers to block forged mail sent as "
                       "your exact domain, and the request is weaker for your subdomains "
                       "and made-up subdomains."), verdict


def test_quarantine_with_pct_zero_blocks_nothing(audit):
    result = audit(_zone(f"v=DMARC1;p=quarantine;rua=mailto:d@{DOMAIN};pct=0",
                         "v=spf1 mx -all", domain=DOMAIN), DOMAIN, dkim_selector="s1")
    verdict = result["executive_summary"]["verdict"]

    assert "pct=0" in verdict, verdict
    for claim in ("block most", "send forged mail to spam", "Receivers are asked to block"):
        assert claim not in verdict, verdict
