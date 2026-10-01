"""A same-provider SOA serial mismatch does not outrank email authentication.

google.com showed an SOA serial mismatch as its biggest risk. Serials are now
compared within each provider (tests/test_nameserver_serials_per_provider.py),
but two nameservers of one provider can still disagree for a moment while a
change propagates. That finding is amber and usually transient. Its plan row
was added ahead of the DMARC rows, so on a tie in priority it took the
biggest-risk slot. Within a tier it now sorts after every other row.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import build_executive_summary, build_security_roadmap
from test_nameserver_serials_per_provider import NS1, ROUTE53, _check
from test_verdict_names_broken_records import _zone

DOMAIN = "google-shape.test"


def _ns_card_with_same_provider_mismatch():
    hosts = {**ROUTE53, **NS1}
    serials = {ip: 1 for ip in ROUTE53.values()}
    serials.update({ip: 1717171717 for ip in NS1.values()})
    serials[NS1["dns4.p08.nsone.net"]] = 1717171600
    _, card = _check(hosts, serials)
    assert card["status"] == "warn"
    return card


def _dmarc_card_with_a_medium_row(audit):
    # pct is a retired tag: a medium "Remove the tag" row on a passing record.
    result = audit(_zone(f"v=DMARC1; p=reject; pct=100; rua=mailto:d@{DOMAIN}",
                         "v=spf1 mx -all", domain=DOMAIN), DOMAIN, dkim_selector="s1")
    return {c["name"]: c for c in result["checks"]}["DMARC"]


def test_dmarc_row_outranks_a_serial_mismatch_of_the_same_priority(audit):
    ns = _ns_card_with_same_provider_mismatch()
    dmarc = _dmarc_card_with_a_medium_row(audit)
    # Nameservers listed first, the order the audit produces the cards in
    # does not matter to the plan.
    checks = [ns, dmarc]
    roadmap = build_security_roadmap(checks)
    items = roadmap["items"]

    ns_row = next(i for i in items if i["protocol"] == "Nameservers")
    dmarc_rows = [i for i in items if i["protocol"] == "DMARC" and i["priority"] == ns_row["priority"]]
    assert dmarc_rows, [(i["priority"], i["protocol"]) for i in items]
    assert items.index(dmarc_rows[-1]) < items.index(ns_row)

    es = build_executive_summary(checks, roadmap)
    assert "SOA" not in es["biggest_risk"] and "serial" not in es["biggest_risk"].lower(), es["biggest_risk"]
    assert es["biggest_risk"] == dmarc_rows[0]["action"]


def test_alone_the_serial_mismatch_is_still_reported():
    ns = _ns_card_with_same_provider_mismatch()
    roadmap = build_security_roadmap([ns])
    assert [i["protocol"] for i in roadmap["items"]] == ["Nameservers"]
