"""SOA serials are compared within a DNS provider, not across providers.

github.com is served by Amazon Route 53 and NS1, linkedin.com by Azure DNS
and NS1. Each provider keeps its own SOA serial for the zone, so the serials
differ by design. The Nameservers card graded that a warning, "SOA serial
mismatch ... zone sync issue", and the plan told the operator to check AXFR
and IXFR configuration that does not exist. Two nameservers of the same
provider that disagree are still a finding.

The SOA probe goes straight to each nameserver with dns.query.udp, so the
test answers it per address with a real dnspython response.
"""
import os
import sys
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rrset

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import audit_engine
from result_transformer import build_security_roadmap, transform_nameservers

DOMAIN = "github.test"

# Shaped like github.com's real delegation: four Route 53 hosts and four NS1
# hosts, the two providers on different serials.
ROUTE53 = {
    "ns-1283.awsdns-32.org": "205.251.197.3",
    "ns-1707.awsdns-21.co.uk": "205.251.198.171",
    "ns-421.awsdns-52.com": "205.251.193.165",
    "ns-520.awsdns-01.net": "205.251.194.8",
}
NS1 = {
    "dns1.p08.nsone.net": "198.51.44.8",
    "dns2.p08.nsone.net": "198.51.45.8",
    "dns3.p08.nsone.net": "198.51.44.72",
    "dns4.p08.nsone.net": "198.51.45.72",
}


def _zone(hosts):
    records = {DOMAIN: {"NS": list(hosts)}}
    for host, ip in hosts.items():
        records[host] = {"A": [ip], "AAAA": ["2600:9000:5300::1"]}
    return FakeZone(records)


def _udp(serial_by_ip):
    def _answer(query, where, *args, **kwargs):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(
            DOMAIN + ".", 900, "IN", "SOA",
            f"ns1.{DOMAIN}. hostmaster.{DOMAIN}. {serial_by_ip[where]} 7200 900 1209600 86400",
        ))
        return response
    return _answer


def _check(hosts, serial_by_ip):
    with fake_dns(_zone(hosts)), patch("dns.query.udp", _udp(serial_by_ip)):
        raw = audit_engine._raw_check_nameservers(DOMAIN)
    card = transform_nameservers(raw, DOMAIN)
    return raw, card


def _mismatch(raw):
    return [i for i in raw["issues"] if i["issue"].startswith("SOA serial mismatch")]


def test_two_providers_on_their_own_serials_is_not_a_finding():
    hosts = {**ROUTE53, **NS1}
    serials = {ip: 1 for ip in ROUTE53.values()}
    serials.update({ip: 1717171717 for ip in NS1.values()})

    raw, card = _check(hosts, serials)

    assert sorted(raw["providers"]) == ["Amazon Route 53", "NS1 (IBM)"]
    assert _mismatch(raw) == []
    assert card["status"] == "pass", card
    assert not any("mismatch" in d["text"].lower() for d in card["details"])
    actions = [i["action"] for i in build_security_roadmap([card])["items"]]
    assert not any("zone transfer" in a.lower() for a in actions), actions


def test_disagreement_inside_one_provider_is_still_a_finding():
    hosts = {**ROUTE53, **NS1}
    serials = {ip: 1 for ip in ROUTE53.values()}
    serials.update({ip: 1717171717 for ip in NS1.values()})
    serials[NS1["dns4.p08.nsone.net"]] = 1717171600

    raw, card = _check(hosts, serials)

    found = _mismatch(raw)
    assert len(found) == 1
    # Only the provider that disagrees with itself is named.
    assert "nsone.net" in found[0]["plain_english"]
    assert "awsdns" not in found[0]["plain_english"]
    assert raw["soa_serials_consistent"] is False
    assert card["status"] == "warn"


def test_unrecognised_hosts_group_by_their_registrable_domain():
    hosts = {
        "ns1.example-dns.net": "192.0.32.10",
        "ns2.example-dns.net": "192.0.32.11",
        "a.other-dns.net": "192.0.33.10",
    }
    agree = {"192.0.32.10": 5, "192.0.32.11": 5, "192.0.33.10": 9}
    raw, _ = _check(hosts, agree)
    assert _mismatch(raw) == []

    disagree = dict(agree, **{"192.0.32.11": 4})
    raw, _ = _check(hosts, disagree)
    assert len(_mismatch(raw)) == 1
