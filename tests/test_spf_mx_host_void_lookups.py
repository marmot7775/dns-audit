"""An MX host with no address is a void lookup.

An mx mechanism makes a receiver resolve every MX host's address (RFC 7208
section 5.4), and each empty answer counts toward the limit of two void
lookups (section 4.6.4). The counter resolved only the MX query, so a record
whose mx terms named three dead hosts passed while enforcing receivers
return PermError.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import spf_recursive


def _zone(**hosts):
    records = {
        "example.com": {"TXT": ["v=spf1 mx -all"],
                        "MX": [(i, h) for i, h in enumerate(hosts)]},
    }
    for name, addr in hosts.items():
        if addr:
            records[name] = {"A": [addr]} if "." in addr else {"AAAA": [addr]}
    return FakeZone(records)


def test_three_dead_mx_hosts_pass_the_void_limit():
    zone = _zone(**{"mx1.example.com": None, "mx2.example.com": None,
                    "mx3.example.com": None})
    with fake_dns(zone):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["void_lookups"] == 3
    notes = [i for i in result["issues"] if i["issue"].startswith("MX host with no address")]
    assert notes and "mx1.example.com" in notes[0]["issue"]


def test_live_hosts_are_not_void():
    zone = _zone(**{"mx1.example.com": "192.0.2.1", "mx2.example.com": "2001:db8::1"})
    with fake_dns(zone):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["void_lookups"] == 0
    assert not any(i["issue"].startswith("MX host") for i in result["issues"])


def test_void_mx_hosts_fail_the_card_past_two():
    import audit_engine
    zone = _zone(**{"mx1.example.com": None, "mx2.example.com": None,
                    "mx3.example.com": None})
    with fake_dns(zone):
        raw = audit_engine._raw_check_spf("example.com")
    assert raw["void_lookup_count"] == 3
    assert raw["status"] == "error"
