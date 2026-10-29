"""An mx mechanism whose target has more than 10 MX hosts is a PermError.

RFC 7208 section 4.6.4: evaluating an mx mechanism must not look up the
addresses of more than 10 MX hosts, and past that the mechanism returns
PermError. The counter resolved the MX query only to spot a void lookup, so
a record whose mx: target had 12 MX hosts was graded pass.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
from spf_execution_engine import _spf_permerror
import spf_recursive


def _zone(mx_hosts):
    return FakeZone({
        "example.com": {"TXT": ["v=spf1 mx:mail.example.net -all"]},
        "mail.example.net": {"MX": [(i, f"mx{i}.example.net") for i in range(mx_hosts)]},
    })


def test_more_than_ten_mx_hosts_is_a_permerror():
    with fake_dns(_zone(11)):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["status"] == "fail"
    assert result["mx_over_limit"] == [
        {"domain": "example.com", "term": "mx:mail.example.net"}]
    assert any("more than 10 MX hosts" in i["issue"] and i["severity"] == "error"
               for i in result["issues"])
    assert _spf_permerror({"spf_recursive": result})


def test_ten_mx_hosts_is_fine():
    with fake_dns(_zone(10)):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["mx_over_limit"] == []
    assert result["status"] == "pass"
