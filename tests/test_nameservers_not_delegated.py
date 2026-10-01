"""A name that is not delegated is not told to add NS records at a registrar.

gouv.fr is an empty non-terminal inside .fr: its NS query returns no answer
and it has no SOA of its own. The Nameservers card failed it with "No
nameservers found" and a high plan row, "Configure NS records with your
domain registrar.", because _is_subdomain decided by label count and gouv.fr
has two labels. Whether a name needs its own NS records depends on whether
it is a zone apex, which the nameserver check now asks (its own SOA), with
the public suffix list as the fallback when that answer is missing.
"""
import os
import sys

import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeAnswer, FakeZone, fake_dns
import audit_engine
from result_transformer import build_security_roadmap, transform_nameservers

REGISTRAR = "Configure NS records with your domain registrar."


def _nameservers(zone, domain):
    with fake_dns(zone):
        raw = audit_engine._raw_check_nameservers(domain)
    return raw, transform_nameservers(raw, domain)


def _plan_actions(card):
    return [i["action"] for i in build_security_roadmap([card])["items"]]


def test_empty_non_terminal_under_a_tld_gets_the_inherited_card():
    zone = FakeZone({"gouv.fr": {}, "fr": {"NS": ["d.nic.fr"]}})
    zone.fail("gouv.fr", "NS", dns.resolver.NoAnswer())
    zone.fail("gouv.fr", "SOA", dns.resolver.NoAnswer())

    raw, card = _nameservers(zone, "gouv.fr")

    assert raw["zone_apex"] is False
    assert raw["issues"] == []
    assert card["status"] == "pass"
    assert card["pill_label"] == "Inherited"
    assert card["fix"] is None
    assert REGISTRAR not in _plan_actions(card)


class _ApexZone(FakeZone):
    """FakeZone has no SOA rdata, and this case needs one to come back."""

    def resolve(self, name, rdtype="A", *args, **kwargs):
        if str(rdtype).upper() == "SOA" and str(name).rstrip(".").lower() == "broken.example":
            return FakeAnswer([object()])
        return super().resolve(name, rdtype, *args, **kwargs)


def test_a_zone_apex_with_no_ns_records_is_still_a_failure():
    zone = _ApexZone({})
    zone.fail("broken.example", "NS", dns.resolver.NoAnswer())

    raw, card = _nameservers(zone, "broken.example")

    assert raw["zone_apex"] is True
    assert card["status"] == "fail"
    assert card["fix"] == REGISTRAR


def test_without_the_soa_answer_the_public_suffix_list_decides():
    """Transformer fallback: no zone_apex in the raw result (the NXDOMAIN
    path, or a unit caller). Label count is not the rule."""
    raw = {"ns_count": 0, "issues": [], "status": "error"}

    assert transform_nameservers(raw, "gouv.fr")["pill_label"] == "Inherited"
    assert transform_nameservers(raw, "mail.example.com")["pill_label"] == "Inherited"

    registered = transform_nameservers(raw, "example.co.uk")
    assert registered["status"] == "fail"
    assert registered["fix"] == REGISTRAR
    assert transform_nameservers(raw, "example.com")["status"] == "fail"


def test_an_unrecognized_suffix_is_not_called_a_subdomain():
    """No PSL answer for broken.example is no evidence of a parent zone; a
    listed public suffix such as gouv.fr is still not its own zone."""
    from result_transformer import _is_subdomain
    assert _is_subdomain("broken.example") is False
    assert _is_subdomain("gouv.fr") is True
    assert _is_subdomain("example.co.uk") is False
