"""A negative answer for one record type must not hide another type.

seattle.gov and uct.ac.za delegate _dmarc to ns.vali.email. That server
answers a TXT query at _dmarc.<domain> with the DMARC record and a CNAME
query at the same name with NXDOMAIN. _raw_check_dmarc probes CNAME before
it reads TXT, both through the shared caching resolver, and dnspython caches
NXDOMAIN under (qname, ANY), so the cached NXDOMAIN answered the TXT lookup
too. The DMARC card read "no DMARC record" while the tree walk in the same
report found it. It happened about half the time because the tree walk runs
concurrently and sometimes cached the TXT answer first.

The rest of the suite patches Resolver.resolve, which bypasses the cache
entirely, so it could not see this. These tests patch one level lower, at
dns.query.udp, so the real Resolver and the real shared cache run.
"""
import os
import sys
from contextlib import contextmanager
from unittest.mock import patch

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import dns_tools
from conftest import FakeZone, fake_dns

DOMAIN = "delegated-dmarc.example"
DMARC_NAME = f"_dmarc.{DOMAIN}"
DMARC_RECORD = "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email"

# What the authoritative servers publish. Anything missing from a name that
# has some records is NODATA; a name with no records at all is NXDOMAIN.
RECORDS = {
    (DOMAIN, "MX"): ["10 mx.delegated-dmarc.example."],
    (DOMAIN, "TXT"): ['"v=spf1 -all"'],
    (f"mx.{DOMAIN}", "A"): ["192.0.2.25"],
    (DMARC_NAME, "TXT"): [f'"{DMARC_RECORD}"'],
    # The report destination authorizes the domain and receives mail, so the
    # card has no reason to fail other than the lookup under test.
    (f"{DOMAIN}._report._dmarc.vali.email", "TXT"): ['"v=DMARC1"'],
    ("vali.email", "MX"): ["10 mx.vali.email."],
    ("mx.vali.email", "A"): ["192.0.2.26"],
}

# The Valimail behaviour: NXDOMAIN for a type it does not serve at a name
# where it serves another type.
NXDOMAIN_FOR = {(DMARC_NAME, "CNAME")}


def _answer(request):
    question = request.question[0]
    name = question.name.to_text().rstrip(".").lower()
    rdtype = dns.rdatatype.to_text(question.rdtype)
    response = dns.message.make_response(request)
    response.flags |= dns.flags.RA
    values = RECORDS.get((name, rdtype))
    if (name, rdtype) in NXDOMAIN_FOR:
        response.set_rcode(dns.rcode.NXDOMAIN)
    elif values:
        response.answer.append(dns.rrset.from_text_list(
            question.name, 300, dns.rdataclass.IN, question.rdtype, values,
        ))
    elif not any(n == name for n, _ in RECORDS):
        response.set_rcode(dns.rcode.NXDOMAIN)
    # Through the wire and back, as a real answer arrives. It also rebuilds
    # the section index that appending to response.answer leaves stale.
    return dns.message.from_wire(response.to_wire())


@contextmanager
def wire_dns():
    """The real Resolver and the real cache, with the network replaced."""
    def _udp(q, where, *args, **kwargs):
        return _answer(q)

    dns_tools._PLAIN_CACHE.flush()
    # fake_dns blocks HTTP and every other egress; the inner patches put the
    # real Resolver.resolve back and serve the wire answers from RECORDS.
    real_resolve = dns.resolver.Resolver.resolve
    with fake_dns(FakeZone()), \
         patch("dns.resolver.Resolver.resolve", real_resolve), \
         patch("dns.query.udp", _udp), \
         patch("dns.query.tcp", _udp):
        try:
            yield
        finally:
            dns_tools._PLAIN_CACHE.flush()


def _txt(resolver, name):
    return [b"".join(r.strings).decode() for r in resolver.resolve(name, "TXT")]


@pytest.mark.parametrize("first", ["CNAME", "TXT"])
def test_txt_lookup_survives_a_cname_nxdomain_in_either_order(first):
    with wire_dns():
        resolver = dns_tools.get_resolver()
        if first == "TXT":
            assert _txt(resolver, DMARC_NAME) == [DMARC_RECORD]
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(DMARC_NAME, "CNAME")
        assert _txt(dns_tools.get_resolver(), DMARC_NAME) == [DMARC_RECORD], (
            "a cached NXDOMAIN for CNAME answered the TXT query"
        )


def test_raw_dmarc_check_finds_the_record_after_its_cname_probe():
    """_raw_check_dmarc on its own always probes CNAME first, so with the
    tree walk out of the way this is the losing order every time."""
    with wire_dns():
        raw = audit_engine._raw_check_dmarc(DOMAIN)
    assert raw.get("record") == DMARC_RECORD
    assert raw.get("policy") == "quarantine"


def test_dmarc_card_finds_the_record():
    with wire_dns():
        result = audit_engine.run_full_audit(DOMAIN, scope="dmarc")
    card = next(c for c in result["checks"] if c.get("name") == "DMARC")
    assert card["status"] == "pass", card
    assert DMARC_RECORD in repr(card)


def test_nodata_stays_cached_by_type():
    """NODATA is keyed by type in dnspython, so caching it hides nothing."""
    with wire_dns():
        resolver = dns_tools.get_resolver()
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(DOMAIN, "CAA")
        key = (dns.name.from_text(DOMAIN), dns.rdatatype.CAA, dns.rdataclass.IN)
        assert dns_tools._PLAIN_CACHE.get(key) is not None
        assert _txt(resolver, DOMAIN) == ["v=spf1 -all"]
