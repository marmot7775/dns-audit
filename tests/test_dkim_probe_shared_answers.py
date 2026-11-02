"""The audit's DKIM probe and Sendermap's selector probe share their answers
(issue 280).

The two probes ask overlapping selector lists, so a complete audit sent about
118 queries twice. resolve_probe remembers a definitive answer for a few
seconds, whichever probe asks first. The DKIM card does not change; a name
nobody could answer is asked again and stays "probe incomplete".
"""
import json
import os
import sys
import types

import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns_tools  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402
from test_spf_suggestion_vendor_footprints import DKIM_KEY  # noqa: E402


class _Counting:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = 0

    def resolve(self, qname, rdtype="TXT", raise_on_no_answer=True, **kw):
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        if self.outcome.rrset is None:  # no TXT at the name: dnspython raises
            raise dns.resolver.NoAnswer(response=self.outcome.response)
        return self.outcome


class _Answer:
    def __init__(self, rrset):
        self.rrset = rrset
        self.response = types.SimpleNamespace(question=[])


def test_a_definitive_answer_is_asked_once():
    for outcome in (_Answer(["key"]), dns.resolver.NXDOMAIN(), _Answer(None)):
        dns_tools.clear_probe_memo()
        resolver = _Counting(outcome)
        for _ in range(3):
            try:
                dns_tools.resolve_probe(resolver, "s1._domainkey.x.test", "TXT")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
        assert resolver.calls == 1, outcome


def test_no_answer_is_raised_or_returned_as_the_caller_asked():
    resolver = _Counting(_Answer(None))
    with pytest.raises(dns.resolver.NoAnswer):
        dns_tools.resolve_probe(resolver, "s1._domainkey.x.test")
    assert dns_tools.resolve_probe(resolver, "s1._domainkey.x.test",
                                   raise_on_no_answer=False).rrset is None


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_a_failure_is_raised_and_never_remembered(failure):
    resolver = _Counting(failure)
    for _ in range(2):
        with pytest.raises(type(failure)):
            dns_tools.resolve_probe(resolver, "s1._domainkey.x.test")
    assert resolver.calls == 2


def test_an_answer_expires(monkeypatch):
    resolver = _Counting(dns.resolver.NXDOMAIN())
    monkeypatch.setattr(dns_tools, "PROBE_MEMO_TTL", 0.0)
    for _ in range(2):
        with pytest.raises(dns.resolver.NXDOMAIN):
            dns_tools.resolve_probe(resolver, "s1._domainkey.x.test")
    assert resolver.calls == 2


def test_the_memo_is_bounded(monkeypatch):
    monkeypatch.setattr(dns_tools, "PROBE_MEMO_MAX", 10)
    resolver = _Counting(dns.resolver.NXDOMAIN())
    for i in range(50):
        with pytest.raises(dns.resolver.NXDOMAIN):
            dns_tools.resolve_probe(resolver, f"s{i}._domainkey.x.test")
    assert len(dns_tools._probe_memo) == 10


DOMAIN = "golden.test"


def _zone():
    return FakeZone({
        DOMAIN: {"MX": [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")],
                 "TXT": ["v=spf1 include:_spf.google.com -all"], "A": ["203.0.113.1"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        "_spf.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"]},
        f"google._domainkey.{DOMAIN}": {"TXT": [DKIM_KEY]},
    })


def _run(monkeypatch, ttl):
    from audit_engine import run_full_audit
    monkeypatch.setattr(dns_tools, "PROBE_MEMO_TTL", ttl)
    dns_tools.clear_probe_memo()
    zone = _zone()
    with fake_dns(zone):
        result = run_full_audit(DOMAIN, scope="complete")
    probes = [q for q in zone.queries if "_domainkey" in str(q[0])]
    return result, probes


def test_the_dkim_card_is_unchanged_and_the_probe_asks_less(monkeypatch):
    before, queries_before = _run(monkeypatch, 0.0)
    after, queries_after = _run(monkeypatch, 20.0)

    def card(r):
        return json.dumps(next(c for c in r["checks"] if c["name"] == "DKIM"), sort_keys=True, default=str)

    assert card(after) == card(before)
    assert [v["name"] for v in after["vendors"]] == [v["name"] for v in before["vendors"]]
    # Printed so the PR can quote the two numbers.
    print(f"selector queries on the golden zone: {len(queries_before)} -> {len(queries_after)}")
    assert len(queries_after) < len(queries_before)
