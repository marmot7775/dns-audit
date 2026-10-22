"""Sendermap on the audit's resolver answers exactly as Sendermap's own would.

sendermap_adapter.AuditResolver stands in for sendermap.dns.SystemResolver
inside an audit. If the two rendered one DNS response differently, the map
built during an audit would differ from the map Sendermap builds alone, and
step 2 would ship a sender list nobody can reproduce with the CLI. So every
dnspython outcome is fed to both and the Answers compared: NXDOMAIN with the
CNAMEs that led there, no record of the type, SERVFAIL from the domain's own
servers, a timeout, a CNAME chain in order, and a TXT record split into
several strings.

Offline: each response is a dnspython message built here, handed to the
adapter through a stub dns_tools.get_resolver and to SystemResolver through
a stub async resolver.
"""
import asyncio
import logging
import os
import subprocess
import sys
import time

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from sendermap.dns import Answer, Status, SystemResolver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import sendermap_adapter  # noqa: E402
from sendermap_adapter import AuditResolver, map_senders  # noqa: E402


def _response(qname, rtype, answer_lines):
    """A dnspython response to `qname rtype` carrying `answer_lines` (zone file syntax)."""
    query = dns.message.make_query(qname, rtype)
    response = dns.message.make_response(query)
    for line in answer_lines:
        owner, ttl, rdclass, rdtype, *rest = line.split(None, 4)
        rrset = response.find_rrset(
            response.answer, dns.name.from_text(owner), dns.rdataclass.from_text(rdclass),
            dns.rdatatype.from_text(rdtype), create=True,
        )
        rrset.add(dns.rdata.from_text(rdclass, rdtype, rest[0]), int(ttl))
    return response


def _answer(qname, rtype, answer_lines):
    """What resolve(..., raise_on_no_answer=False) returns for that response."""
    response = _response(qname, rtype, answer_lines)
    return dns.resolver.Answer(
        dns.name.from_text(qname), dns.rdatatype.from_text(rtype), dns.rdataclass.IN,
        response,
    )


def _nxdomain(qname, answer_lines=()):
    response = _response(qname, "TXT", answer_lines)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return dns.resolver.NXDOMAIN(qnames=[dns.name.from_text(qname)],
                                 responses={dns.name.from_text(qname): response})


class _Stub:
    """Plays dns_tools.get_resolver()'s resolver: returns or raises one outcome."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.asked = []

    def resolve(self, name, rtype, raise_on_no_answer=True):
        self.asked.append((name, rtype, raise_on_no_answer))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _AsyncStub(_Stub):
    async def resolve(self, name, rtype, raise_on_no_answer=True):
        return _Stub.resolve(self, name, rtype, raise_on_no_answer)


def _both(monkeypatch, outcome, name, rtype):
    """(adapter's Answer, SystemResolver's Answer) for the same outcome."""
    stub = _Stub(outcome)
    monkeypatch.setattr(sendermap_adapter.dns_tools, "get_resolver", lambda timeout=5.0: stub)
    ours = asyncio.run(AuditResolver().query(name, rtype))
    system = SystemResolver()
    system._resolver = _AsyncStub(outcome)
    theirs = asyncio.run(system.query(name, rtype))
    return ours, theirs, stub


OUTCOMES = {
    "txt split into strings": (
        _answer("example.test.", "TXT",
                ['example.test. 300 IN TXT "v=spf1 include:_spf.google.com " "include:sendgrid.net ~all"']),
        "example.test", "TXT",
        Answer("example.test", "TXT", Status.OK,
               ("v=spf1 include:_spf.google.com include:sendgrid.net ~all",)),
    ),
    "mx as preference host": (
        _answer("example.test.", "MX",
                ["example.test. 300 IN MX 10 ASPMX.L.Google.com.",
                 "example.test. 300 IN MX 5 alt1.aspmx.l.google.com."]),
        "Example.Test.", "MX",
        Answer("example.test", "MX", Status.OK,
               ("5 alt1.aspmx.l.google.com", "10 aspmx.l.google.com")),
    ),
    "cname chain in order": (
        _answer("em.example.test.", "TXT",
                ["em.example.test. 300 IN CNAME u1.wl.sendgrid.net.",
                 "u1.wl.sendgrid.net. 300 IN CNAME sendgrid.net.",
                 'sendgrid.net. 300 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"']),
        "em.example.test", "TXT",
        Answer("em.example.test", "TXT", Status.OK, ("v=spf1 ip4:192.0.2.0/24 -all",),
               ("u1.wl.sendgrid.net", "sendgrid.net")),
    ),
    "no record of this type": (
        _answer("example.test.", "TXT", []),
        "example.test", "TXT",
        Answer("example.test", "TXT", Status.NOANSWER),
    ),
    "nxdomain": (
        _nxdomain("nope.example.test."),
        "nope.example.test", "TXT",
        Answer("nope.example.test", "TXT", Status.NXDOMAIN),
    ),
    "nxdomain behind a cname": (
        _nxdomain("k1._domainkey.example.test.",
                  ["k1._domainkey.example.test. 300 IN CNAME dkim.gone.test."]),
        "k1._domainkey.example.test", "TXT",
        Answer("k1._domainkey.example.test", "TXT", Status.NXDOMAIN,
               chain=("dkim.gone.test",)),
    ),
    "servfail from the domain's servers": (
        dns.resolver.NoNameservers(),
        "example.test", "TXT",
        Answer("example.test", "TXT", Status.FAILED, servfail=True),
    ),
    "timeout": (
        dns.resolver.LifetimeTimeout(timeout=4.0, errors=[]),
        "example.test", "TXT",
        Answer("example.test", "TXT", Status.FAILED),
    ),
    "network error": (
        dns.exception.DNSException("network unreachable"),
        "example.test", "TXT",
        Answer("example.test", "TXT", Status.FAILED),
    ),
}


@pytest.mark.parametrize("case", OUTCOMES)
def test_each_dnspython_outcome_maps_to_the_answer_sendermap_gives(monkeypatch, case):
    outcome, name, rtype, expected = OUTCOMES[case]
    ours, theirs, _ = _both(monkeypatch, outcome, name, rtype)
    assert ours == expected
    assert ours == theirs


def test_the_adapter_asks_the_audit_resolver_without_raising_on_no_answer(monkeypatch):
    _, _, stub = _both(monkeypatch, _answer("example.test.", "TXT", []), "Example.Test.", "TXT")
    assert stub.asked == [("example.test", "TXT", False)]


def test_the_resolver_names_itself_system():
    assert AuditResolver().name == "system"


def test_map_senders_returns_none_past_its_budget_and_logs_it(monkeypatch, caplog):
    async def slow_map(*args, **kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(sendermap_adapter, "map_domain", slow_map)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="sendermap_adapter"):
        assert map_senders("example.test", 0.05) is None
    assert time.monotonic() - started < 2
    assert "Sender map for example.test exceeded its 0.05s budget" in caplog.text


def test_map_senders_asks_dns_only(monkeypatch):
    seen = {}

    async def fake_map(domain, **kwargs):
        seen.update(kwargs, domain=domain)
        return "map"

    monkeypatch.setattr(sendermap_adapter, "map_domain", fake_map)
    assert map_senders("example.test", 5) == "map"
    assert (seen["use_web"], seen["use_subdomains"], seen["use_ct"]) == (False, False, False)
    assert isinstance(seen["resolver"], AuditResolver)
    assert seen["checked_at"].tzinfo is not None


def test_the_audit_does_not_import_sendermap_yet():
    """Step 1 is a shadow run: loading the app loads neither the adapter nor
    the package, so the audit and its tests run exactly as before."""
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys, audit_engine, result_transformer; "
         "print('sendermap_adapter' in sys.modules, 'sendermap' in sys.modules)"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    assert out == ["False", "False"]
