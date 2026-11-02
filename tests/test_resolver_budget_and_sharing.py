"""Resolver budget across nameservers (issue 276) and one resolver per
configuration instead of one per query (issue 279)."""
import os
import sys
import threading
import time

import dns.exception
import dns.message
import dns.nameserver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns_tools  # noqa: E402

DEAD, SLOW, GOOD = "192.0.2.1", "192.0.2.2", "192.0.2.3"


@pytest.fixture
def three_servers(monkeypatch):
    monkeypatch.setattr(dns_tools, "AUDIT_UPSTREAMS", [DEAD, SLOW, GOOD])
    asked = []

    def query(self, request, timeout, source, source_port, max_size, one_rr_per_rrset=False,
              ignore_trailing=False):
        asked.append((self.address, timeout))
        if self.address != GOOD:
            time.sleep(timeout)  # a server that never answers
            raise dns.exception.Timeout
        response = dns.message.make_response(request)
        # find_rrset keeps the message's index in step; a bare answer.append
        # leaves resolve_chaining unable to find the rrset.
        rrset = response.find_rrset(response.answer, request.question[0].name,
                                    dns.rdataclass.IN, dns.rdatatype.TXT, create=True)
        rrset.add(dns.rdata.from_text("IN", "TXT", '"ok"'), 60)
        return response

    monkeypatch.setattr(dns.nameserver.Do53Nameserver, "query", query)
    return asked


def test_a_first_server_that_never_answers_does_not_use_the_whole_lifetime(three_servers):
    resolver = dns_tools.get_uncached_resolver(3, lifetime=3)
    started = time.monotonic()
    answer = resolver.resolve("probe.example.", "TXT")
    took = time.monotonic() - started
    assert answer.rrset is not None
    assert [a for a, _ in three_servers] == [DEAD, SLOW, GOOD]
    assert all(t <= 1.0 + 0.01 for _, t in three_servers[:2])
    assert took < 3


def test_default_lifetime_gives_every_server_an_attempt(monkeypatch, three_servers):
    resolver = dns_tools.get_resolver(3.0)  # lifetime 6, about two seconds each
    assert resolver.lifetime == 6.0
    assert resolver.timeout == pytest.approx(2.0)


def test_dnssec_resolver_splits_over_its_four_servers():
    resolver = dns_tools.get_dnssec_resolver(8.0)
    assert resolver.lifetime == 16.0
    assert resolver.timeout == 4.0


def test_health_probe_and_preflight_keep_the_three_second_cap():
    import server
    probe = dns_tools.get_uncached_resolver(3, lifetime=3)
    assert probe.lifetime == 3
    assert probe.timeout == min(3, 3 / len(probe.nameservers))
    assert server._preflight_resolver.lifetime == 3


def test_two_get_resolver_calls_share_one_object():
    assert dns_tools.get_resolver(5.0) is dns_tools.get_resolver(5.0)
    assert dns_tools.get_resolver(5.0) is not dns_tools.get_resolver(4.0)
    assert dns_tools.get_uncached_resolver(3) is dns_tools.get_uncached_resolver(3)
    assert dns_tools.get_dnssec_resolver() is dns_tools.get_dnssec_resolver()
    assert dns_tools.get_resolver(5.0).cache is dns_tools._PLAIN_CACHE
    assert dns_tools.get_uncached_resolver(3).cache is None
    assert dns_tools.get_dnssec_resolver().cache is dns_tools._DNSSEC_CACHE


def test_a_new_upstream_list_gets_a_new_resolver(monkeypatch):
    before = dns_tools.get_resolver(5.0)
    monkeypatch.setattr(dns_tools, "AUDIT_UPSTREAMS", ["198.51.100.9"])
    after = dns_tools.get_resolver(5.0)
    assert after is not before
    assert after.nameservers == ["198.51.100.9"]


def test_threads_building_the_same_resolver_get_one(monkeypatch):
    monkeypatch.setattr(dns_tools, "_shared_resolvers", {})
    seen = []
    barrier = threading.Barrier(8)

    def work():
        barrier.wait()
        seen.append(dns_tools.get_resolver(7.0))

    threads = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len({id(r) for r in seen}) == 1


def test_resolve_still_honours_a_per_call_lifetime(three_servers):
    resolver = dns_tools.get_resolver(5.0)
    # Every server hangs for the share; the call-level lifetime stops it sooner.
    dead_only = dns_tools.get_resolver(5.0)
    assert dead_only is resolver
    started = time.monotonic()
    with pytest.raises(dns.exception.Timeout):
        # Fresh name so no cached answer; SLOW/DEAD come first in the list.
        resolver.resolve("lifetime-test.example.", "TXT", lifetime=0.5)
    assert time.monotonic() - started < 2.5
    assert resolver.lifetime == 10.0  # the shared instance was not changed
