"""The CAA check asks for each name's CAA records once.

parkviewdental.com's nameservers drop CAA queries. The check resolved CAA,
timed out after the resolver's 10 second lifetime, then called _lookup_ttl
for the TTL, which sent the same query to the same silent nameservers for
another 10 seconds. That pushed CAA past the 20 second Phase 2 budget and
the audit to 30 seconds. The TTL now comes off the answer already held.
"""
import dns.exception

import audit_engine
from conftest import FakeZone

DOMAIN = "slow-caa.example"


def _caa_queries(zone):
    return [q for q in zone.queries if q == (DOMAIN, "CAA")]


def test_failed_caa_lookup_is_not_repeated(audit_zone):
    zone = FakeZone({DOMAIN: {"A": ["192.0.2.1"]}})
    zone.fail(DOMAIN, "CAA", dns.exception.Timeout())
    result = audit_zone(zone, lambda: audit_engine._raw_check_caa(DOMAIN))

    assert result["lookup_failed"] is True
    assert result["ttl"] is None
    assert len(_caa_queries(zone)) == 1, zone.queries


def test_found_caa_ttl_comes_from_the_answer(audit_zone):
    zone = FakeZone({DOMAIN: {"CAA": [(0, "issue", "letsencrypt.org")]}}, ttl=1800)
    result = audit_zone(zone, lambda: audit_engine._raw_check_caa(DOMAIN))

    assert result["ttl"] == 1800
    assert len(_caa_queries(zone)) == 1, zone.queries
