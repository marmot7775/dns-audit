"""Doc 69: the PDF endpoint reported on domains that do not exist.

`GET /api/audit/<nxdomain>/pdf` returned 200 and an 81 KB, 13-page report.
Its summary read "Your domain has no DMARC record", its biggest risk was
"Publish a DMARC record", and its plan told the reader to publish records at
_dmarc.<nxdomain>. None of it was measured: the domain answers nothing, and
the engine reads that as publishing nothing.

`_preflight_dns_check` already existed and already caught this. Two of the
three entry points called it; the PDF route did not. These tests pin the
guard onto the route and pin the count of entry points, so a fourth one
cannot be added without a preflight in front of it.

The resolver is patched throughout, so nothing here depends on a live
NXDOMAIN or on the network.
"""
import os
import re
import sys

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import server as server_module  # noqa: E402

client = TestClient(server_module.app)

NX = "nonexistent-xyz-9271.com"
REAL = "example-resolves.test"

NOT_FOUND_MSG = "This domain does not exist in DNS. Verify the spelling and try again."


@pytest.fixture(autouse=True)
def clean_state():
    """Each test starts with an empty cache, rate limiter and slot budget."""
    server_module._rate_limits.clear()
    server_module._cache.clear()
    server_module._inflight.clear()
    with server_module._active_audits_lock:
        server_module._active_audits = 0
    yield
    server_module._rate_limits.clear()
    server_module._cache.clear()
    server_module._inflight.clear()
    with server_module._active_audits_lock:
        server_module._active_audits = 0


@pytest.fixture
def no_pdf(monkeypatch):
    """Records whether the renderer was reached. It must not be."""
    calls = []

    def _boom(data):
        calls.append(data)
        raise AssertionError("generate_pdf was called for a domain that is not in DNS")

    monkeypatch.setattr(server_module, "generate_pdf", _boom)
    return calls


@pytest.fixture
def no_audit(monkeypatch):
    """The engine must not be reached either: the guard sits in front of it."""
    calls = []

    def _boom(*args, **kwargs):
        calls.append(args)
        raise AssertionError("run_full_audit was called for a domain that is not in DNS")

    monkeypatch.setattr(server_module, "run_full_audit", _boom)
    return calls


def _resolver_raises(monkeypatch, exc):
    def _resolve(self, *args, **kwargs):
        raise exc

    monkeypatch.setattr(server_module._preflight_resolver.__class__, "resolve",
                        _resolve, raising=False)


# ---------------------------------------------------------------
# The three refusal branches
# ---------------------------------------------------------------

# (exception, the error key the preflight returns, a phrase from its message)
BRANCHES = [
    (dns.resolver.NXDOMAIN(), "domain_not_found", "does not exist in DNS"),
    (dns.resolver.NoNameservers(), "dns_broken", "SERVFAIL or REFUSED"),
    (dns.exception.Timeout(), "timeout", "timed out"),
]
# A domain that does not exist is a bad request; a DNS failure is the
# service's to retry, so it is 503.
STATUS = {"domain_not_found": 400, "dns_broken": 503, "timeout": 503}


@pytest.mark.parametrize("exc,error_key,phrase", BRANCHES,
                         ids=[b[1] for b in BRANCHES])
def test_the_pdf_route_refuses_and_renders_nothing(monkeypatch, no_pdf, no_audit,
                                                   exc, error_key, phrase):
    _resolver_raises(monkeypatch, exc)

    r = client.get(f"/api/audit/{NX}/pdf")

    assert r.status_code == STATUS[error_key], r.text
    assert r.headers["content-type"].startswith("text/plain")
    assert phrase in r.text
    assert no_pdf == [] and no_audit == []


def test_the_nxdomain_body_is_the_message_the_json_route_gives(monkeypatch, no_pdf, no_audit):
    """The two entry points say the same sentence to the reader."""
    _resolver_raises(monkeypatch, dns.resolver.NXDOMAIN())

    pdf = client.get(f"/api/audit/{NX}/pdf")
    js = client.get("/api/audit", params={"domain": NX, "scope": "dmarc"})

    assert pdf.text == NOT_FOUND_MSG
    assert js.json()["error"] == "domain_not_found"
    assert js.json()["error_message"] == NOT_FOUND_MSG
    assert pdf.text == js.json()["error_message"]


def test_no_pdf_bytes_come_back(monkeypatch, no_audit):
    """The renderer is left in place here, so this catches a real PDF body."""
    _resolver_raises(monkeypatch, dns.resolver.NXDOMAIN())

    r = client.get(f"/api/audit/{NX}/pdf")

    assert not r.content.startswith(b"%PDF")
    assert len(r.content) < 500


# ---------------------------------------------------------------
# It leaves no trace
# ---------------------------------------------------------------

@pytest.mark.parametrize("exc", [b[0] for b in BRANCHES], ids=[b[1] for b in BRANCHES])
def test_a_refused_domain_never_lands_in_the_audit_cache(monkeypatch, no_pdf, no_audit, exc):
    _resolver_raises(monkeypatch, exc)

    client.get(f"/api/audit/{NX}/pdf")

    assert server_module._cache == {}, server_module._cache
    assert server_module._get_cached(f"{NX}::complete") is None


def test_a_refused_domain_never_joins_or_leads_an_in_flight_audit(monkeypatch, no_pdf, no_audit):
    """The guard sits before _join_or_lead, so the registry stays empty."""
    _resolver_raises(monkeypatch, dns.resolver.NXDOMAIN())

    client.get(f"/api/audit/{NX}/pdf")

    assert server_module._inflight == {}, server_module._inflight


@pytest.mark.parametrize("exc,error_key", [b[:2] for b in BRANCHES], ids=[b[1] for b in BRANCHES])
def test_the_concurrency_slot_is_released_on_the_refusal_path(monkeypatch, no_pdf, no_audit,
                                                              exc, error_key):
    """The guard is inside the reservation, so its finally has to run."""
    _resolver_raises(monkeypatch, exc)

    for _ in range(server_module._MAX_CONCURRENT_AUDITS + 2):
        server_module._rate_limits.clear()
        assert client.get(f"/api/audit/{NX}/pdf").status_code == STATUS[error_key]

    assert server_module._active_audits == 0


@pytest.mark.parametrize("exc", [b[0] for b in BRANCHES[1:]], ids=[b[1] for b in BRANCHES[1:]])
def test_a_cached_result_is_served_when_the_preflight_would_fail(monkeypatch, no_audit, exc):
    """A good cached audit is not refused because a fresh SOA query failed."""
    _resolver_raises(monkeypatch, exc)
    monkeypatch.setattr(server_module, "generate_pdf", lambda data: b"%PDF-cached")
    server_module._set_cached(f"{NX}::complete", {"domain": NX, "checks": []})

    r = client.get(f"/api/audit/{NX}/pdf")

    assert r.status_code == 200, r.text
    assert r.content == b"%PDF-cached"
    assert no_audit == []


# ---------------------------------------------------------------
# The normal path still works
# ---------------------------------------------------------------

def test_a_domain_that_resolves_still_gets_its_pdf(monkeypatch):
    """The guard must not break the path it was added in front of."""
    def _resolve(self, *args, **kwargs):
        return object()  # any answer at all means "proceed"

    monkeypatch.setattr(server_module._preflight_resolver.__class__, "resolve",
                        _resolve, raising=False)
    monkeypatch.setattr(server_module, "run_full_audit",
                        lambda *a, **kw: {"domain": REAL, "checks": [], "timestamp": "t"})
    monkeypatch.setattr(server_module, "generate_pdf", lambda data: b"%PDF-1.4 stub")

    r = client.get(f"/api/audit/{REAL}/pdf")

    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert len(r.content) > 0
    assert r.content.startswith(b"%PDF")


def test_an_ambiguous_dns_error_still_lets_the_audit_try():
    """The preflight only refuses on the three decisive outcomes."""
    class _Odd(dns.exception.DNSException):
        pass

    assert server_module._preflight_dns_check.__doc__
    # Exercised directly: a generic DNSException is the "let it through" case.
    import unittest.mock as mock
    with mock.patch.object(server_module._preflight_resolver, "resolve", side_effect=_Odd()):
        assert server_module._preflight_dns_check(NX) is None


# ---------------------------------------------------------------
# Every entry point is guarded, and there are only three
# ---------------------------------------------------------------

def _server_source():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server.py")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_there_are_exactly_three_audit_call_sites_and_each_has_a_preflight():
    """Doc 69: the defect was a fourth path missing the guard, so pin both.

    Read as source rather than exercised, so a new route that forgets the
    preflight fails here rather than in production.
    """
    src = _server_source()
    lines = src.splitlines()

    # Any reference to the symbol, not just "run_full_audit(": two of the
    # three call sites pass it to functools.partial, where the name is
    # followed by a comma.
    audit_calls = [i for i, ln in enumerate(lines)
                   if "run_full_audit" in ln
                   and not ln.lstrip().startswith("#")
                   and "import" not in ln
                   and "def run_full_audit" not in ln]
    preflights = [i for i, ln in enumerate(lines)
                  if "_preflight_dns_check" in ln and "def _preflight_dns_check" not in ln
                  and not ln.lstrip().startswith("#")]

    assert len(audit_calls) == 3, [lines[i].strip() for i in audit_calls]
    assert len(preflights) == 3, [lines[i].strip() for i in preflights]

    # Each audit call has a preflight above it, and no two share one.
    used = set()
    for call in audit_calls:
        above = [p for p in preflights if p < call and p not in used]
        assert above, f"no preflight guards the run_full_audit at line {call + 1}"
        used.add(max(above))


def test_every_audit_route_is_one_of_the_three_known_ones():
    """A new /api/audit* route has to be considered here before it ships."""
    src = _server_source()
    routes = re.findall(r'@app\.(?:get|post)\("(/api/audit[^"]*)"', src)
    assert sorted(routes) == ["/api/audit", "/api/audit/stream", "/api/audit/{domain}/pdf"], routes


def test_the_pdf_guard_runs_on_a_cache_miss_before_the_inflight_registry():
    src = _server_source()
    body = src[src.index("async def audit_pdf("):]
    body = body[:body.index("\n@app.")] if "\n@app." in body else body

    guard = body.index("_preflight_dns_check")
    cache_read = body.index("_get_cached(cache_key)")
    join = body.index("_join_or_lead(cache_key)")
    reservation = body.index("_active_audits += 1")

    assert reservation < guard, "the guard must sit inside the concurrency reservation"
    # A cached result already passed the guard, as on /api/audit and the stream.
    assert cache_read < guard, "the guard runs only when the cache misses"
    assert guard < join, "the guard must run before the in-flight registry is joined"
