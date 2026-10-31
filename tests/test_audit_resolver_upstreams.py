"""The audit never depends on a lone stub resolver, and says what failed (Doc 100).

On 2026-10-12 every NXDOMAIN through the droplet's systemd-resolved stub,
127.0.0.53, timed out while the same query sent to the upstream answered in
2 ms. The audit's resolvers copied /etc/resolv.conf, which named only the
stub, so MTA-STS, TLS-RPT and BIMI read "Not checked" on every domain and the
card blamed the domain's nameserver.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns.resolver
from fastapi.testclient import TestClient

import config
import dns_tools
import mx_check
import server as server_module
from audit_engine import _build_resilience_analysis
from result_transformer import _lookup_unavailable_card

OLD_SENTENCE = "returned a failure or stopped"
NEW_SENTENCE = (
    "This audit did not get an answer in time. That can be the domain's "
    "nameservers or the audit's own resolver, and the audit cannot tell which "
    "from here."
)


def _stub_only_template():
    template = dns.resolver.Resolver(configure=False)
    template.nameservers = ["127.0.0.53"]
    return template


# -- _upstream_nameservers ---------------------------------------------------

def test_stub_replaced_by_systemd_upstreams_then_public(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", [])
    upstream = tmp_path / "resolv.conf"
    upstream.write_text("nameserver 67.207.67.2\nnameserver 67.207.67.3\n")

    servers = dns_tools._upstream_nameservers(_stub_only_template(), str(upstream))

    assert servers == ["67.207.67.2", "67.207.67.3", "1.1.1.1", "8.8.8.8"]


def test_stub_dropped_when_systemd_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", [])

    servers = dns_tools._upstream_nameservers(
        _stub_only_template(), str(tmp_path / "missing.conf"))

    assert servers == ["1.1.1.1", "8.8.8.8"]
    assert "127.0.0.53" not in servers


def test_stub_dropped_when_systemd_file_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", [])
    upstream = tmp_path / "resolv.conf"
    upstream.write_text("")

    servers = dns_tools._upstream_nameservers(_stub_only_template(), str(upstream))

    assert servers == ["1.1.1.1", "8.8.8.8"]


def test_ipv6_loopback_is_a_stub_too(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", [])
    template = dns.resolver.Resolver(configure=False)
    template.nameservers = ["::1", "10.0.0.2"]

    servers = dns_tools._upstream_nameservers(template, str(tmp_path / "missing.conf"))

    assert servers == ["10.0.0.2", "1.1.1.1", "8.8.8.8"]


def test_public_resolvers_not_repeated(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", [])
    template = dns.resolver.Resolver(configure=False)
    template.nameservers = ["8.8.8.8"]

    servers = dns_tools._upstream_nameservers(template, str(tmp_path / "missing.conf"))

    assert servers == ["8.8.8.8", "1.1.1.1"]


def test_audit_nameservers_setting_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_NAMESERVERS", ["9.9.9.9", "149.112.112.112"])
    upstream = tmp_path / "resolv.conf"
    upstream.write_text("nameserver 67.207.67.2\n")

    servers = dns_tools._upstream_nameservers(_stub_only_template(), str(upstream))

    assert servers == ["9.9.9.9", "149.112.112.112"]


def test_audit_resolvers_use_the_upstream_list():
    assert dns_tools.get_resolver().nameservers == dns_tools.AUDIT_UPSTREAMS
    assert dns_tools.get_uncached_resolver().nameservers == dns_tools.AUDIT_UPSTREAMS
    assert not any(dns_tools._is_loopback(ns) for ns in dns_tools.AUDIT_UPSTREAMS)


def test_timeout_and_lifetime_unchanged():
    resolver = dns_tools.get_resolver(4.0)
    assert resolver.timeout == 4.0
    assert resolver.lifetime == 8.0


# -- /api/health negative lookup probe ---------------------------------------

class _RaisingResolver:
    def __init__(self, exc):
        self.exc = exc
        self.lifetime = None
        self.queries = []

    def resolve(self, name, rdtype, *args, **kwargs):
        self.queries.append((name, rdtype))
        raise self.exc


def _health_with(monkeypatch, exc):
    fake = _RaisingResolver(exc)
    monkeypatch.setattr(server_module, "get_uncached_resolver", lambda timeout: fake)
    monkeypatch.setattr(server_module.dns.resolver, "resolve", lambda *a, **k: None)
    monkeypatch.setitem(server_module._health_cache, "expires", 0.0)
    monkeypatch.setitem(server_module._negative_probe_cache, "expires", 0.0)
    response = TestClient(server_module.app).get("/api/health")
    return response, fake


def test_health_reports_negative_lookups_failing(monkeypatch):
    response, fake = _health_with(monkeypatch, dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["dns_resolution"] == "working"
    assert body["negative_lookups"] == "failing"
    assert body["negative_lookups_error"] == "LifetimeTimeout"
    assert len(fake.queries) == 1
    assert fake.lifetime == 3
    assert fake.queries[0][1] == "TXT"
    assert fake.queries[0][0].startswith("health-")


def test_health_reports_negative_lookups_ok_on_nxdomain(monkeypatch):
    response, _ = _health_with(monkeypatch, dns.resolver.NXDOMAIN())

    body = response.json()
    assert body["status"] == "ok"
    assert body["negative_lookups"] == "ok"
    assert "negative_lookups_error" not in body


def test_health_reports_negative_lookups_ok_on_no_answer(monkeypatch):
    response, _ = _health_with(monkeypatch, dns.resolver.NoAnswer())

    assert response.json()["negative_lookups"] == "ok"


def test_negative_probe_flags_positive_answer(monkeypatch):
    class _Answering:
        lifetime = 0

        def resolve(self, name, rdtype, *args, **kwargs):
            return object()

    monkeypatch.setattr(server_module, "get_uncached_resolver", lambda timeout: _Answering())
    assert server_module._negative_lookup_probe() == "UnexpectedPositiveAnswer"


def test_negative_probe_memoized(monkeypatch):
    _, fake = _health_with(monkeypatch, dns.resolver.NXDOMAIN())
    client = TestClient(server_module.app)
    client.get("/api/health")
    client.get("/api/health")

    assert len(fake.queries) == 1


# -- The uncompleted lookup says it cannot tell who failed -------------------

def test_lookup_unavailable_card_wording():
    card = _lookup_unavailable_card("MTA-STS", {"domain": "example.com"}, "MTA-STS policy record")

    assert NEW_SENTENCE in card["explanation"]
    assert OLD_SENTENCE not in card["explanation"]
    assert "not a finding about the domain" in card["explanation"]
    assert "does not mean the record is missing" in card["explanation"]


def test_mx_lookup_unavailable_wording(monkeypatch):
    class _Timeout:
        def resolve(self, *a, **k):
            raise dns.exception.Timeout()

    monkeypatch.setattr(mx_check, "_get_resolver", lambda *a, **k: _Timeout())
    result = mx_check.check_mx("example.com")

    assert result["status"] == "unavailable"
    text = " ".join(str(v) for issue in result["issues"] for v in issue.values())
    assert NEW_SENTENCE in text
    assert OLD_SENTENCE not in text


def test_resilience_unavailable_wording():
    raw = {
        "spf": {"status": "unavailable"},
        "dmarc": {"status": "unavailable"},
        "dkim": {},
    }
    resilience = _build_resilience_analysis(raw, [], has_mx=True, is_defensive=False)

    assert resilience["level"] == "inconclusive"
    assert NEW_SENTENCE in resilience["risk"]
    assert OLD_SENTENCE not in resilience["risk"]


def test_no_rerun_advice_blames_the_nameservers():
    # The audit cannot tell whose resolver failed, so the re-run advice
    # must not imply the domain's nameservers were the problem.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("audit_engine.py", "mx_check.py", "result_transformer.py"):
        with open(os.path.join(root, name), encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        assert "once the nameservers are answering" not in text, name
