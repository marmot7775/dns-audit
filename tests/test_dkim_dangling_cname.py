"""DKIM selectors that are CNAMEs to names that do not exist.

github.com's selector2 is one (Microsoft's unfilled rotation slot, which is
normal). The dangerous kind points into a domain nobody has registered:
whoever registers it can publish a key and sign mail that passes DKIM, and
so DMARC, as the audited domain. Discovery used to drop both silently.
"""
import os
import sys

import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import comprehensive_selectors
import spf_intelligence
from conftest import FakeZone, fake_dns
from result_transformer import build_security_roadmap, transform_dkim
from test_dkim_discovery_starvation import DKIM_RECORD

DOMAIN = "dangle.test"
SPF = "v=spf1 ip4:203.0.113.80 -all"


class _DanglingNX(dns.resolver.NXDOMAIN):
    """NXDOMAIN after following a CNAME, as dnspython raises it."""

    def __init__(self, target):
        super().__init__()
        self._target = target

    @property
    def canonical_name(self):
        return dns.name.from_text(self._target)


def _zone(dangling=(), keys=(), registered=()):
    records = {DOMAIN: {"TXT": [SPF]}}
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    for zone_name in registered:
        records[zone_name] = {"NS": ["ns1.example.net."]}
    zone = FakeZone(records)
    for sel, target in dangling:
        zone.fail(f"{sel}._domainkey.{DOMAIN}", "TXT", _DanglingNX(target))
    return zone


def _run(zone, monkeypatch):
    monkeypatch.setattr(comprehensive_selectors, "GENERIC_SELECTORS", [])
    with fake_dns(zone):
        return spf_intelligence.smart_dkim_check(DOMAIN, SPF, mx_hosts=[])


def test_unregistered_target_fails_the_card_and_tops_the_plan(monkeypatch):
    raw = _run(_zone(dangling=[("k1", "dkim.lapsed-esp-example.com")], keys=["s1"]), monkeypatch)
    [d] = raw["dangling_selectors"]
    assert d["status"] == "unregistered" and d["registrable"] == "lapsed-esp-example.com"
    assert [s["selector"] for s in raw["found_selectors"]] == ["s1"]
    card = transform_dkim(raw, DOMAIN)
    assert card["status"] == "fail"
    assert any("not a registered domain" in x["text"] for x in card["details"])
    items = build_security_roadmap([card])["items"]
    assert items[0]["priority"] == "critical"
    assert "unregistered domain" in items[0]["action"]


def test_unregistered_target_fails_even_with_no_key_found(monkeypatch):
    raw = _run(_zone(dangling=[("k1", "dkim.lapsed-esp-example.com")]), monkeypatch)
    card = transform_dkim(raw, DOMAIN)
    assert card["status"] == "fail"
    assert "pill_label" not in card
    assert card["verdict"] == "DKIM selector k1 points at an unregistered domain"


def test_unregistered_target_fails_on_a_no_mail_domain(monkeypatch):
    raw = _run(_zone(dangling=[("k1", "dkim.lapsed-esp-example.com")]), monkeypatch)
    card = transform_dkim(raw, DOMAIN, has_mx=False, non_mail=True)
    assert card["status"] == "fail"


def test_stale_target_in_a_live_zone_is_info_only(monkeypatch):
    raw = _run(_zone(dangling=[("k1", "dkim.mcsv.net")], keys=["s1"],
                     registered=["mcsv.net"]), monkeypatch)
    [d] = raw["dangling_selectors"]
    assert d["status"] == "stale" and d["vendor"] == "Mailchimp"
    card = transform_dkim(raw, DOMAIN)
    assert card["status"] == "pass"
    assert any(x["type"] == "info" and "does not exist" in x["text"] for x in card["details"])
    assert not any(i["protocol"] == "DKIM" and "unregistered" in i["action"]
                   for i in build_security_roadmap([card])["items"])


def test_microsoft_rotation_slot_is_not_reported(monkeypatch):
    target = "selector2-dangle-test._domainkey.contoso.onmicrosoft.com"
    raw = _run(_zone(dangling=[("selector2", target)], keys=["selector1"]), monkeypatch)
    assert raw["dangling_selectors"] == []
    assert not any("selector2" in x["text"] for x in transform_dkim(raw, DOMAIN)["details"])


def test_plain_nxdomain_is_not_dangling(monkeypatch):
    raw = _run(_zone(keys=["s1"]), monkeypatch)
    assert raw["dangling_selectors"] == []


def test_both_microsoft_slots_empty_is_an_info_line(monkeypatch):
    zone = _zone(dangling=[
        ("selector1", "selector1-dangle-test._domainkey.contoso.onmicrosoft.com"),
        ("selector2", "selector2-dangle-test._domainkey.contoso.onmicrosoft.com"),
    ], keys=["s1"])
    raw = _run(zone, monkeypatch)
    [d] = raw["dangling_selectors"]
    assert d["status"] == "microsoft_unfilled"
    card = transform_dkim(raw, DOMAIN)
    assert card["status"] == "pass"
    assert any("not turned on" in x["text"] for x in card["details"])


def test_unanswered_ns_lookup_is_unknown_not_stale(monkeypatch):
    zone = _zone(dangling=[("k1", "dkim.flaky-example.com")], keys=["s1"])
    zone.fail("flaky-example.com", "NS")
    raw = _run(zone, monkeypatch)
    [d] = raw["dangling_selectors"]
    assert d["status"] == "unknown"
    assert transform_dkim(raw, DOMAIN)["status"] == "pass"
