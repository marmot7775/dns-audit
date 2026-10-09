"""Return path, tracking and autodiscover CNAMEs name vendors (vendor gap
report, step 6, docs/history/vendor-gap-report.md).

The audit asks one parallel wave of CNAME queries at the fixed labels in
vendor_patterns.VENDOR_CNAME_LABELS, on _probe_executor, plus a random label:
a wildcard CNAME answers every name, so a label that returns the wildcard's
own target counts for nothing. Before, the fingerprinter asked for an A
record at bounce, autodiscover and email and never looked at a target.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402
from vendor_patterns import VENDOR_CNAME_LABELS, label_cname_vendor  # noqa: E402


def _zone(domain, extra):
    zone = {
        domain: {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"], "MX": [(10, f"mail.{domain}")],
                 "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
    }
    zone.update(extra)
    return zone


def test_a_return_path_and_a_tracking_cname_name_their_vendors(audit):
    domain = "rp.test"
    result = audit(_zone(domain, {
        f"pm-bounces.{domain}": {"CNAME": ["pm.mtasv.net."]},
        f"click.{domain}": {"CNAME": ["u123.ct.sendgrid.net."]},
        f"autodiscover.{domain}": {"CNAME": ["autodiscover.outlook.com."]},
    }), domain, scope="email_full")
    by_name = {v["name"]: v for v in result["vendors"]}
    assert by_name["Postmark"]["sources"] == ["return path CNAME"]
    assert by_name["Postmark"]["tier"] == "Configured" and by_name["Postmark"]["role"] == "sender"
    assert by_name["SendGrid"]["sources"] == ["tracking CNAME"]
    assert by_name["Microsoft 365"]["tier"] == "Account only"
    assert by_name["Microsoft 365"]["role"] == "account"


def test_a_wildcard_cname_names_nobody():
    domain = "wild.test"
    zone = FakeZone(_zone(domain, {}))
    original = zone.resolve

    def resolve(name, rdtype="A", *a, **k):
        # Every label under the domain is a CNAME to one host in a vendor zone.
        if str(rdtype).upper() == "CNAME" and str(name).rstrip(".").endswith("." + domain):
            zone.queries.append((str(name), "CNAME"))
            return FakeZone({"x": {"CNAME": ["catchall.sendgrid.net."]}}).resolve("x", "CNAME")
        return original(name, rdtype, *a, **k)
    zone.resolve = resolve
    with fake_dns(zone):
        assert audit_engine._probe_vendor_cnames(domain, 3.0) == {}


def test_the_wave_asks_every_label_once_and_a_canary():
    domain = "count.test"
    zone = FakeZone(_zone(domain, {}))
    with fake_dns(zone):
        audit_engine._probe_vendor_cnames(domain, 3.0)
    asked = [n for n, t in zone.queries if t == "CNAME"]
    assert len(asked) == len(VENDOR_CNAME_LABELS) + 1
    assert sum(1 for n in asked if n.startswith("dnsaudit")) == 1


def test_label_order_decides_tracking_or_return_path():
    # mailjet.com is both a return path and a tracking zone.
    assert label_cname_vendor("bnc3", "bnc3.mailjet.com") == ("Mailjet", "return path")
    assert label_cname_vendor("links", "r.mailjet.com") == ("Mailjet", "tracking")
    assert label_cname_vendor("autodiscover", "autodiscover.example.net") == (None, None)


def test_an_unfinished_canary_discards_the_wave(monkeypatch):
    import threading
    domain = "slow.test"
    release = threading.Event()
    real = audit_engine._probe_vendor_cname

    def probe(name):
        if name.startswith("dnsaudit"):
            release.wait(5)  # the canary outlives the budget
            return None
        return "pm.mtasv.net" if name.startswith("pm-bounces.") else None
    monkeypatch.setattr(audit_engine, "_probe_vendor_cname", probe)
    try:
        assert audit_engine._probe_vendor_cnames(domain, 0.3) == {}
    finally:
        release.set()
        monkeypatch.setattr(audit_engine, "_probe_vendor_cname", real)
