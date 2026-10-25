"""dns_hosts.py: which host a domain's nameservers belong to, and the steps the
results page and the PDF show for adding a record there."""

import re

import pytest

import dns_hosts
from dns_hosts import HOSTS, dns_host_block, host_for


@pytest.mark.parametrize("ns, name", [
    (["carlos.ns.cloudflare.com", "faye.ns.cloudflare.com"], "Cloudflare"),
    (["ns05.domaincontrol.com.", "NS06.DOMAINCONTROL.COM"], "GoDaddy"),
    (["dns1.registrar-servers.com", "dns2.registrar-servers.com"], "Namecheap"),
    (["ns-1234.awsdns-12.org", "ns-77.awsdns-09.com", "ns-900.awsdns-40.net",
      "ns-1800.awsdns-33.co.uk"], "Amazon Route 53"),
    (["ns1-01.azure-dns.com", "ns2-01.azure-dns.net", "ns3-01.azure-dns.org",
      "ns4-01.azure-dns.info"], "Azure DNS"),
    (["ns1.dns-parking.com", "ns2.dns-parking.com"], "Hostinger"),
    (["curitiba.ns.porkbun.com", "maceio.ns.porkbun.com"], "Porkbun"),
    (["dns11.ovh.net", "ns11.ovh.net"], "OVHcloud"),
])
def test_known_nameservers_name_their_host(ns, name):
    assert host_for(ns).name == name


@pytest.mark.parametrize("ns", [
    [],
    ["dns1.p08.nsone.net", "dns2.p08.nsone.net"],            # NS1: many hosts
    ["ns-cloud-a1.googledomains.com"],                        # Google Cloud or Squarespace
    ["edns3.registrar-servers.com", "edns4.ultradns.com"],    # mixed
    ["ha1.markmonitor.zone"],                                 # not in the table
    ["evilcloudflare.com"],                                   # suffix without a label boundary
])
def test_unknown_mixed_or_shared_nameservers_name_no_host(ns):
    assert host_for(ns) is None


def test_block_words_the_name_rule_for_the_domain():
    block = dns_host_block("example.org", ["a.ns.cloudflare.com", "b.ns.cloudflare.com"])
    assert block["name"] == "Cloudflare"
    assert "ns" not in block
    assert block["name_tip"] == ("Enter the name without your domain (`_dmarc`, not "
                                 "`_dmarc.example.org`). For the domain itself, use @.")
    assert block["warning"].startswith("Set any CNAME for email")
    assert dns_host_block("example.org", []) is None


def test_every_host_has_steps_an_apex_rule_and_a_source_on_its_own_site():
    for host in HOSTS:
        assert len(host.steps) >= 2, host.name
        assert host.apex, host.name
        assert host.source.startswith("https://"), host.name


def test_host_copy_follows_the_house_rules():
    for host in HOSTS:
        text = " ".join((*host.steps, host.apex, host.value_tip, host.warning))
        assert "—" not in text and " -- " not in text, host.name
        assert not re.search(r"[\w.+-]+@[\w-]+\.\w", text), host.name


class _Answer(list):
    pass


class _Target:
    def __init__(self, name):
        self.target = name


class _FakeResolver:
    def __init__(self, zones):
        self.zones = zones
        self.asked = []

    def resolve(self, name, rdtype, lifetime=None):
        self.asked.append(name)
        if name not in self.zones:
            raise dns_hosts.dns.resolver.NoAnswer()
        return _Answer(_Target(n) for n in self.zones[name])


def test_lookup_ns_falls_back_to_the_parent_zone():
    resolver = _FakeResolver({"example.com": ["B.ns.cloudflare.com.", "a.ns.cloudflare.com."]})
    assert dns_hosts.lookup_ns("mail.example.com", resolver) == [
        "a.ns.cloudflare.com", "b.ns.cloudflare.com"]
    assert resolver.asked == ["mail.example.com", "example.com"]


def test_lookup_ns_stops_before_a_top_level_domain():
    resolver = _FakeResolver({})
    assert dns_hosts.lookup_ns("example.com", resolver) == []
    assert resolver.asked == ["example.com"]


def test_audit_engine_reuses_the_nameserver_check(monkeypatch):
    import audit_engine

    monkeypatch.setattr(audit_engine, "lookup_ns",
                        lambda *a, **k: pytest.fail("asked NS again"))
    raw = {"nameservers": {"nameservers": [{"hostname": "x.ns.cloudflare.com"}]}}
    assert audit_engine._dns_host("example.com", raw)["name"] == "Cloudflare"


def test_audit_engine_dns_host_failure_is_none(monkeypatch):
    import audit_engine

    def boom(*a, **k):
        raise RuntimeError("no network")

    monkeypatch.setattr(audit_engine, "lookup_ns", boom)
    assert audit_engine._dns_host("example.com", {}) is None


def test_pdf_prints_the_host_steps_and_names_it_on_dns_host_rows():
    import pdf_report

    data = {"dns_host": dns_host_block("example.org", ["a.ns.cloudflare.com"])}
    S = pdf_report._styles()
    els = pdf_report._dns_host_block(data, S)
    text = " ".join(getattr(e, "text", "") for e in els)
    assert "Your DNS is at Cloudflare" in text
    assert "1. Sign in to the Cloudflare dashboard" in text
    assert "developers.cloudflare.com" in text
    assert pdf_report._dns_host_block({}, S) == []
