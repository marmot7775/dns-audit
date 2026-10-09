"""Vendor signals the audit already holds the records for, now read.

From the vendor gap report (docs/history/vendor-gap-report.md), step 4:

- Every DMARC rua and ruf address and every TLS-RPT rua address. The panel
  read only the first rua address, with one regex, against five reporting
  services.
- Vendors behind the domain's own nested SPF includes and redirects. The
  panel read only the top-level record, so a vendor behind
  include:_spf.example.com, or a record that is just redirect=, was missed,
  though the audit had resolved the whole tree.
- Every hop of a DKIM CNAME chain. Discovery kept only the final name, so a
  vendor CNAME that points on to a CDN fell back to the selector name.
"""
import os
import sys

import dns.name
import dns.rdatatype
import dns.rrset

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import comprehensive_selectors  # noqa: E402
import spf_intelligence  # noqa: E402
from advanced_fingerprinting import AdvancedVendorFingerprinter, nested_spf_vendor_includes  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402
from test_dkim_discovery_starvation import DKIM_RECORD  # noqa: E402
from vendor_patterns import dkim_key_vendor, report_address_domains  # noqa: E402

DOMAIN = "free.test"


def _panel(**prefetch):
    base = {"spf_record": None, "mx_hosts": [], "dmarc_record": None,
            "tls_rpt_record": None, "apex_txt": [], "dkim_selectors": []}
    base.update(prefetch)
    fp = AdvancedVendorFingerprinter(DOMAIN, prefetch=base)
    return {v["name"]: v for v in audit_engine._format_vendors(fp.fingerprint_all()["vendors"])}


# --- report addresses ---

def test_report_address_domains_reads_every_address_in_every_tag():
    rec = ("v=DMARC1; p=none; rua=mailto:a@free.test,mailto:x@ag.dmarcian.com!10m; "
           "ruf=mailto:f@ondmarc.com")
    assert report_address_domains(rec, ("rua", "ruf")) == ["free.test", "ag.dmarcian.com", "ondmarc.com"]
    assert report_address_domains(rec) == ["free.test", "ag.dmarcian.com"]


def test_a_second_rua_and_a_ruf_name_their_services():
    out = _panel(dmarc_record="v=DMARC1; p=none; rua=mailto:a@free.test,mailto:r@rua.easydmarc.com; "
                              "ruf=mailto:f@ruf.uriports.com",
                 tls_rpt_record="v=TLSRPTv1; rua=mailto:t@free.test,mailto:t@dmarc-reports.cloudflare.net")
    assert {"EasyDMARC", "URIports", "Cloudflare DMARC Management"} <= set(out)
    assert all(out[n]["role"] == "reporting" for n in ("EasyDMARC", "URIports",
                                                         "Cloudflare DMARC Management"))


# --- nested SPF ---

def _chain(*entries):
    return [{"domain": d, "record": r, "depth": depth} for depth, d, r in entries]


def test_a_vendor_behind_the_domains_own_include_is_found():
    chain = _chain(
        (0, DOMAIN, "v=spf1 include:_spf.free.test -all"),
        (1, "_spf.free.test", "v=spf1 include:sendgrid.net ~include:mailgun.org -all"),
        (2, "sendgrid.net", "v=spf1 ip4:167.89.0.0/17 ~all"),
        (2, "mailgun.org", "v=spf1 ip4:209.61.151.0/24 ~all"),
    )
    found = nested_spf_vendor_includes(chain)
    # ~include: asks for a softfail: it does not authorize Mailgun.
    assert [(f["vendor"], f["parent"]) for f in found] == [("SendGrid", "_spf.free.test")]
    out = _panel(spf_record="v=spf1 include:_spf.free.test -all", spf_chain=chain)
    assert out["SendGrid"]["sources"] == ["SPF"] and out["SendGrid"]["role"] == "sender"


def test_a_top_level_redirect_names_its_vendor():
    chain = _chain((0, DOMAIN, "v=spf1 redirect=_spf.google.com"),
                   (1, "_spf.google.com", "v=spf1 include:_netblocks.google.com ~all"),
                   (2, "_netblocks.google.com", "v=spf1 ip4:35.190.247.0/24 ~all"))
    out = _panel(spf_record="v=spf1 redirect=_spf.google.com", spf_chain=chain)
    assert "Google Workspace" in out


def test_includes_inside_a_vendors_own_record_are_not_credited():
    # An ESP whose record includes Amazon SES is that ESP, not an SES account.
    chain = _chain((0, DOMAIN, "v=spf1 include:sendgrid.net -all"),
                   (1, "sendgrid.net", "v=spf1 include:amazonses.com ~all"),
                   (2, "amazonses.com", "v=spf1 ip4:199.255.192.0/22 ~all"))
    assert nested_spf_vendor_includes(chain) == []


# --- DKIM CNAME chain ---

class ChainZone(FakeZone):
    """A TXT query at an alias answers with a two-hop CNAME chain in the
    response, as dnspython returns it."""

    def __init__(self, records, chains):
        super().__init__(records)
        self.chains = chains

    def resolve(self, name, rdtype="A", *args, **kwargs):
        hops = self.chains.get(str(name).rstrip(".").lower())
        if hops and str(rdtype).upper() == "TXT":
            answer = super().resolve(hops[-1], rdtype, *args, **kwargs)
            answer.canonical_name = dns.name.from_text(hops[-1])
            names = [str(name).rstrip(".")] + hops
            answer.response.answer = [
                dns.rrset.from_text(names[i] + ".", 300, "IN", "CNAME", names[i + 1] + ".")
                for i in range(len(hops))]
            return answer
        return super().resolve(name, rdtype, *args, **kwargs)


def test_the_first_hop_names_the_vendor(monkeypatch):
    hops = ["s1.domainkey.u1.wl.sendgrid.net", "keys.cdn-example.net"]
    zone = ChainZone({DOMAIN: {"TXT": ["v=spf1 -all"]}, hops[-1]: {"TXT": [DKIM_RECORD]}},
                     {f"s1._domainkey.{DOMAIN}": hops})
    monkeypatch.setattr(comprehensive_selectors, "GENERIC_SELECTORS", [])
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, "v=spf1 -all", mx_hosts=[])
    [sel] = raw["found_selectors"]
    assert sel["cname_chain"] == hops
    out = _panel(dkim_selectors=audit_engine._live_dkim_selectors(raw))
    assert out["SendGrid"]["sources"] == ["DKIM CNAME"]
    assert dkim_key_vendor("s1", hops[-1], None, hops) == "SendGrid"


def test_a_full_audit_finds_the_vendor_behind_a_wrapper_include(audit):
    domain = "wrap.test"
    zone = {
        domain: {"TXT": ["v=spf1 include:_spf.wrap.test -all"], "MX": [(10, f"mail.{domain}")],
                 "A": ["203.0.113.1"]},
        f"_spf.{domain}": {"TXT": ["v=spf1 include:sendgrid.net -all"]},
        "sendgrid.net": {"TXT": ["v=spf1 ip4:167.89.0.0/17 ~all"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain},mailto:x@rua.easydmarc.com"]},
    }
    result = audit(zone, domain, scope="email_full")
    by_name = {v["name"]: v for v in result["vendors"]}
    assert by_name["SendGrid"]["sources"] == ["SPF"] and by_name["SendGrid"]["role"] == "sender"
    assert by_name["EasyDMARC"]["role"] == "reporting"


def test_a_softfail_wrapper_does_not_authorize_what_it_includes():
    chain = _chain((0, DOMAIN, "v=spf1 ~include:_spf.free.test -all"),
                   (1, "_spf.free.test", "v=spf1 include:sendgrid.net -all"),
                   (2, "sendgrid.net", "v=spf1 ip4:167.89.0.0/17 ~all"))
    assert nested_spf_vendor_includes(chain) == []


def test_mailto_header_fields_are_not_the_recipient():
    rec = "v=DMARC1; p=none; rua=mailto:r@free.test?subject=x@dmarcian.com"
    assert report_address_domains(rec) == ["free.test"]


def test_a_malformed_recipient_names_nobody():
    assert report_address_domains("v=DMARC1; rua=mailto:bad@@dmarcian.com,mailto:@x.com") == []
