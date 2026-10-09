"""One rule names a DKIM key's vendor, in the DKIM card, its key table and
the vendor panel alike (vendor_patterns.dkim_key_vendor).

The card and key table preferred the vendor discovery tagged from the SPF
vendor map, which lists k1 under six vendors and selector1 under Microsoft
365. A domain on Mailgun with a Mailchimp k1 CNAME got "k1 (Mailgun)" in the
card while the panel said Mailchimp, and a selector1 TXT key at a Microsoft
365 domain was credited to Microsoft 365, though Microsoft publishes those
names only as CNAMEs. The rule matches Neil's sender discovery script: the
CNAME target first, selector1 and selector2 only through the CNAME, a
generic name only when other records back the vendor.
"""
import os
import sys

import dns.name

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import comprehensive_selectors
import spf_intelligence
from advanced_fingerprinting import AdvancedVendorFingerprinter
from audit_engine import _live_dkim_selectors
from conftest import FakeZone, fake_dns
from result_transformer import _build_dkim_key_analysis, transform_dkim
from test_dkim_discovery_starvation import DKIM_RECORD
from vendor_patterns import dkim_key_vendor

DOMAIN = "naming.test"


class AliasZone(FakeZone):
    """FakeZone plus CNAMEs: a TXT query at an alias answers with the
    target's records and the target as canonical_name, as dnspython does."""

    def __init__(self, records, aliases):
        super().__init__(records)
        self.aliases = {k.lower(): v for k, v in aliases.items()}

    def resolve(self, name, rdtype="A", *args, **kwargs):
        target = self.aliases.get(str(name).rstrip(".").lower())
        if target and str(rdtype).upper() == "TXT":
            answer = super().resolve(target, rdtype, *args, **kwargs)
            answer.canonical_name = dns.name.from_text(target)
            return answer
        return super().resolve(name, rdtype, *args, **kwargs)


def _run(monkeypatch, spf, mx=(), keys=(), aliases=None):
    records = {DOMAIN: {"TXT": [spf]}}
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    for target in (aliases or {}).values():
        records[target] = {"TXT": [DKIM_RECORD]}
    zone = AliasZone(records, {f"{s}._domainkey.{DOMAIN}": t for s, t in (aliases or {}).items()})
    monkeypatch.setattr(comprehensive_selectors, "GENERIC_SELECTORS", [])
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, spf, mx_hosts=list(mx))
    card = transform_dkim(raw, DOMAIN)
    table = {k["selector"]: k["provider"] for k in _build_dkim_key_analysis(raw)["keys"]}
    fp = AdvancedVendorFingerprinter(DOMAIN, prefetch={
        "spf_record": None, "mx_hosts": [], "dmarc_record": None, "tls_rpt_record": None,
        "txt_ttl": None, "apex_txt": [], "dkim_selectors": _live_dkim_selectors(raw)})
    fp._fingerprint_dkim()
    panel = {s["evidence"].split("._domainkey")[0]: s["vendor"] for s in fp.signals}
    return card, table, panel


def test_the_cname_target_beats_the_spf_tag(monkeypatch):
    card, table, panel = _run(monkeypatch, "v=spf1 include:mailgun.org ~all",
                              aliases={"k1": "dkim.mcsv.net"})
    assert table == {"k1": "Mailchimp"}
    assert panel == {"k1": "Mailchimp"}
    texts = [d["text"] for d in card["details"]]
    assert any(t.startswith("k1:") and "(Mailchimp)" in t for t in texts), texts
    assert "Sending providers detected: Mailchimp" in card["explanation"]


def test_selector1_without_microsofts_cname_names_nobody(monkeypatch):
    card, table, panel = _run(monkeypatch, "v=spf1 include:spf.protection.outlook.com -all",
                              mx=["naming-test.mail.protection.outlook.com"], keys=["selector1"])
    assert table == {"selector1": "Vendor: unknown"}
    assert panel == {}
    assert not any("(Microsoft 365)" in d["text"] for d in card["details"])


def test_selector1_through_microsofts_cname_is_microsoft(monkeypatch):
    _, table, panel = _run(monkeypatch, "v=spf1 include:spf.protection.outlook.com -all",
                           aliases={"selector1": "selector1-naming-test._domainkey.contoso.onmicrosoft.com"})
    assert table == {"selector1": "Microsoft 365"}
    assert panel == {"selector1": "Microsoft 365"}


def test_a_shared_name_goes_to_the_vendor_spf_backs(monkeypatch):
    # k1 as a TXT key at a Mailgun domain, no CNAME: Mailgun, not Mailchimp.
    _, table, panel = _run(monkeypatch, "v=spf1 include:mailgun.org ~all", keys=["k1"])
    assert table == {"k1": "Mailgun"} and panel == {"k1": "Mailgun"}


def test_generic_names_need_backing():
    assert dkim_key_vendor("mg", None) is None
    assert dkim_key_vendor("sf", None) is None
    assert dkim_key_vendor("default", None) is None
    assert dkim_key_vendor("mg", None, "Mailgun") == "Mailgun"
    # Short names the script keeps as distinctive still name their vendor.
    assert dkim_key_vendor("k1", None) == "Mailchimp"
    assert dkim_key_vendor("s1", None) == "SendGrid"
    assert dkim_key_vendor("kl", None) == "Klaviyo"
    assert dkim_key_vendor("selector2", None, "Microsoft 365") is None
