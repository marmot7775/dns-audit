"""Vendor detection reads one table, and DKIM keys count as evidence.

Before, the vendor panel knew 13 vendors from SPF and 4 from MX, three of
its SPF patterns did not exist in DNS, and it ignored DKIM entirely.
casper.com (Salesforce and Campaign Monitor in SPF; Mailchimp, Mandrill
and SendGrid keys) showed only Google Workspace and DMARCian.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
from advanced_fingerprinting import AdvancedVendorFingerprinter
from comprehensive_selectors import ESP_SELECTORS
from vendor_patterns import (
    DKIM_SELECTOR_VENDORS,
    MX_VENDORS,
    SPF_INCLUDE_VENDORS,
    dkim_key_vendor,
    match_host,
)


def test_longest_pattern_wins():
    assert match_host("spf.em.secureserver.net", SPF_INCLUDE_VENDORS) == "GoDaddy Websites + Marketing"
    assert match_host("secureserver.net", SPF_INCLUDE_VENDORS) == "GoDaddy Professional Email"
    assert match_host("x.olc.protection.outlook.com", MX_VENDORS) == "Outlook.com (consumer)"
    assert match_host("x.mail.protection.outlook.com", MX_VENDORS) == "Microsoft 365"


def test_label_boundary_not_substring():
    assert match_host("sendgrid.net.attacker.example", SPF_INCLUDE_VENDORS) is None
    assert match_host("notsendgrid.net", SPF_INCLUDE_VENDORS) is None
    assert match_host("u123.wl.sendgrid.net.", SPF_INCLUDE_VENDORS) == "SendGrid"


def test_dead_spf_names_are_gone():
    for dead in ("_spf.marketo.com", "_spf.mimecast.com", "_spf.pphosted.com"):
        assert dead not in SPF_INCLUDE_VENDORS
    # The zones still match the per-customer includes.
    assert match_host("_netblocks.mimecast.com", SPF_INCLUDE_VENDORS) == "Mimecast"
    assert match_host("_spf.pphosted.com", SPF_INCLUDE_VENDORS) == "Proofpoint"


def test_dkim_cname_beats_selector_name():
    assert dkim_key_vendor("s1", "s1.domainkey.u1.wl.sendgrid.net") == "SendGrid"
    assert dkim_key_vendor("k1", None) == "Mailchimp"
    assert dkim_key_vendor("hs1-12345", "x.hs1-12345.dkim.hubspotemail.net") == "HubSpot"
    assert dkim_key_vendor("default", None) is None
    assert dkim_key_vendor("api", None) is None


def test_esp_selectors_all_named_but_api():
    assert [s for s in ESP_SELECTORS if s not in DKIM_SELECTOR_VENDORS] == ["api"]


def _fp(**prefetch):
    base = {"spf_record": None, "mx_hosts": [], "dmarc_record": None,
            "tls_rpt_record": None, "txt_ttl": None}
    base.update(prefetch)
    fp = AdvancedVendorFingerprinter("example.test", prefetch=base)
    fp._fingerprint_spf()
    fp._fingerprint_mx()
    fp._fingerprint_dkim()
    fp._fingerprint_verification_txt()
    return {v["vendor"]: v for v in fp._aggregate_and_score()["vendors"]}


def test_dkim_keys_feed_the_panel():
    vendors = _fp(dkim_selectors=[
        {"selector": "k1"},
        {"selector": "s1", "cname_target": "s1.domainkey.u1.wl.sendgrid.net"},
        {"selector": "default"},
    ])
    assert set(vendors) == {"Mailchimp", "SendGrid"}
    assert vendors["SendGrid"]["confidence"] > vendors["Mailchimp"]["confidence"]


def test_weaker_second_signal_does_not_lower_the_score():
    spf_only = _fp(spf_record="v=spf1 include:_spf.createsend.com -all")
    both = _fp(spf_record="v=spf1 include:_spf.createsend.com -all",
               dkim_selectors=[{"selector": "cm"}])
    assert both["Campaign Monitor"]["confidence"] >= spf_only["Campaign Monitor"]["confidence"]


def test_format_vendors_names_sources_and_side():
    out = audit_engine._format_vendors([{
        "vendor": "Mailchimp", "confidence": 0.75,
        "signals": [{"technique": "DKIM Key"}, {"technique": "SPF Include"}],
    }])
    assert out == [{"name": "Mailchimp", "confidence": 75,
                    "detected_via": "outbound", "sources": ["SPF", "DKIM"]}]


def test_retired_keys_are_not_passed_to_fingerprinting():
    live = audit_engine._live_dkim_selectors({"found_selectors": [
        {"selector": "k1", "record": "v=DKIM1; k=rsa; p="},
        {"selector": "s1", "record": "v=DKIM1; k=rsa; p=MIGfMA0G"},
    ]})
    assert [s["selector"] for s in live] == ["s1"]


def test_verification_tokens_name_mail_services_only():
    from vendor_patterns import match_verification_txt as m
    assert m("MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805") == "Microsoft 365"
    assert m("MS=ms12345678") == "Microsoft 365"
    assert m("pardot1113342=ea9966a0") == "Salesforce Account Engagement"
    assert m("brevo-code:7e6bbbf1") == "Brevo"
    assert m("amazonses:KsIm8akt") == "Amazon SES"
    assert m("google-site-verification=UTM-3akM") is None
    assert m("stripe-verification=f88ef1") is None
    assert m("ms=hello") is None


def test_verification_txt_feeds_the_panel_without_a_side():
    vendors = _fp(apex_txt=["MS=ms12345678", "google-site-verification=x", "mgverify=2738a5123a"])
    assert set(vendors) == {"Microsoft 365", "Mailgun"}
    out = audit_engine._format_vendors([vendors["Mailgun"]])
    assert out[0]["sources"] == ["TXT"] and out[0]["detected_via"] is None


def test_only_authorizing_includes_name_a_vendor():
    vendors = _fp(spf_record="v=spf1 include:_spf.google.com -include:sendgrid.net "
                             "~include:mailgun.org +include:spf.mtasv.net -all")
    assert set(vendors) == {"Google Workspace", "Postmark"}


def test_verification_prefix_needs_a_token():
    from vendor_patterns import match_verification_txt as m
    assert m("mgverify=") is None
    assert m("amazonses:") is None
    assert m("pardot123=") is None
    assert m("MS=") is None
    assert m("MS=ms12345678") == "Microsoft 365"
