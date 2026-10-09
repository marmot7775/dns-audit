"""The vendor panel says how strong the evidence is in words, the sender
discovery script's tiers, in place of a percentage that read 99 for nearly
every vendor (vendor gap report, step 7).

In use: MX. Configured: an SPF include, or a DKIM key the vendor hosts
through a CNAME. Likely: a DKIM key known only by its selector name.
Account only: a verification token or a report address. A verification
token alone had shown Microsoft 365 as a sender and could draw an SPF
include suggestion.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
from advanced_fingerprinting import AdvancedVendorFingerprinter  # noqa: E402


def _panel(**prefetch):
    base = {"spf_record": None, "mx_hosts": [], "dmarc_record": None,
            "tls_rpt_record": None, "apex_txt": [], "dkim_selectors": []}
    base.update(prefetch)
    fp = AdvancedVendorFingerprinter("tier.test", prefetch=base)
    return audit_engine._format_vendors(fp.fingerprint_all()["vendors"])


def test_each_signal_lands_in_its_tier_in_order():
    out = _panel(mx_hosts=["aspmx.l.google.com"],
                 spf_record="v=spf1 include:sendgrid.net ~all",
                 dkim_selectors=[{"selector": "k1", "cname_target": "dkim.mcsv.net"},
                                 {"selector": "kl"}],
                 apex_txt=["MS=ms12345678"],
                 dmarc_record="v=DMARC1; p=none; rua=mailto:x@ag.dmarcian.com")
    assert [(v["name"], v["tier"], v["role"]) for v in out] == [
        ("Google Workspace", "In use", "sender"),
        ("Mailchimp", "Configured", "sender"),
        ("SendGrid", "Configured", "sender"),
        ("Klaviyo", "Likely", "sender"),
        ("Microsoft 365", "Account only", "account"),
        ("DMARCian", "Account only", "reporting"),
    ]


def test_a_verification_token_alone_gets_no_spf_include_suggestion(audit):
    domain = "tok.test"
    zone = {
        domain: {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all", "MS=ms12345678"],
                 "MX": [(10, f"mail.{domain}")], "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
        "spf.protection.outlook.com": {"TXT": ["v=spf1 ip4:40.92.0.0/15 -all"]},
    }
    result = audit(zone, domain, scope="email_full")
    assert [(v["name"], v["role"]) for v in result["vendors"]] == [("Microsoft 365", "account")]
    fix = next(c for c in result["checks"] if c["name"] == "SPF").get("fix") or ""
    assert "outlook" not in fix.lower(), fix
