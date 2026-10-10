"""The SPF card suggests a vendor's include only when the vendor needs one.

VENDOR_SPF_INCLUDES suggested includes for ESPs that send with their own
return path (Mailchimp, Postmark, SparkPost, Brevo), so a domain whose only
Mailchimp evidence was its k1 DKIM key was told to add
include:servers.mcsv.net, a lookup out of ten spent on nothing. Two keys
("ProtonMail", "Brevo (Sendinblue)") never matched a name the vendor panel
produces, and Barracuda, Zoho and Fastmail pointed at includes their own
docs do not give. The table now follows the footprints in Neil's sender
discovery vendors.json: only vendors whose include is required.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vendor_patterns  # noqa: E402
from audit_engine import VENDOR_SPF_INCLUDES  # noqa: E402

DKIM_KEY = ("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwQ7hD3Cj2Nk5vH9g"
            "YxBf3m6QeZ4j1T2nYh6uJ0rP8kL5sA7dE9fG2hI4jK6lM8nO0pQ2rS4tU6vW8xY0zA2bC4dE6fG8hI"
            "0jK2lM4nO6pQ8rS0tU2vW4xY6zA8bC0dE2fG4hI6jK8lM0nO2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hI"
            "2jK4lM6nO8pQ0rS2tU4vW6xY8zA0bC2dE4fG6hI8jK0lM2nO4pQ6rS8tU0vW2xY4zA6bC8dE0fG2hI"
            "4jK6lM8nO0pQ2rS4tU6vW8xY0zA2bC4dE6fG8hI0jK2lM4nO6pQ8rS0tU2vW4xY6zA8bC0dE2fG4hI"
            "6jK8lM0nO2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hI2jK4lM6nO8pQ0rS2tU4vW6xY8zA0bC2dE4fG6hI"
            "8jK0lM2nO4pQIDAQAB")


def _zone(domain, spf, mx, extra=None):
    zone = {
        domain: {"TXT": [spf], "MX": mx, "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
    }
    zone.update(extra or {})
    return zone


def _fix_and_vendors(audit, zone, domain):
    result = audit(zone, domain, scope="email_full")
    card = next(c for c in result["checks"] if c["name"] == "SPF")
    return card.get("fix") or "", [v["name"] for v in result["vendors"]]


def test_an_esp_that_uses_its_own_return_path_gets_no_include(audit):
    domain = "mc.test"
    zone = _zone(domain, "v=spf1 ip4:203.0.113.0/24 -all", [(10, f"mail.{domain}")],
                 {f"k1._domainkey.{domain}": {"TXT": [DKIM_KEY]}})
    fix, vendors = _fix_and_vendors(audit, zone, domain)
    assert "Mailchimp" in vendors
    assert "servers.mcsv.net" not in fix, fix
    assert "Detected services" not in fix, fix


def test_proton_mail_gets_its_include_now_that_the_name_matches(audit):
    domain = "pm.test"
    zone = _zone(domain, "v=spf1 ip4:203.0.113.0/24 -all",
                 [(10, "mail.protonmail.ch"), (20, "mailsec.protonmail.ch")],
                 {"_spf.protonmail.ch": {"TXT": ["v=spf1 ip4:185.70.40.0/24 ~all"]}})
    fix, vendors = _fix_and_vendors(audit, zone, domain)
    assert "Proton Mail" in vendors
    assert "Proton Mail" in fix and "include:_spf.protonmail.ch" in fix, fix


def test_barracuda_gets_the_ess_include_its_docs_give(audit):
    domain = "bc.test"
    zone = _zone(domain, "v=spf1 ip4:203.0.113.0/24 -all",
                 [(10, "d123.ess.barracudanetworks.com")],
                 {"spf.ess.barracudanetworks.com": {"TXT": ["v=spf1 ip4:209.222.80.0/21 ~all"]}})
    fix, vendors = _fix_and_vendors(audit, zone, domain)
    assert "Barracuda" in vendors
    assert "include:spf.ess.barracudanetworks.com" in fix, fix


def test_an_older_zoho_include_already_covers_zoho(audit):
    domain = "zo.test"
    zone = _zone(domain, "v=spf1 include:zoho.com -all", [(10, "mx.zoho.com")],
                 {"zoho.com": {"TXT": ["v=spf1 ip4:136.143.188.0/24 ~all"]}})
    fix, vendors = _fix_and_vendors(audit, zone, domain)
    assert "Zoho Mail" in vendors
    assert "zohomail.com" not in fix, fix
    assert "Detected services" not in fix, fix


def test_every_key_is_a_name_the_vendor_panel_can_produce():
    names = (set(vendor_patterns.SPF_INCLUDE_VENDORS.values())
             | set(vendor_patterns.MX_VENDORS.values())
             | set(vendor_patterns.DKIM_CNAME_VENDORS.values())
             | set(vendor_patterns.DKIM_SELECTOR_VENDORS.values()))
    assert set(VENDOR_SPF_INCLUDES) <= names, set(VENDOR_SPF_INCLUDES) - names


def test_no_include_for_a_vendor_whose_footprint_needs_none():
    for name in ("Mailchimp", "Postmark", "SparkPost", "Brevo", "SendGrid",
                 "Amazon SES", "HubSpot", "Salesforce", "Zendesk", "Freshdesk", "Intercom"):
        assert name not in VENDOR_SPF_INCLUDES, name


def test_a_hosted_spf_record_gets_no_include_suggestion():
    """glossier.com publishes only a Valimail macro include; the card said
    to add include:_spf.google.com to it."""
    import audit_engine
    m = audit_engine._spf_managed_by
    assert m("v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all") == "Valimail"
    assert m("v=spf1 +include:acme.test.smart.ondmarc.com -all") == "Red Sift OnDMARC"
    assert m("v=spf1 redirect=%{ir}._spf.example.net") == "a macro include"
    assert m("v=spf1 include:_spf.google.com ~all") is None


def test_only_authorizing_terms_make_a_record_hosted():
    """-include: excludes, and nothing after all is evaluated (review on #189)."""
    m = __import__("audit_engine")._spf_managed_by
    assert m("v=spf1 -include:_spf.vali.email include:_spf.google.com ~all") is None
    assert m("v=spf1 ~include:%{i}._spf.example.net -all") is None
    assert m("v=spf1 include:_spf.google.com -all include:_spf.vali.email") is None
