"""On a tie in tier and status, the row nearest to spoofing protection leads.

london.gov.uk publishes p=quarantine; pct=0 and a 1024-bit DKIM key. Both
plan rows are high and both cards amber, and the weak-key row was added
first, so "Two of your email signing keys are shorter than recommended. They
still work." led Do these first, ahead of a policy that applies to none of
the failing mail. Ties now break DMARC, then SPF, then DKIM, then the rest.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_spf_permerror_outranks_weak_dkim import _rsa_key_record  # noqa: E402

DOMAIN = "ldn.test"


def test_pct_zero_row_leads_a_weak_dkim_key(audit):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.1"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=quarantine; pct=0; rua=mailto:d@{DOMAIN}"]},
        f"default._domainkey.{DOMAIN}": {"TXT": [_rsa_key_record(1024)]},
    }
    result = audit(zone, DOMAIN)
    first = result["executive_summary"]["do_first"]
    protocols = [d["protocol"] for d in first]
    assert "DMARC" in protocols and "DKIM" in protocols, first
    assert protocols.index("DMARC") < protocols.index("DKIM"), first
