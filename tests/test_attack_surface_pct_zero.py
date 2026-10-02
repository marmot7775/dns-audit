"""pct=0 weakens the subdomain routes too.

london.gov.uk publishes p=quarantine; pct=0. The direct route already read
exposed, but the subdomain and non-existent subdomain routes read "partial"
from the policy alone. RFC 7489 section 6.6.4 applies pct to whichever policy
is selected, so at pct=0 quarantine becomes none and reject becomes
quarantine on every route.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOMAIN = "pctzero.test"


def _zone(record):
    return {
        DOMAIN: {"MX": [(10, f"mx.{DOMAIN}")], "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.1"]},
        f"mx.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"_dmarc.{DOMAIN}": {"TXT": [record]},
    }


def _routes(result):
    card = next(c for c in result["checks"] if c["name"] == "DMARC")
    vectors = (card.get("attack_surface") or {}).get("vectors") or []
    return {v["name"]: v["status"] for v in vectors}


def test_quarantine_at_pct_zero_exposes_every_route(audit):
    routes = _routes(audit(_zone(f"v=DMARC1; p=quarantine; pct=0; rua=mailto:d@{DOMAIN}"), DOMAIN))
    assert routes["Subdomain Spoofing"] == "exposed", routes
    assert routes["Non-Existent Subdomain Spoofing"] == "exposed", routes


def test_reject_at_pct_zero_is_quarantine_on_subdomains(audit):
    routes = _routes(audit(_zone(f"v=DMARC1; p=reject; pct=0; rua=mailto:d@{DOMAIN}"), DOMAIN))
    assert routes["Subdomain Spoofing"] == "partial", routes
    assert routes["Non-Existent Subdomain Spoofing"] == "partial", routes


def test_full_pct_is_unchanged(audit):
    routes = _routes(audit(_zone(f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"), DOMAIN))
    assert routes["Subdomain Spoofing"] == "protected", routes
