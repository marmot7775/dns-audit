"""Under Email Deliverability a p=none card passes only with usable reporting.

A published p=none whose rua has no mailto: is not reporting (receivers send
nothing to it), and a subdomain inheriting p=none from a parent without a rua
must grade like the parent's own record, amber.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_verdict_names_broken_records import _zone

DOMAIN = "pnone-rua.test"
SUB = f"sub.{DOMAIN}"


def _card(result):
    return {c["name"]: c for c in result["checks"]}["DMARC"]


def _published(audit, dmarc):
    zone = _zone(dmarc, "v=spf1 mx -all", domain=DOMAIN)
    return _card(audit(zone, DOMAIN, scope="deliverability", dkim_selector="s1"))


def _inherited(audit, parent_dmarc):
    zone = _zone(parent_dmarc, "v=spf1 mx -all", domain=DOMAIN, extra={
        SUB: {"A": ["203.0.113.20"], "TXT": ["v=spf1 mx -all"]},
    })
    return _card(audit(zone, SUB, scope="deliverability", dkim_selector="s1"))


def test_published_p_none_with_mailto_rua_passes(audit):
    assert _published(audit, f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}")["status"] == "pass"


def test_published_p_none_with_bare_rua_address_is_not_a_pass(audit):
    card = _published(audit, f"v=DMARC1; p=none; rua=d@{DOMAIN}")
    assert card["status"] == "warn", card["status"]


def test_inherited_p_none_without_rua_is_not_a_pass(audit):
    card = _inherited(audit, "v=DMARC1; p=none")
    assert card["status"] == "warn", card["status"]


def test_inherited_p_none_with_mailto_rua_passes(audit):
    card = _inherited(audit, f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}")
    assert card["status"] == "pass", card["status"]
