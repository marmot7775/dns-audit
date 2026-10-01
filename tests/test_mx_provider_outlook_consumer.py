"""outlook.com's MX hosts are consumer Outlook.com, not Microsoft 365 GCC.

outlook.com, hotmail.com, live.com and msn.com all deliver to
*.olc.protection.outlook.com, the consumer Outlook.com service. The MX card
labelled them "Microsoft 365 (GCC)", the US government cloud tenancy, which
none of them are.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mx_check import _detect_provider

DOMAIN = "outlook.test"


def test_olc_hosts_are_labelled_consumer_outlook():
    assert _detect_provider("outlook-com.olc.protection.outlook.com.") == "Outlook.com (consumer)"
    assert _detect_provider("hotmail-com.olc.protection.outlook.com") == "Outlook.com (consumer)"


def test_tenant_hosts_are_still_microsoft_365():
    assert _detect_provider("contoso-com.mail.protection.outlook.com") == "Microsoft 365"


def test_mx_card_names_the_consumer_service(audit):
    mx = "outlook-com.olc.protection.outlook.com"
    zone = {
        DOMAIN: {"MX": [(5, mx)], "TXT": ["v=spf1 include:spf.protection.outlook.com -all"]},
        mx: {"A": ["52.101.0.1"]},
    }
    result = audit(zone, DOMAIN, scope="transport")
    card = next(c for c in result["checks"] if c["name"] == "MX Records")
    assert "Outlook.com (consumer)" in card["verdict"], card["verdict"]
    assert "GCC" not in str(card)
