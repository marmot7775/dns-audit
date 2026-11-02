"""An MX only vendor gets a conditional SPF note, not "add this include"
(issue 270).

An MX says mail is delivered at a vendor, not that the vendor sends as the
domain. A domain that receives at Microsoft 365 and sends through another
service was told to add Microsoft's include to its SPF record, spending a
lookup on a sender that is not one. The vendor stays in use (it receives
mail); only the recommendation changes. The plain wording applies when there
is an outbound signal: a DKIM selector for the vendor, an existing include
elsewhere in the tree, or a sender map hit (a return path or tracking CNAME).
"""
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _format_vendors, _receiving_only  # noqa: E402
from test_spf_suggestion_vendor_footprints import DKIM_KEY  # noqa: E402

M365_MX = [(0, "mx-m365-test.mail.protection.outlook.com")]
M365_INCLUDE = "include:spf.protection.outlook.com"
OTHER_SPF = {"spf.protection.outlook.com": {"TXT": ["v=spf1 ip4:40.92.0.0/15 -all"]},
             "_spf.sender.test": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]}}


def _zone(domain, extra=None, spf="v=spf1 include:_spf.sender.test -all"):
    zone = {
        domain: {"TXT": [spf], "MX": M365_MX, "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
        **OTHER_SPF,
    }
    zone.update(extra or {})
    return zone


def _run(audit, zone, domain):
    result = audit(zone, domain, scope="email_security")
    card = next(c for c in result["checks"] if c["name"] == "SPF")
    vendors = {v["name"]: v for v in result["vendors"]}
    return card.get("fix") or "", vendors


def test_a_domain_that_receives_at_microsoft_365_and_sends_elsewhere(audit):
    domain = "recv.test"
    fix, vendors = _run(audit, _zone(domain), domain)
    m365 = vendors["Microsoft 365"]
    # Still in use: it receives the domain's mail.
    assert m365["tier"] == "In use"
    assert m365["detected_via"] == "inbound"
    # The SPF card: conditional, no suggested record, no plain "detected" line.
    assert "If this service also sends your mail" in fix, fix
    assert M365_INCLUDE in fix
    assert "Suggested SPF record" not in fix, fix
    assert "Detected services" not in fix, fix
    # The vendor line says the same.
    assert m365["missing"], m365
    assert all("If it also sends your mail, its include belongs in your SPF record" in m
               for m in m365["missing"] if "SPF" in m), m365["missing"]
    assert not any(m.startswith("No SPF record") for m in m365["missing"])


def test_a_dkim_selector_is_an_outbound_signal(audit):
    """Google Workspace receives at the MX and signs with its own selector."""
    domain = "dkim.test"
    zone = _zone(domain, {f"google._domainkey.{domain}": {"TXT": [DKIM_KEY]},
                          "_spf.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"]}})
    zone[domain]["MX"] = [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]
    fix, vendors = _run(audit, zone, domain)
    assert "outbound" in (vendors["Google Workspace"]["detected_via"] or "")
    assert "If this service also sends your mail" not in fix, fix
    assert "Google Workspace" in fix and "include:_spf.google.com" in fix, fix


def test_an_include_elsewhere_in_the_tree_covers_it_and_says_nothing(audit):
    domain = "tree.test"
    zone = _zone(domain, spf="v=spf1 include:_spf.sender.test include:spf.protection.outlook.com -all")
    fix, _ = _run(audit, zone, domain)
    assert "Microsoft 365" not in fix, fix


def test_receiving_only_is_inbound_claims_alone():
    assert _receiving_only({"detected_via": "inbound"})
    assert not _receiving_only({"detected_via": "outbound + inbound"})
    assert not _receiving_only({"detected_via": "outbound"})
    assert not _receiving_only({"detected_via": None})


def test_format_vendors_leaves_other_missing_records_alone():
    """Only the SPF item turns conditional; a required DKIM record stays."""
    from datetime import datetime, timezone

    from sendermap.model import (Claim, Evidence, Kind, Need, Role, Run, SenderMap, Service,
                                 Setup, SetupItem, State, Tier)
    at = datetime(2026, 11, 1, tzinfo=timezone.utc)
    claim = Claim("Microsoft 365", Kind.MX, "x.test", Evidence("x.test", "MX", "0 x.mail.protection.outlook.com", at))
    setup = Setup("Microsoft 365", "x.test", (
        SetupItem("spf", Need.REQUIRED, State.MISSING, (), "TXT at x.test", "no include"),
        SetupItem("dkim", Need.REQUIRED, State.MISSING, (), "CNAME at selector1._domainkey.x.test", "no key"),
    ), False)
    svc = Service("Microsoft 365", "Mailbox", Tier.IN_USE, Role.SENDER, (claim,), (setup,))
    rows = _format_vendors(SenderMap("x.test", (svc,), Run(at, 0.1, 1, "system")))
    missing = rows[0]["missing"]
    assert missing[0].startswith("Microsoft 365 receives your mail. If it also sends your mail")
    assert missing[1].startswith("No DKIM for Microsoft 365")
