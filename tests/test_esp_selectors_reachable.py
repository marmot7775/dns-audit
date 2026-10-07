"""ESP selectors go out in the first wave, whatever SPF says (Doc 93).

Commit 8675be4 cut smart_dkim_check's cap from 200 to 40. The 40-name
slice ends inside OTHER_EMAIL_PROVIDERS, so the marketing, transactional,
CRM and support blocks (k1 to k6, s1, s2, mandrill, zendesk1 and the rest)
were probed only when the vendor's include appeared in SPF. ESPs usually
send from their own Return-Path domain, so the include is often absent. A
domain on Google plus Mailchimp got a DKIM card listing only the Google
key, and a domain whose only signer was an ESP was told no DKIM was found.

ESP_SELECTORS is now unioned into the priority wave on top of the cap, the
way GENERIC_SELECTORS was for "default". These assert reachability, not
membership, the same as test_proton_selectors_reachable.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import comprehensive_selectors
from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, ESP_SELECTORS
from conftest import FakeZone, fake_dns
from test_dkim_discovery_starvation import DKIM_RECORD
import spf_intelligence

DOMAIN = "esp.test"
NO_VENDOR_SPF = "v=spf1 ip4:203.0.113.80 -all"
CAP = 40  # smart_dkim_check's max_selectors default


def _zone(keys=(), mx=f"mail.{DOMAIN}", spf=NO_VENDOR_SPF):
    records = {
        DOMAIN: {"TXT": [spf], "MX": [(10, mx)]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.80"]},
    }
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    return FakeZone(records)


def _probed(zone):
    return {
        q[0].split("._domainkey.")[0]
        for q in zone.queries
        if "._domainkey." in q[0] and "_dkimwildcardtest" not in q[0]
    }


def test_every_esp_selector_is_in_the_first_wave(monkeypatch):
    """No vendor in SPF or MX. With the generic fallback emptied, whatever
    is probed is the first wave and nothing else."""
    monkeypatch.setattr(comprehensive_selectors, "GENERIC_SELECTORS", [])
    zone = _zone()
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=[f"mail.{DOMAIN}"])
    assert raw["vendors_detected"] == []
    probed = _probed(zone)
    missing = [s for s in ESP_SELECTORS if s.lower() not in probed]
    assert not missing, f"not in the first wave without a vendor hint: {missing}"
    # On top of the cap, not inside it, and deduplicated against it.
    expected = set(COMPREHENSIVE_DKIM_SELECTORS[:CAP]) | set(ESP_SELECTORS)
    assert probed == {s.lower() for s in expected}


def test_the_cap_alone_would_not_reach_them():
    """Guards the reasoning: these names sit past the 40-name slice."""
    head = set(COMPREHENSIVE_DKIM_SELECTORS[:CAP])
    assert {"k1", "s1", "mandrill", "zendesk1"}.isdisjoint(head)


def test_a_domain_whose_only_key_is_k1_is_found():
    zone = _zone(keys=("k1",))
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=[f"mail.{DOMAIN}"])
    assert [s["selector"] for s in raw["found_selectors"]] == ["k1"]
    assert not raw.get("timed_out")


def test_google_from_mx_and_k1_are_both_found():
    zone = _zone(keys=("google", "k1"), mx="aspmx.l.google.com")
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=["aspmx.l.google.com"])
    assert raw["discovery_method"] == "mx_intelligent"
    assert {s["selector"] for s in raw["found_selectors"]} == {"google", "k1"}
