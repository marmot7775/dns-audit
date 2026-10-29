"""The whole vendor sweep goes out in the first wave, whatever SPF says.

Doc 93 unioned ESP_SELECTORS into the priority wave because ESPs usually
send from their own Return-Path domain, so their include is often absent
from SPF, and a key reached only through an SPF hint was missed. Doc 105
made Sendermap's catalog the vendor dictionary: its whole sweep, plus
LOCAL_SELECTORS, is the priority wave, so every vendor name is probed on
every domain. These assert reachability, not membership, the same as
test_proton_selectors_reachable.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import generic_selectors
from conftest import FakeZone, fake_dns
from generic_selectors import LOCAL_SELECTORS
from sendermap_adapter import catalog
from test_dkim_discovery_starvation import DKIM_RECORD
import spf_intelligence

DOMAIN = "esp.test"
NO_VENDOR_SPF = "v=spf1 ip4:203.0.113.80 -all"


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


def test_the_whole_sweep_is_the_first_wave(monkeypatch):
    """No vendor in SPF or MX. With the generic fallback emptied, whatever
    is probed is the first wave and nothing else."""
    monkeypatch.setattr(generic_selectors, "GENERIC_SELECTORS", [])
    zone = _zone()
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=[f"mail.{DOMAIN}"])
    assert raw["discovery_method"] == "blind_loop"
    expected = {s.lower() for s in (*catalog().probe_selectors, *LOCAL_SELECTORS)}
    assert _probed(zone) == expected


def test_a_domain_whose_only_key_is_k1_is_found():
    zone = _zone(keys=("k1",))
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=[f"mail.{DOMAIN}"])
    assert [s["selector"] for s in raw["found_selectors"]] == ["k1"]
    assert not raw.get("timed_out")


def test_google_from_mx_and_k1_are_both_found():
    zone = _zone(keys=("google", "k1"), mx="smtp.google.com")
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, NO_VENDOR_SPF, mx_hosts=["smtp.google.com"])
    assert raw["discovery_method"] == "mx_intelligent"
    assert {s["selector"] for s in raw["found_selectors"]} == {"google", "k1"}
