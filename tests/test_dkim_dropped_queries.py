"""DKIM discovery against nameservers that drop queries (Doc 72).

Measured from the droplet on 2026-09-28: suckless.org's nameservers answer
the first few NXDOMAIN probes of a burst and drop the rest. 162 of the 197
selector probes timed out, the zone kept dropping for a few seconds after,
and fingerprinting and subdomain probing then ran to their own timeouts:
28 s with the sweep, 6 s with a named selector and no sweep. The card also
said "Checked 197 common selectors, no public key found" when most of those
lookups never got an answer.

The generic fallback now stops once a wave shows DKIM_DROP_THRESHOLD
unanswered probes, and the card reads not confirmed. These pin that, and
that the selectors which must still be found are found: the ones SPF points
at (Mailchimp k2 and k3, Proton's three) and any selector the user types.
"""
import os
import sys
import threading
import time

import dns.exception

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
from test_dkim_discovery_starvation import DKIM_RECORD
import audit_engine
import spf_intelligence
from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, ESP_SELECTORS, GENERIC_SELECTORS
from spf_intelligence import _selectors_from_vendors, detect_vendors_from_spf

DOMAIN = "drops.test"
DROP_DELAY = 0.5  # stands in for the resolver lifetime a dropped probe waits out


class _DroppingZone(FakeZone):
    """Answers every _domainkey name that holds a record and drops the rest
    after the first few, the way response rate limiting on NXDOMAIN does."""

    def __init__(self, *args, answer_first=10, **kwargs):
        super().__init__(*args, **kwargs)
        self._answer_first = answer_first
        self._lock = threading.Lock()
        self.nx_answered = 0
        self.dropped = 0

    def resolve(self, name, rdtype="A", *args, **kwargs):
        key = self._key(name, rdtype)
        if "._domainkey." in key[0] and key not in self._records:
            with self._lock:
                drop = self.nx_answered >= self._answer_first
                if drop:
                    self.dropped += 1
                else:
                    self.nx_answered += 1
            if drop:
                self.queries.append(key)
                time.sleep(DROP_DELAY)
                raise dns.exception.Timeout()
        return super().resolve(name, rdtype, *args, **kwargs)


def _zone(spf="v=spf1 mx -all", keys=(), **kwargs):
    records = {
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": [spf],
            "A": ["203.0.113.70"],
            "NS": [f"ns1.{DOMAIN}"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.71"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    }
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    return _DroppingZone(records, **kwargs)


def _dkim_card(result):
    return next(c for c in result["checks"] if c["name"] == "DKIM")


def _found(card):
    return {k["selector"] for k in (card.get("dkim_deep") or {}).get("keys", [])}


def _dkim_queries(zone):
    # _aprf._domainkey names are the APRF check's own few lookups, not
    # DKIM selector probes.
    return [q for q in zone.queries if "._domainkey." in q[0] and "_dkimwildcardtest" not in q[0]
            and "_aprf._domainkey." not in q[0]]


def test_a_zone_that_drops_queries_finishes_in_budget_and_reads_not_confirmed():
    zone = _zone()
    start = time.monotonic()
    with fake_dns(zone):
        result = audit_engine.run_full_audit(DOMAIN, scope="complete")
    elapsed = time.monotonic() - start
    card = _dkim_card(result)

    assert elapsed < 10, f"audit took {elapsed:.1f}s against a dropping zone"
    # The priority wave (the capped 40 plus ESP_SELECTORS) runs in full,
    # the generic fallback never starts.
    probed = len(_dkim_queries(zone))
    assert probed <= 40 + len(ESP_SELECTORS), f"{probed} selector probes; the sweep did not stop"
    assert card["status"] == "unavailable", card["verdict"]
    assert card["pill_label"] == "Not confirmed"
    assert card["verdict"] == "DKIM discovery did not finish"
    assert "stopped answering" in card["explanation"]
    text = " ".join(d["text"] for d in card["details"])
    assert "got no answer" in text
    # Not absent, and not a claim about the domain's DKIM.
    assert card["status"] not in ("fail", "absent")
    assert "no public key found" not in text
    assert "no DKIM" not in card["explanation"]


def test_the_raw_result_separates_unanswered_from_checked():
    zone = _zone(answer_first=10)
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, "v=spf1 mx -all")
    assert raw["timed_out"] is True
    assert raw["stopped_reason"] == "queries_dropped"
    assert raw["unanswered_count"] >= spf_intelligence.DKIM_DROP_THRESHOLD
    # tested_count counts answers only; the canary took one of the ten.
    assert raw["tested_count"] + raw["unanswered_count"] == len(_dkim_queries(zone))
    assert raw["tested_count"] <= 10


def test_a_zone_that_answers_still_gets_the_whole_generic_sweep():
    """No drops, no key: every generic selector is still probed."""
    zone = _zone(answer_first=10_000)
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, "v=spf1 mx -all")
    probed = {q[0].split("._domainkey.")[0] for q in _dkim_queries(zone)}
    assert {s.lower() for s in GENERIC_SELECTORS} <= probed
    assert not raw.get("timed_out")
    assert raw["unanswered_count"] == 0


def test_mailchimp_k2_and_k3_are_found_while_the_zone_drops():
    zone = _zone(spf="v=spf1 include:servers.mcsv.net -all", keys=("k2", "k3"), answer_first=0)
    with fake_dns(zone):
        result = audit_engine.run_full_audit(DOMAIN, scope="complete")
    card = _dkim_card(result)
    assert {"k2", "k3"} <= _found(card), card["verdict"]
    assert card["status"] in ("pass", "warn")


def test_proton_selectors_are_found_while_the_zone_drops():
    zone = _zone(spf="v=spf1 include:_spf.protonmail.ch -all",
                 keys=("protonmail", "protonmail2", "protonmail3"), answer_first=0)
    with fake_dns(zone):
        result = audit_engine.run_full_audit(DOMAIN, scope="complete")
    assert {"protonmail", "protonmail2", "protonmail3"} <= _found(_dkim_card(result))


def test_proton_without_a_hint_is_still_reached_by_the_chunked_sweep():
    zone = _zone(keys=("protonmail",), answer_first=10_000)
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, "v=spf1 mx -all")
    assert "protonmail" in {s["selector"] for s in raw["found_selectors"]}


def test_a_typed_selector_is_found_while_the_zone_drops():
    zone = _zone(keys=("custom2026",), answer_first=0)
    with fake_dns(zone):
        result = audit_engine.run_full_audit(DOMAIN, dkim_selector="custom2026", scope="complete")
    card = _dkim_card(result)
    assert "custom2026" in _found(card) or card["status"] == "pass", card["verdict"]
    assert card["status"] in ("pass", "warn")


def test_mailchimp_selectors_lead_the_probe_order():
    """Reachability, not membership: k2 and k3 go out in the first wave."""
    vendors = detect_vendors_from_spf("v=spf1 include:servers.mcsv.net -all")
    order = _selectors_from_vendors(vendors, COMPREHENSIVE_DKIM_SELECTORS)[:40]
    assert order[:3] == ["k1", "k2", "k3"]


def test_answered_selectors_holds_only_names_that_got_an_answer():
    """The vendor panel says a sender's key is missing only at names listed
    here, so a dropped probe must not appear in it."""
    zone = _zone(answer_first=10)
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(DOMAIN, "v=spf1 mx -all")
    assert len(raw["answered_selectors"]) == raw["tested_count"]
    dropped = {q[0].split("._domainkey.")[0] for q in _dkim_queries(zone)} - set(raw["answered_selectors"])
    assert len(dropped) == raw["unanswered_count"]
