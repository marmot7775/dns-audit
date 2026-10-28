"""A selector in a dictionary is not the same as a selector we ever probe.

Doc 17 reported that the 193-selector probe "missed all three" Proton
selectors. protonmail was in the old master list, at index 46 of 1128, past
the 40-name cap, so the entry did nothing and a membership test would have
passed. Since Doc 105 the vendor dictionary is Sendermap's catalog and its
whole sweep is the priority wave, so these assert that the Proton names are
probed, with and without Proton's SPF include.

Sourcing: verified live on proton.me on 2026-09-08. All three names exist as
CNAMEs into domains.proton.ch.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sendermap.selectors import probe_order, rank_rules

from generic_selectors import GENERIC_SELECTORS, LOCAL_SELECTORS
from sendermap_adapter import catalog
from spf_intelligence import parse_spf_record

PROTON_SPF = "v=spf1 include:_spf.protonmail.ch ~all"
PROTON_SELECTORS = catalog().selectors_of("Proton Mail")


def _first_wave(spf):
    """Exactly the priority wave smart_dkim_check builds."""
    ranked = rank_rules(catalog().rules, [], parse_spf_record(spf))
    return set(probe_order(ranked, (*catalog().probe_selectors, *LOCAL_SELECTORS)))


def test_the_catalog_knows_the_three_proton_names():
    assert set(PROTON_SELECTORS) == {"protonmail", "protonmail2", "protonmail3"}


def test_proton_selectors_are_probed_with_the_include_present():
    missing = PROTON_SELECTORS - _first_wave(PROTON_SPF)
    assert not missing, f"not probed even with Proton's own SPF include: {missing}"


def test_proton_selectors_are_probed_with_no_recognised_spf():
    """A domain can use Proton without that include appearing in its SPF."""
    missing = PROTON_SELECTORS - _first_wave("v=spf1 -all")
    assert not missing, f"not probed without a vendor hint: {missing}"


def test_the_include_ranks_proton_only_if_the_catalog_gives_hints():
    """Sendermap 0.1.2 gives Proton Mail no hints, so the include moves
    nothing; the names are in the sweep regardless, which is what matters.
    If the catalog gains hints, the include must match them."""
    rules = [r for r in catalog().rules if r.vendor == "Proton Mail"]
    assert rules
    for rule in rules:
        if rule.hints.spf:
            assert rule.hints.matches(frozenset(), frozenset({"_spf.protonmail.ch"}))
    assert set(PROTON_SELECTORS) <= {s.lower() for s in catalog().probe_selectors}


def test_the_generic_fallback_still_carries_them():
    assert set(PROTON_SELECTORS) <= set(GENERIC_SELECTORS)
