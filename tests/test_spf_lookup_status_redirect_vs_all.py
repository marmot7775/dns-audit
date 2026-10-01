"""The same SPF lookup count gets the same card status however the record ends.

A record at exactly 10 lookups was warn when it ended in redirect= and pass
when it ended in -all or ~all. transform_spf forced pass only for records
ending in an all mechanism, so a redirect= record fell through to the engine
status, which the "at the 10-lookup limit" warning had set to warn.
spf_recursive.spf_lookup_band is the one rule for the count (ok 0 to 8, near
9 to 10, over above 10), and it now judges both shapes the same way: near is
a warning detail on a passing card, over is a fail.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOMAIN = "end.test"
TARGET = f"_spf.{DOMAIN}"


def _zone(lookups, redirect):
    """An SPF record costing `lookups` lookups. The redirect= version spends
    one of them on the redirect itself and the rest on a: terms."""
    if redirect:
        terms = [f"a:h{i}.{DOMAIN}" for i in range(lookups - 1)] + [f"redirect={TARGET}"]
    else:
        terms = [f"a:h{i}.{DOMAIN}" for i in range(lookups)] + ["-all"]
    zone = {
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 " + " ".join(terms)],
            "A": ["203.0.113.1"],
        },
        TARGET: {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.2"]},
    }
    for i in range(lookups):
        zone[f"h{i}.{DOMAIN}"] = {"A": ["203.0.113.3"]}
    return zone


def _spf_card(result):
    return next(c for c in result["checks"] if c["name"] == "SPF")


@pytest.mark.parametrize("lookups,expected", [(8, "pass"), (9, "pass"), (10, "pass"), (11, "fail")])
def test_status_does_not_depend_on_how_the_record_ends(audit, lookups, expected):
    with_all = _spf_card(audit(_zone(lookups, redirect=False), DOMAIN))
    with_redirect = _spf_card(audit(_zone(lookups, redirect=True), DOMAIN))

    assert with_all["spf_deep"]["lookup_count"] == lookups
    assert with_redirect["spf_deep"]["lookup_count"] == lookups
    assert with_all["status"] == with_redirect["status"] == expected, (
        with_all["status"], with_redirect["status"])

    if lookups in (9, 10):
        # Near the limit still shows as a warning on both cards.
        for card in (with_all, with_redirect):
            assert any(d["type"] == "warning" and "lookup" in d["text"].lower()
                       for d in card["details"]), card["details"]
