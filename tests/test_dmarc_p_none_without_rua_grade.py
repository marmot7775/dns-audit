"""A valid p=none record without rua is amber everywhere, never red.

intelligentsia.com publishes "v=DMARC1; p=none" and nothing else. The DMARC
card graded it amber "Warning", while the RFC 9989 readiness tile above it read
red "Action needed" and the tag breakdown said "Misconfigured: This record has
critical issues". The record is valid; it blocks nothing and reports nothing.
The breakdown now says that under "Needs Attention", and the readiness tile is
never a more severe colour than the DMARC card.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import result_transformer
from test_verdict_names_broken_records import _zone

DOMAIN = "p-none-no-rua.test"
RUA = f"rua=mailto:d@{DOMAIN}"
SEVERITY = {"green": 0, "blue": 0, "neutral": 0, "amber": 1, "red": 2}
CARD_SEVERITY = {"pass": 0, "absent": 0, "unavailable": 0, "warn": 1, "fail": 2}


def _run(audit, dmarc):
    result = audit(_zone(dmarc, "v=spf1 mx -all", domain=DOMAIN), DOMAIN, dkim_selector="s1")
    card = {c["name"]: c for c in result["checks"]}["DMARC"]
    return result, card


def test_p_none_without_rua_is_needs_attention_not_misconfigured(audit):
    result, card = _run(audit, "v=DMARC1; p=none")
    health = card["tag_breakdown"]["health"]

    assert card["status"] == "warn"
    assert health["status"] == "attention"
    assert health["label"] == "Needs Attention"
    assert health["color"] == "amber"
    assert health["summary"] == "This record blocks nothing and reports nothing."
    assert "Misconfigured" not in health["label"]
    assert "critical" not in health["summary"]
    # No config warning on this record is graded critical, which the web
    # breakdown draws with the fail icon.
    assert not [w for w in card["tag_breakdown"]["config_warnings"]
                if w["level"] == "critical"]

    tile = result["executive_summary"]["dmarcbis_readiness"]
    assert tile["color"] == "amber", tile
    assert tile["label"] != "Action needed"


def test_p_none_without_rua_is_not_said_to_block_anything(audit):
    result, _ = _run(audit, "v=DMARC1; p=none")
    assert "blocks spoofed email" not in result["executive_summary"]["verdict"]


def test_the_rua_row_is_still_in_the_plan(audit):
    result, _ = _run(audit, "v=DMARC1; p=none")
    actions = [i["action"] for i in result["security_roadmap"]["items"]]
    assert "Add aggregate reporting (rua=)" in actions


def test_p_none_with_rua_is_still_monitoring(audit):
    _, card = _run(audit, f"v=DMARC1; p=none; {RUA}")
    assert card["tag_breakdown"]["health"]["status"] == "monitoring"


def test_readiness_tile_is_never_redder_than_the_card(audit):
    # sp=none under p=reject is a critical config warning and a
    # "Misconfigured" health verdict, on a card graded amber.
    for record in ("v=DMARC1; p=none",
                   f"v=DMARC1; p=reject; sp=none; {RUA}",
                   f"v=DMARC1; p=none; sp=reject; {RUA}"):
        result, card = _run(audit, record)
        tile = result["executive_summary"]["dmarcbis_readiness"]
        assert SEVERITY[tile["color"]] <= CARD_SEVERITY[card["status"]], (record, tile, card["status"])


def test_a_failing_card_keeps_a_red_tile():
    checks = [{"name": "DMARC", "status": "fail", "pill_label": "Missing"}]
    es = result_transformer.build_executive_summary(checks, {"items": []})
    assert es["dmarcbis_readiness"] == {"label": "Action needed", "color": "red"}
