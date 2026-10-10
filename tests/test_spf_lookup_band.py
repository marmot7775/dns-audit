"""The SPF lookup count is judged by one rule on every surface.

The card, the plan, the anomaly list, the deliverability summary and the
optimization list each used their own threshold. At 8 lookups the card said
"well within the 10-lookup limit" and the plan listed a HIGH row whose impact
described a PermError the domain was not in. At 11 the deliverability summary
said the record was near the limit, because it found the word "at" inside
"satisfy".

spf_recursive.spf_lookup_band is the rule: ok 0 to 8, near 9 to 10, over
above 10. Each test runs the real audit against a declared zone and asserts
on the output the user sees.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spf_recursive import spf_lookup_band  # noqa: E402

DOMAIN = "band.test"


def _zone(lookups):
    """An SPF record costing exactly `lookups` lookups, one a: per lookup.

    Every a: target resolves, so there are no void lookups to muddy the card.
    """
    zone = {
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 " + " ".join(f"a:h{i}.{DOMAIN}" for i in range(lookups)) + " -all"],
            "A": ["203.0.113.1"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.2"]},
    }
    for i in range(lookups):
        zone[f"h{i}.{DOMAIN}"] = {"A": ["203.0.113.3"]}
    return zone


_RESULTS = {}


@pytest.fixture
def run(audit):
    def _run(lookups):
        if lookups not in _RESULTS:
            _RESULTS[lookups] = audit(_zone(lookups), DOMAIN)
        return _RESULTS[lookups]
    return _run


def _spf_card(result):
    return next(c for c in result["checks"] if c["name"] == "SPF")


def _lookup_rows(result):
    return [i for i in result["security_roadmap"]["items"]
            if i.get("protocol") == "SPF" and "SPF lookups" in i["action"]]


def _lookup_details(card):
    return [d for d in card["details"] if "lookup" in d["text"].lower()]


def _lookup_anomalies(result):
    return [a for a in result.get("anomalies", [])
            if "lookup" in (a["title"] + a["description"]).lower()]


def test_spf_band_is_near_from_9_and_over_past_10():
    assert [spf_lookup_band(n) for n in (0, 8, 9, 10, 11, 25)] == [
        "ok", "ok", "near", "near", "over", "over"]
    # A count that is only a floor is never ok, and a floor past 10 is over.
    assert spf_lookup_band(3, indeterminate=True) == "unknown"
    assert spf_lookup_band(9, indeterminate=True) == "near"
    assert spf_lookup_band(11, indeterminate=True) == "over"


def test_8_lookups_is_ok_everywhere(run):
    result = run(8)
    card = _spf_card(result)

    assert card["status"] == "pass"
    assert [d["type"] for d in _lookup_details(card)] == ["good"]
    assert "well within the 10-lookup limit" in _lookup_details(card)[0]["text"]
    assert _lookup_rows(result) == []
    assert not any("lookup" in i["action"].lower() for i in result["security_roadmap"]["items"])
    assert _lookup_anomalies(result) == []
    assert "lookup" not in result["executive_summary"]["deliverability_summary"]
    assert card["spf_deep"]["optimizations"] == []


@pytest.mark.parametrize("lookups", [9, 10])
def test_9_and_10_lookups_are_near(run, lookups):
    result = run(lookups)
    card = _spf_card(result)

    assert card["status"] == "pass"
    assert [d["type"] for d in _lookup_details(card)] == ["warning"]

    rows = _lookup_rows(result)
    assert len(rows) == 1, rows
    assert rows[0]["priority"] == "medium"
    assert rows[0]["action"] == f"Free up SPF lookups ({lookups}/10)"
    # A risk, not a current failure: the PermError is conditional on going
    # past 10, and the row says what would take it there.
    impact = rows[0]["impact"]
    assert impact.startswith("One more include, a, or mx mechanism would take this past 10.")
    assert not impact.startswith("Past 10 lookups")

    assert _lookup_anomalies(result) == []
    assert "near the 10-lookup limit" in result["executive_summary"]["deliverability_summary"]
    assert len(card["spf_deep"]["optimizations"]) == 1


def test_11_lookups_is_over(run):
    result = run(11)
    card = _spf_card(result)

    assert card["status"] == "fail"
    rows = _lookup_rows(result)
    assert len(rows) == 1, rows
    assert rows[0]["priority"] == "critical"
    assert rows[0]["impact"].startswith("Past 10 lookups, receivers return PermError.")
    assert _lookup_anomalies(result) == []
    summary = result["executive_summary"]["deliverability_summary"]
    assert "near the 10-lookup limit" not in summary
    assert "PermError" in summary


@pytest.mark.parametrize("lookups", [8, 9, 10, 11])
def test_no_two_surfaces_disagree(run, lookups):
    result = run(lookups)
    card = _spf_card(result)
    expected = spf_lookup_band(lookups)

    detail_types = {d["type"] for d in _lookup_details(card)}
    card_band = ("over" if card["status"] == "fail" or "error" in detail_types
                 else "near" if "warning" in detail_types else "ok")

    rows = _lookup_rows(result)
    plan_band = ("over" if rows and rows[0]["priority"] == "critical"
                 else "near" if rows else "ok")

    summary = result["executive_summary"]["deliverability_summary"]
    summary_band = ("over" if "PermError" in summary
                    else "near" if "near the 10-lookup limit" in summary else "ok")

    optimization_band = "ok" if not card["spf_deep"]["optimizations"] else expected

    surfaces = {
        "card": card_band,
        "plan": plan_band,
        "deliverability": summary_band,
        "optimization": optimization_band,
        "spf_deep": card["spf_deep"]["lookup_band"],
        "lookup budget bar": result["spf_tree"]["band"],
    }
    assert set(surfaces.values()) == {expected}, surfaces
    assert _lookup_anomalies(result) == []


def test_a_floor_count_is_not_banded_ok(audit):
    zone = _zone(3)
    zone[DOMAIN]["TXT"] = ["v=spf1 include:flaky.band.test a:h0.band.test -all"]
    from conftest import FakeZone
    fz = FakeZone(zone).fail("flaky.band.test", "TXT")
    result = audit(fz, DOMAIN)
    card = _spf_card(result)

    assert card["status"] == "warn"
    assert card["spf_deep"]["lookup_band"] == "unknown"
    assert not any("well within" in d["text"] for d in card["details"])
    assert _lookup_rows(result) == []
