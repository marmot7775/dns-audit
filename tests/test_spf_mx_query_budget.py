"""The SPF walk's query budget covers every MX host address query.

An mx term costs one lookup toward the limit of 10, but resolving its hosts
costs up to two queries each: A, then AAAA when A has no answer. The budget
was charged once per host, so AAAA fallbacks went unpaid and the walk could
pass its 100 query cap. When the budget did run out the MX loop stopped
without marking the walk truncated, so a record with a handful of mx terms
graded as a clean pass with hosts never checked for void answers.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import spf_recursive


def _zone(terms=5, hosts=10, address="AAAA"):
    """terms mx mechanisms, each naming a domain with hosts MX hosts that
    publish only an AAAA record (address="AAAA") or nothing (None)."""
    targets = [f"d{t}.example.net" for t in range(terms)]
    records = {"example.com": {
        "TXT": ["v=spf1 " + " ".join(f"mx:{d}" for d in targets) + " -all"]}}
    for d in targets:
        names = [f"mx{h}.{d}" for h in range(hosts)]
        records[d] = {"MX": [(h, n) for h, n in enumerate(names)]}
        for n in names:
            if address == "AAAA":
                records[n] = {"AAAA": ["2001:db8::1"]}
    return FakeZone(records)


def test_aaaa_only_hosts_exhaust_the_budget_and_mark_the_walk_truncated():
    # 1 TXT + 5 x (1 MX + 10 x (A + AAAA)) = 106 queries, over the cap.
    with fake_dns(_zone()):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["total_lookups"] == 5
    assert result["truncated"] is True
    assert result["incomplete"] is True
    assert result["tree"]["truncated"] is True
    assert result["status"] == "warn"
    assert result["band"] == "unknown"
    assert "well within" not in result["summary"]
    assert "query cap" in result["summary"]
    capped = [i for i in result["issues"] if "query cap" in i["issue"]]
    assert capped and "not checked" in capped[0]["plain_english"]


def test_truncated_child_marks_its_parent():
    zone = _zone()
    zone.add("example.com", "TXT", ["v=spf1 include:spf.example.com -all"])
    zone.add("spf.example.com", "TXT", [
        "v=spf1 " + " ".join(f"mx:d{t}.example.net" for t in range(5)) + " -all"])
    with fake_dns(zone):
        result = spf_recursive.count_spf_lookups("example.com")
    assert result["tree"]["truncated"] is True
    assert result["tree"]["children"][0]["truncated"] is True
    assert result["chain"][0]["truncated"] is True


def test_hosts_without_an_a_record_stay_within_the_budget():
    for address in ("AAAA", None):
        zone = _zone(terms=9, hosts=10, address=address)
        with fake_dns(zone):
            spf_recursive.count_spf_lookups("example.com")
        assert len(zone.queries) <= spf_recursive.SPF_WALK_QUERY_BUDGET


def test_a_few_hosts_are_not_truncated():
    zone = _zone(terms=2, hosts=3)
    with fake_dns(zone):
        result = spf_recursive.count_spf_lookups("example.com")
    # 1 TXT + 2 x (1 MX + 3 x 2) = 15 queries.
    assert len(zone.queries) == 15
    assert result["truncated"] is False
    assert result["status"] == "pass"
    assert result["band"] == "ok"


def test_ten_terms_with_unchecked_hosts_are_incomplete_not_passing():
    import audit_engine
    import result_transformer
    with fake_dns(_zone(terms=10)):
        result = spf_recursive.count_spf_lookups("example.com")
        raw = audit_engine._raw_check_spf("example.com")
    assert result["total_lookups"] == 10
    assert result["truncated"] is True
    assert result["incomplete"] is True
    assert result["status"] == "warn"
    assert any("query cap" in i["issue"] for i in result["issues"])
    card = result_transformer.transform_spf(raw, has_mx=True)
    assert card["status"] == "warn"


def test_card_does_not_pass_an_incomplete_walk():
    import audit_engine
    import result_transformer
    with fake_dns(_zone()):
        raw = audit_engine._raw_check_spf("example.com")
    assert raw["spf_indeterminate"] is True
    card = result_transformer.transform_spf(raw, has_mx=True)
    assert card["status"] == "warn"
    assert card["pill_label"] != result_transformer.PILL_PASS
    texts = " ".join(d["text"] for d in card["details"])
    assert "stopped after 100 DNS queries" in texts and "not checked" in texts
    assert "well within" not in texts + card.get("verdict", "") + card.get("explanation", "")
