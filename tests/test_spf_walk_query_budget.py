"""Regression test: the SPF lookup counter has a query budget.

_count_recursive tracked loops per path but had no bound on the size of the
walk. A record tree the audited domain controls, three levels of 30
includes each, made one audit send 27,931 DNS queries, and the walking
thread kept going long after the audit's timeout stopped waiting for it.

The walk now stops resolving after SPF_WALK_QUERY_BUDGET queries. Lookup
terms are still counted, the verdict stays over the limit, and the total is
reported as a floor.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spf_execution_engine
import spf_recursive


def _fan_out(monkeypatch, width=30, levels=3):
    calls = {"n": 0}

    def fake_lookup(domain):
        calls["n"] += 1
        d = domain.lower()
        if d.count(".") - 1 >= levels:
            return {"record": "v=spf1 a:host.example -all",
                    "status": spf_recursive.SPF_FOUND, "error": None}
        kids = " ".join(f"include:k{i}.{d}" for i in range(width))
        return {"record": f"v=spf1 {kids} -all",
                "status": spf_recursive.SPF_FOUND, "error": None}

    def fake_mech(mtype, target):
        calls["n"] += 1
        return "ok"

    monkeypatch.setattr(spf_recursive, "_lookup_spf", fake_lookup)
    monkeypatch.setattr(spf_recursive, "_mechanism_lookup_status", fake_mech)
    return calls


def test_walk_stops_at_the_query_budget(monkeypatch):
    calls = _fan_out(monkeypatch)
    result = spf_recursive.count_spf_lookups("x.test")
    assert calls["n"] <= spf_recursive.SPF_WALK_QUERY_BUDGET
    assert result["truncated"] is True
    assert result["over_limit"] is True
    assert result["band"] == "over"
    assert result["total_lookups"] >= spf_recursive.SPF_WALK_QUERY_BUDGET - 1


def test_truncated_count_is_worded_as_a_floor(monkeypatch):
    _fan_out(monkeypatch)
    result = spf_recursive.count_spf_lookups("x.test")
    assert result["summary"].startswith("At least ")
    limit = [i for i in result["issues"] if i.get("kind") == "lookup_limit"]
    assert limit and "at least" in limit[0]["issue"]


def test_trace_and_tree_survive_a_truncated_walk(monkeypatch):
    _fan_out(monkeypatch)
    result = spf_recursive.count_spf_lookups("x.test")
    trace = spf_execution_engine.build_spf_execution_trace(result, result["record"])
    assert trace["flat_steps"][-1]["running_total"] == result["total_lookups"]
    assert spf_execution_engine.build_spf_tree_viz(result)["root"]["domain"] == "x.test"


def test_ordinary_record_is_not_truncated(monkeypatch):
    calls = _fan_out(monkeypatch, width=3, levels=1)
    result = spf_recursive.count_spf_lookups("x.test")
    assert result["truncated"] is False
    assert not result["summary"].startswith("At least")
    # 3 includes, each with one a: term.
    assert result["total_lookups"] == 6
    assert calls["n"] == 1 + 3 + 3
