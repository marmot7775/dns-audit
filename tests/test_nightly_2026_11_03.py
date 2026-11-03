"""Nightly fixes from the PR 307 review threads."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from result_transformer import _build_spf_deep_analysis
from spf_recursive import open_authorizations


def test_deep_analysis_stops_at_first_all():
    deep = _build_spf_deep_analysis({"record": "v=spf1 -all include:vendor.example +all",
                                     "lookup_count": 0})
    assert all(m["type"] != "include" for m in deep["mechanisms"])
    assert "+all" not in str(deep.get("all_mechanism", ""))


def test_open_authorizations_skips_void_terms():
    def tree(void):
        mech = {"raw": "a/0", "type": "a"}
        if void:
            mech["void"] = True
        return {"domain": "x.example", "record": "v=spf1 a/0 -all", "mechanisms": [mech],
                "children": []}
    assert open_authorizations(tree(False))
    assert open_authorizations(tree(True)) == []


def test_privacy_resolver_sentence_is_qualified():
    path = os.path.join(os.path.dirname(__file__), "..", "static", "privacy.html")
    html = open(path).read()
    assert "9.9.9.9" in html and "only when those fail" in html
