"""SPF records receivers reject with PermError that the audit graded pass.

- An include loop (a include:b, b include:a, or a including itself). A real
  evaluator follows it past the 10 lookup limit, RFC 7208 section 4.6.4.
  The loop node was dropped with a total of 0, so the card said pass.
- redirect= or exp= more than once, which RFC 7208 section 6 forbids.
- include, exists, ip4 or ip6 with no ":" value (sections 5.2, 5.6, 5.7).
  They were matched against the known-mechanism list and accepted.
- The DMARC evaluation called SPF "configured, a path to DMARC pass" next to
  a failing SPF card whenever the PermError was not the lookup count.
"""
from unittest.mock import patch

import pytest

import audit_engine
import result_transformer
import spf_recursive
from spf_execution_engine import build_dmarc_evaluation

DOMAIN = "example.com"


def _fake_lookup_spf(records):
    def _inner(domain):
        record = records.get(domain.lower().rstrip("."))
        if record:
            return {"record": record, "status": spf_recursive.SPF_FOUND, "error": None}
        return {"record": None, "status": spf_recursive.SPF_NXDOMAIN,
                "error": f"{domain} does not exist (NXDOMAIN)"}
    return _inner


def _raw_spf(records):
    with patch.object(audit_engine, "_lookup_txt", return_value=[records[DOMAIN]]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_lookup_spf",
                      side_effect=_fake_lookup_spf(records)):
        return audit_engine._raw_check_spf(DOMAIN)


def _card(records):
    return result_transformer.transform_spf(_raw_spf(records), has_mx=True)


LOOPS = [
    {DOMAIN: "v=spf1 include:example.com -all"},
    {DOMAIN: "v=spf1 include:b.example.com -all",
     "b.example.com": "v=spf1 include:example.com -all"},
    {DOMAIN: "v=spf1 redirect=b.example.com",
     "b.example.com": "v=spf1 redirect=example.com"},
]


@pytest.mark.parametrize("records", LOOPS)
def test_an_include_loop_fails(records):
    card = _card(records)
    assert card["status"] == "fail", card
    rec = _raw_spf(records)["spf_recursive"]
    assert rec["status"] == "fail"
    assert rec["loop_domains"]


def test_two_includes_of_one_target_are_not_a_loop():
    records = {DOMAIN: "v=spf1 include:a.example.com include:b.example.com -all",
               "a.example.com": "v=spf1 include:shared.example.com -all",
               "b.example.com": "v=spf1 include:shared.example.com -all",
               "shared.example.com": "v=spf1 ip4:192.0.2.1 -all"}
    assert _card(records)["status"] == "pass"
    assert _raw_spf(records)["spf_recursive"]["loop_domains"] == []


SYNTAX = [
    "v=spf1 redirect=a.example.com redirect=b.example.com",
    "v=spf1 exp=a.example.com exp=b.example.com -all",
    "v=spf1 include -all",
    "v=spf1 exists -all",
    "v=spf1 ip4 -all",
    "v=spf1 ip6 -all",
]


@pytest.mark.parametrize("record", SYNTAX)
def test_a_syntax_permerror_fails(record):
    records = {DOMAIN: record, "a.example.com": "v=spf1 -all",
               "b.example.com": "v=spf1 -all"}
    raw = _raw_spf(records)
    assert raw["syntax_errors"], raw["issues"]
    assert _card(records)["status"] == "fail"


@pytest.mark.parametrize("record", ["v=spf1 a mx -all", "v=spf1 a/24 mx//64 -all",
                                    "v=spf1 ip4:192.0.2.1 exp=x.example.com -all"])
def test_valid_bare_mechanisms_still_pass(record):
    assert _raw_spf({DOMAIN: record})["syntax_errors"] == []


DMARC = {"record": "v=DMARC1; p=reject; rua=mailto:d@example.com",
         "policy": "reject", "rua": "mailto:d@example.com"}
DKIM_NONE = {"found_selectors": []}


@pytest.mark.parametrize("records", [
    {DOMAIN: "v=spf1 include:nospf.example.com -all",
     "nospf.example.com": None},
    {DOMAIN: "v=spf1 ip4:192.0.2.1 ip4:bad -all"},
    {DOMAIN: "v=spf1 include:example.com -all"},
])
def test_dmarc_evaluation_reads_an_spf_permerror(records):
    def _lookup(domain):
        d = domain.lower().rstrip(".")
        if d in records and records[d] is None:
            return {"record": None, "status": spf_recursive.SPF_NO_RECORD, "error": None}
        return _fake_lookup_spf(records)(domain)
    with patch.object(audit_engine, "_lookup_txt", return_value=[records[DOMAIN]]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_lookup_spf", side_effect=_lookup):
        raw = audit_engine._raw_check_spf(DOMAIN)
    assert result_transformer.transform_spf(raw, has_mx=True)["status"] == "fail"
    ev = build_dmarc_evaluation(DMARC, raw, DKIM_NONE, tree_walk=None)
    assert ev["spf_result"] == "permerror", ev


def test_a_repaired_record_is_still_configured():
    raw = {"record": "v=spf1 ip4:192.0.2.1 -all", "lookup_count": 0,
           "syntax_errors": [], "void_lookup_count": 0,
           "spf_recursive": {"permerror_domains": [], "multiple_spf_domains": [],
                             "loop_domains": []}}
    ev = build_dmarc_evaluation(DMARC, raw, DKIM_NONE, tree_walk=None)
    assert ev["spf_result"] == "configured"
