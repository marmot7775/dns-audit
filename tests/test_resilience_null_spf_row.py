"""The resilience SPF row for v=spf1 -all says it authorizes no server.

Doc 78 left this open: example.com's row read "SPF record is valid ...
SPF verifies that the sending server's IP address is authorized" and
warned about forwarding, beside an SPF card and a DMARC evaluation that
both say the record authorizes no servers.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine


def _spf_row(record, lookups=0):
    raw_spf = {"status": "pass", "record": record, "lookup_count": lookups}
    resilience = audit_engine._build_resilience_analysis(
        raw_results={"spf": raw_spf, "dmarc": {}, "dkim": {},
                     "mx": {"has_null_mx": True}},
        checks=[], has_mx=False, is_defensive=True,
    )
    return resilience["mechanisms"]["spf"]


def test_null_spf_row_says_no_server_is_authorized():
    row = _spf_row("v=spf1 -all")
    assert row["status"] == "pass"
    assert "authorizes no server" in row["note"]
    assert "sending server's IP address is authorized" not in row["note"]
    assert "forwarded" not in row["note"]


def test_null_spf_match_ignores_case_and_spacing():
    assert "authorizes no server" in _spf_row("  V=SPF1 -ALL ")["note"]


def test_softfail_all_is_not_null_spf():
    row = _spf_row("v=spf1 ~all")
    assert "authorizes no server" not in row["note"]


def test_ordinary_record_keeps_the_generic_note():
    row = _spf_row("v=spf1 include:_spf.google.com -all", lookups=4)
    assert row["note"].startswith("SPF record is valid (4/10 lookups used).")
