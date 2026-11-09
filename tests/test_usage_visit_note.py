"""
Visit notes from the sister tools.

A tool page sends one note when it opens, so a visitor who reads nothing
still shows in the log. The note carries the tool and the linking host and
nothing else; any other field is dropped, never logged.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import server as server_module

_usage_entry = server_module._usage_entry


@pytest.mark.parametrize("tool", ["aprf-reader", "header-decoder"])
def test_visit_note_needs_no_counts_or_status(tool):
    assert _usage_entry({"tool": tool, "visit": True}) == {"tool": tool, "visit": True}


def test_visit_note_keeps_the_linking_host():
    entry = _usage_entry({"tool": "aprf-reader", "visit": True, "ref": "Dns-Audit.com"})
    assert entry == {"tool": "aprf-reader", "ref": "dns-audit.com", "visit": True}


def test_visit_note_drops_every_other_field():
    entry = _usage_entry({"tool": "aprf-reader", "visit": True, "sample": True, "reports": 5,
                          "domains": ["example.com"], "status": "ok", "extra": "x" * 50})
    assert entry == {"tool": "aprf-reader", "visit": True}


def test_visit_note_for_an_unknown_tool_is_refused():
    assert _usage_entry({"tool": "other", "visit": True}) is None


@pytest.mark.parametrize("visit", ["true", 1, None, False])
def test_only_a_true_visit_flag_counts(visit):
    # Anything but true falls through to the use checks, which this bare note fails
    assert _usage_entry({"tool": "aprf-reader", "visit": visit}) is None
