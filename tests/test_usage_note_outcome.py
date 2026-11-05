"""
Usage notes from the sister tools: did the tool work, and if not, why.

The APRF reader used to send a note only when a read succeeded. A read that
found no report in the files, or that threw, sent nothing at all, so a broken
reader and a page nobody opened produced the same log: silence. Whatever share
of reads were failing was unmeasurable, which is the one number you need to
find a bug from use rather than from a report.

It also sent a bare count of skipped files. A count says something was
refused without saying what kind of thing, and the reasons the reader shows
on screen name the file and can quote the parse error, so they cannot be
sent as they are. Hence a closed set of codes: enough to tell a zip the
reader correctly declined from a report it could not parse, which is the
difference between the file being wrong and the reader being wrong.

These test _usage_entry directly, since it is the whole of the validation.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import server as server_module

_usage_entry = server_module._usage_entry


def _note(**over):
    note = {"tool": "aprf-reader", "reports": 394, "streams": 53,
            "warnings": 409, "domains": ["sender.example"]}
    note.update(over)
    return note


# ------------------------------------------------------------------
# outcome
# ------------------------------------------------------------------

@pytest.mark.parametrize("status", ["ok", "partial", "none", "error"])
def test_each_outcome_is_logged(status):
    entry = _usage_entry(_note(status=status, skips={}))
    assert entry is not None
    assert entry["status"] == status


def test_a_failed_read_is_a_note_not_a_silence():
    """The 'error' note carries zero counts and still has to be accepted."""
    entry = _usage_entry({"tool": "aprf-reader", "status": "error",
                          "reports": 0, "streams": 0, "warnings": 0,
                          "skips": {}, "domains": []})
    assert entry is not None
    assert entry["status"] == "error"
    assert entry["reports"] == 0


def test_an_unknown_outcome_is_refused():
    assert _usage_entry(_note(status="fine", skips={})) is None


@pytest.mark.parametrize("bad", [["ok"], {"ok": 1}, 1, True])
def test_a_non_string_outcome_is_refused_not_an_error(bad):
    assert _usage_entry(_note(status=bad)) is None


def test_outcome_may_be_absent_while_the_old_page_is_live():
    entry = _usage_entry(_note(skipped=11, copies=0))
    assert entry is not None
    assert "status" not in entry


# ------------------------------------------------------------------
# why a file was not read
# ------------------------------------------------------------------

def test_skip_codes_are_kept_per_reason():
    entry = _usage_entry(_note(status="partial",
                               skips={"encrypted": 2, "parse_failed": 9}))
    assert entry["skips"] == {"encrypted": 2, "parse_failed": 9}
    # The total is the sum of the codes, so it is not stored a second time.
    assert "skipped" not in entry


def test_an_unknown_skip_code_is_dropped_not_stored():
    entry = _usage_entry(_note(status="partial",
                               skips={"encrypted": 1, "etc/passwd": 3,
                                      "a long free text reason": 1}))
    assert entry["skips"] == {"encrypted": 1}


@pytest.mark.parametrize("bad", [0, -4, True, "2", 2.5, None, 10_000_001])
def test_a_skip_count_that_is_not_a_positive_int_is_dropped(bad):
    entry = _usage_entry(_note(status="partial",
                               skips={"encrypted": bad, "too_large": 1}))
    assert entry["skips"] == {"too_large": 1}


def test_no_skips_means_no_skips_field():
    entry = _usage_entry(_note(status="ok", skips={}))
    assert "skips" not in entry
    assert "skipped" not in entry


def test_the_old_bare_count_still_lands_until_the_page_is_replaced():
    entry = _usage_entry(_note(skipped=11, copies=0))
    assert entry["skipped"] == 11
    assert "skips" not in entry


def test_skips_wins_over_a_bare_count_if_a_page_sends_both():
    entry = _usage_entry(_note(status="partial", skips={"encrypted": 1},
                               skipped=99))
    assert entry["skips"] == {"encrypted": 1}
    assert "skipped" not in entry


# ------------------------------------------------------------------
# what a note still must not carry
# ------------------------------------------------------------------

def test_a_note_carries_no_filename_or_error_text():
    entry = _usage_entry(_note(status="partial", skips={"parse_failed": 1},
                               file="acme-corp-dmarc-oct.zip",
                               reason="line 4: unexpected token </xml>"))
    assert entry is not None
    flat = repr(entry)
    assert "acme-corp" not in flat
    assert "unexpected token" not in flat


def test_counts_are_still_required():
    assert _usage_entry({"tool": "aprf-reader", "status": "ok",
                         "domains": []}) is None


# ------------------------------------------------------------------
# signing domains, which the reader no longer sends
# ------------------------------------------------------------------

def test_no_domains_means_no_domains_field():
    """An empty list would be a field on every note that says nothing."""
    entry = _usage_entry({"tool": "aprf-reader", "status": "ok", "reports": 1,
                          "streams": 1, "warnings": 0, "skips": {}})
    assert entry is not None
    assert "domains" not in entry


def test_domains_are_still_recorded_from_a_reader_that_sends_them():
    entry = _usage_entry(_note(status="ok", skips={},
                               domains=["Sender.Example", "*.bigsender.example"]))
    assert entry["domains"] == ["sender.example", "bigsender.example"]
