"""A plan row keeps the breaks its card's fix text had.

_roadmap_fix_text stripped tags without leaving anything where a <br> was,
so oregonstate.edu's SPF row read "Detected services: ZendeskSuggested SPF
record:v=spf1 ... ?allChange ?all to ~all or -all." and every DANE row read
"steps:1. DNSSEC ... domain.2. Generate". A <br> is now a space and a
paragraph break ends a sentence, except after a record in <code>, where a
period would be copied with it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import _roadmap_fix_text


SPF_FIX = (
    "<strong>Detected services:</strong> Zendesk<br><br>"
    "<strong>Suggested SPF record:</strong><br>"
    "<code>v=spf1 include:_spf.google.com include:mail.zendesk.com ?all</code><br><br>"
    "Change <code>?all</code> to <code>~all</code> or <code>-all</code>."
)


def test_paragraphs_become_sentences():
    assert _roadmap_fix_text({"fix": SPF_FIX}) == (
        "Detected services: Zendesk. Suggested SPF record: "
        "v=spf1 include:_spf.google.com include:mail.zendesk.com ?all "
        "Change ?all to ~all or -all."
    )


def test_no_period_is_added_after_a_record():
    text = _roadmap_fix_text({"fix": SPF_FIX})
    assert "?all." not in text.replace("-all.", "")


def test_single_breaks_become_spaces():
    fix = ("DANE implementation requires multiple steps:<br><strong>1.</strong> "
           "DNSSEC must be enabled.<br><strong>2.</strong> Generate a TLSA record.")
    assert _roadmap_fix_text({"fix": fix}) == (
        "DANE implementation requires multiple steps: 1. DNSSEC must be enabled. "
        "2. Generate a TLSA record."
    )


def test_existing_punctuation_is_not_doubled():
    fix = "Prerequisite: DNSSEC is not enabled.<br><br>Enable it first."
    assert _roadmap_fix_text({"fix": fix}) == (
        "Prerequisite: DNSSEC is not enabled. Enable it first."
    )


def test_plain_fix_is_unchanged():
    fix = "Publish a record at <code>_dmarc.example.com</code> &amp; wait."
    assert _roadmap_fix_text({"fix": fix}) == "Publish a record at _dmarc.example.com & wait."


def test_no_fix_is_empty():
    assert _roadmap_fix_text({}) == ""
    assert _roadmap_fix_text({"fix": None}) == ""
    assert _roadmap_fix_text({"fix": ["not", "a", "string"]}) == ""
