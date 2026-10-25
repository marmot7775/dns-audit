"""An unauthorized report destination grades amber, and the record is in force.

espn.com sends its reports to disney.com, which has not published the
authorization record (RFC 9990 section 4). Receivers still apply the policy;
only the reports are dropped. Until 2026-10-25 that failed the card and the
headline said receivers ignore the record, which was false. It now grades
warn like a record with no rua, and the plan and the card fix still name the
destination. A record receivers really discard keeps its red card and its
"receivers ignore it" headline.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import DOMAIN, _card, _pdf_text, _run

IGNORED = "Your spoofing protection record has an error, so receivers ignore it."
DROPPED = "Your DMARC record is in force, but the reports it asks for are dropped."
EXTERNAL = "rua=mailto:d@other.test"


def _actions(result):
    return [i.get("action") for tier in result["security_roadmap"].values()
            if isinstance(tier, list) for i in tier]


def test_an_unauthorized_rua_at_p_reject_is_amber_and_in_force(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {EXTERNAL}")
    card = _card(result)
    es = result["executive_summary"]
    assert card["status"] == "warn"
    assert card["reports_dropped"] is True
    assert "other.test" in (card["fix"] or "")
    assert any(d["type"] == "warning" and "not authorized" in d["text"] for d in card["details"])
    assert not [d for d in card["details"] if d["type"] == "error"]
    assert es["headline"] == DROPPED
    assert es["headline_state"] == "warn"
    assert "broken" not in es["verdict"]
    assert "Have other.test authorize the DMARC reports sent to it" in _actions(result)
    text = _pdf_text(result)
    assert IGNORED not in text
    assert DROPPED in text


def test_at_p_none_the_policy_headline_wins_outside_deliverability(audit):
    result = _run(audit, f"v=DMARC1; p=none; {EXTERNAL}")
    assert _card(result)["status"] == "warn"
    assert result["executive_summary"]["headline"] == (
        "Your domain does not yet ask receivers to block mail that fakes it.")
    assert "Have other.test authorize the DMARC reports sent to it" in _actions(result)


def test_under_deliverability_p_none_with_dropped_reports_says_so(audit):
    result = _run(audit, f"v=DMARC1; p=none; {EXTERNAL}", scope="deliverability")
    card = _card(result)
    assert card["status"] == "warn"
    assert card["graded_for_scope"] is None
    assert result["executive_summary"]["headline"] == DROPPED


def test_a_record_receivers_discard_still_says_so(audit):
    result = _run(audit, ["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert _card(result)["status"] == "fail"
    assert result["executive_summary"]["headline"] == IGNORED


def test_a_fatal_syntax_error_with_an_unauthorized_rua_still_fails(audit):
    result = _run(audit, f"p=reject; v=DMARC1; {EXTERNAL}")
    assert _card(result)["status"] == "fail"
    assert result["executive_summary"]["headline"] != DROPPED


def test_an_authorized_record_is_unflagged(audit):
    card = _card(_run(audit, f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"))
    assert card["status"] == "pass"
    assert card["reports_dropped"] is False
