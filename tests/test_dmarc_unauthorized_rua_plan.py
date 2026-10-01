"""An unauthorized external rua gets a plan row and leads the card's fix.

knoxville.org sends aggregate reports to an address at lbmc.com, and
knoxville.org._report._dmarc.lbmc.com publishes no TXT record, so receivers
drop the reports (RFC 9990 section 4). _check_report_authorization raises
that as an error and the DMARC card fails for it, but the card's fix said
"Remove the pct tag" (the pct warning's fix came first) and the plan had no
row for it: the fallback that gives every failing card a row skips a
protocol that already has one.
"""
from conftest import FakeZone

D = "knoxville.test"
RECEIVER = "lbmc.test"
AUTH_HOST = f"{D}._report._dmarc.{RECEIVER}"


def _run(audit, dmarc, authorized=False):
    records = {
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "MX": [(10, f"mx.{D}")],
            "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.5"]},
        f"mx.{D}": {"A": ["203.0.113.6"]},
        f"_dmarc.{D}": {"TXT": [dmarc]},
        RECEIVER: {"MX": [(10, f"mx.{RECEIVER}")]},
    }
    if authorized:
        records[AUTH_HOST] = {"TXT": ["v=DMARC1"]}
    return audit(FakeZone(records), D, scope="dmarc")


def _card(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def _auth_rows(result):
    return [i for i in result["security_roadmap"]["items"]
            if i["protocol"] == "DMARC" and "authorize" in i["action"]]


DMARC = f"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@{RECEIVER}"


def test_card_fix_names_the_authorization_record(audit):
    card = _card(_run(audit, DMARC))
    assert card["status"] == "fail"
    assert AUTH_HOST in card["fix"], card["fix"]
    assert "pct" not in card["fix"], card["fix"]
    assert f"address at {D}" in card["fix"], card["fix"]


def test_plan_has_a_high_row_for_the_unauthorized_receiver(audit):
    result = _run(audit, DMARC)
    rows = _auth_rows(result)
    assert len(rows) == 1
    row = rows[0]
    assert row["priority"] == "high"
    assert row["action"] == f"Have {RECEIVER} authorize the DMARC reports sent to it"
    assert AUTH_HOST in row["what_note"] and "v=DMARC1" in row["what_note"]
    assert "RFC 9990 section 4" in row["what_note"]
    assert f"address at {D}" in row["what_note"]
    assert f"dmarc@{RECEIVER}" in row["impact"]
    # It outranks the medium pct row and the low np row, so it is the
    # biggest risk the summary names.
    assert result["executive_summary"]["biggest_risk"] == row["action"]


def test_no_row_when_the_receiver_has_authorized_the_reports(audit):
    result = _run(audit, DMARC, authorized=True)
    assert _card(result)["status"] != "fail"
    assert _auth_rows(result) == []
    assert _card(result).get("unauthorized_reports") == []
