"""Two DMARC records mean no DMARC policy, and the summary and plan say so.

capital.net publishes two v=DMARC1 records at _dmarc:
"v=DMARC1; p=quarantine; pct=25; rua=..." and "v=DMARC1; p=none; sp=none;
rua=...". Receivers discard both and apply no policy (RFC 9989). The card
was red, but the engine returned early with the first record and never
parsed its tags, so everything downstream read one record as the policy:
the summary said the domain was monitoring, the only DMARC plan row was
"Progress from p=none to enforcement", no row said to remove the duplicate,
and the card said rua was missing although both records carry one.
"""
import io
import re

import pytest
from pypdf import PdfReader

from conftest import FakeZone
import pdf_report

D = "capital.test"
QUARANTINE = f"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@{D}"
NONE = f"v=DMARC1; p=none; sp=none; rua=mailto:reports@{D}"


def _run(audit, records):
    zone = FakeZone({
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "MX": [(10, f"mx.{D}")],
            "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.5"]},
        f"mx.{D}": {"A": ["203.0.113.6"]},
        f"_dmarc.{D}": {"TXT": records},
    })
    return audit(zone, D, scope="dmarc")


def _card(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def _dmarc_rows(result):
    return [i for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"]


@pytest.mark.parametrize("records", [[QUARANTINE, NONE], [NONE, QUARANTINE]])
def test_summary_says_there_is_no_usable_policy(audit, records):
    result = _run(audit, records)
    summary = result["executive_summary"]
    assert "no DMARC policy" in summary["verdict"], summary["verdict"]
    for text in (summary["verdict"], summary["deliverability_summary"]):
        assert "monitoring" not in text.lower(), text
        assert "partially" not in text.lower(), text
    assert summary["biggest_risk"] == "Remove the duplicate DMARC record"
    assert summary["biggest_risk_severity"] == "critical"


@pytest.mark.parametrize("records", [[QUARANTINE, NONE], [NONE, QUARANTINE]])
def test_first_dmarc_row_removes_the_duplicate_and_names_both(audit, records):
    rows = _dmarc_rows(_run(audit, records))
    first = rows[0]
    assert first["priority"] == "critical"
    assert first["action"] == "Remove the duplicate DMARC record"
    assert QUARANTINE in first["what_note"] and NONE in first["what_note"]


@pytest.mark.parametrize("records", [[QUARANTINE, NONE], [NONE, QUARANTINE]])
def test_no_row_treats_either_record_as_the_policy(audit, records):
    for row in _dmarc_rows(_run(audit, records)):
        # A row with a record proposes an edit to the live policy, and there
        # is none to edit.
        assert not row.get("record"), row
        text = f"{row['action']} {row.get('impact', '')}"
        for phrase in ("p=none", "enforcement", "retired", "np=", "subdomain policy"):
            assert phrase not in text, (phrase, row)


def test_card_names_both_records_and_does_not_claim_rua_is_missing(audit):
    card = _card(_run(audit, [QUARANTINE, NONE]))
    assert card["status"] == "fail"
    assert card["pill_label"] == "Multiple records"
    assert card["record"] is None
    texts = [d["text"] for d in card["details"]]
    assert QUARANTINE in texts and NONE in texts
    every = " ".join(texts + [card["verdict"], card["explanation"], card["fix"] or ""])
    assert "No aggregate reporting" not in every
    assert "rua) configured" not in every
    # No panel built from one record as if it were the policy.
    assert card["tag_breakdown"] is None
    assert card["attack_surface"] is None
    assert card["effective_policy"] is None


def test_pdf_plan_names_both_records(audit):
    result = _run(audit, [QUARANTINE, NONE])
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages))
    assert "Remove the duplicate DMARC record" in text
    assert "monitoring email authentication" not in text
