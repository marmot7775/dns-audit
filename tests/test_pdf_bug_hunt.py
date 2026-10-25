"""PDF details that disagreed with the page or with CLAUDE.md.

- Page 1 ticked biggest_risk green whenever nothing was in Do these first,
  so "Configure MTA-STS" printed as if MTA-STS were set up.
- The vendor table set its record line in built-in Courier, a face the
  report does not embed (Doc 52).
- Path to enforcement told a p=reject record it was N steps "to an
  enforcing policy".
- An unavailable card took TEXT_SEC, not NEUTRAL_CLR, the neutral grey.
- The overview table said "Partial" where the attack surface page and the
  web say "Partly protected".
"""
import copy
import io
import re

from pypdf import PdfReader

import pdf_report
from test_pdf_fonts import _base_fonts
from test_ui_consistency_a11y import _run, _zone


def _text(pdf):
    return re.sub(r"\s+", " ", " ".join(
        p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf)).pages))


def _box_text(es):
    data = {"executive_summary": es, "security_roadmap": {"items": []}}
    flow = pdf_report._do_first_box(data, pdf_report._styles())
    return flow[0]._cellvalues[0][0].text if flow else ""


def test_page_one_ticks_only_an_all_clear():
    action = _box_text({"biggest_risk": "Configure MTA-STS for TLS enforcement",
                        "biggest_risk_severity": "medium"})
    assert action and pdf_report.PASS_CLR.hexval() not in action, action
    clear = _box_text({"biggest_risk": "No urgent problems. Smaller improvements are under What to do.",
                       "biggest_risk_severity": "none"})
    assert pdf_report.PASS_CLR.hexval() in clear


def test_the_vendor_table_uses_the_embedded_mono_face():
    data = copy.deepcopy(_run(_zone()))
    data["vendors"] = [{"name": "Example Mail", "confidence": 90, "detected_via": ["spf"],
                        "signals": [{"record": "v=spf1 include:_spf.example.net -all"}]}]
    data.pop("vendors_status", None)
    names = _base_fonts(pdf_report.generate_pdf(data))
    assert not any("Courier" in n for n in names), names


def test_path_to_enforcement_does_not_tell_reject_it_is_not_enforcing():
    data = {"checks": [{"name": "DMARC", "status": "warn", "tag_breakdown": {"migration": {
        "status": "needs_changes", "total_steps": 1,
        "steps": [{"title": "Add sp=reject and np=reject", "record": "v=DMARC1; p=reject; sp=reject; np=reject"}],
    }}}]}
    flow = pdf_report._migration_page(data, pdf_report._styles())
    texts = " ".join(getattr(f, "text", "") for f in flow)
    assert "to an enforcing policy" not in texts, texts


def test_an_unavailable_card_is_the_neutral_grey():
    clr, label = pdf_report._card_status({"status": "unavailable"})
    assert clr == pdf_report.NEUTRAL_CLR
    assert label == "Not checked"


def test_a_partial_vector_reads_partly_protected_in_the_overview():
    text = _text(pdf_report.generate_pdf(_run(_zone(dmarc="v=DMARC1; p=none"))))
    assert "Partly protected" in text
    assert not re.search(r"\bPartial\b", text), re.findall(r".{40}\bPartial\b.{40}", text)
