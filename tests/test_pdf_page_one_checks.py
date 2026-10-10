"""Page 1 lists every check, and the plan still starts on page 2.

Page 1 held the headline and up to three "Do these first" items, and on most
reports half the page was blank. It now ends with every check on one line:
plain name, status (the card's own pill when it has one), verdict. The table
is sized to fit beside three long items, so "What to do" stays on page 2.
"""
import copy
import io
import os
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_engine  # noqa: E402
import pdf_report  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402
from test_status_semantics import DOMAIN, _zone  # noqa: E402


@pytest.fixture(scope="module")
def result():
    zone = _zone(f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}")
    with fake_dns(zone if isinstance(zone, FakeZone) else FakeZone(zone)):
        return audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope="complete")


def _pages(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return [" ".join((p.extract_text() or "").split()) for p in reader.pages]


def test_page_one_lists_every_check_with_its_status(result):
    first = _pages(result)[0]
    shown = [c for c in (pdf_report._get_check(result, n) for n in pdf_report.PROTOCOL_SECTION_ORDER) if c]
    assert f"Every check ({len(shown)})" in first
    for card in shown:
        assert (card.get("plain_name") or card["name"]) in first
        assert pdf_report._card_status(card)[1] in first


def test_plan_starts_on_page_two_with_three_long_items(result):
    stressed = copy.deepcopy(result)
    long_item = {"priority": "critical", "protocol": "DMARC",
                 "action": "Publish a DMARC record with an enforcing policy and a reporting address",
                 "plain_head": ("Anyone can send mail that claims to be from your domain, and "
                                "receivers have no instruction to stop it or to tell you.")}
    es = stressed.setdefault("executive_summary", {})
    es["do_first"] = [dict(long_item) for _ in range(3)]
    es["biggest_risk_severity"] = "critical"
    pages = _pages(stressed)
    assert "Every check (" in pages[0]
    # The section heading, "2 What to do"; page 1 names it in its pointer line.
    assert "2 What to do" in pages[1] and "2 What to do" not in pages[0]


def test_cards_and_page_one_share_one_status_rule():
    card = {"name": "MX Records", "status": "pass", "pill_label": "No mail, by design"}
    assert pdf_report._card_status(card)[1] == "No mail, by design"
    assert pdf_report._card_status({"status": "absent"})[1] == "Optional, not set up"


def test_layouts_step_down_and_never_overflow(result):
    S = pdf_report._styles()
    [fits] = pdf_report._checks_at_a_glance(result, S)
    width = pdf_report._FRAME_WIDTH
    _, full_h = fits.wrap(width, 2000)
    assert fits._chosen is fits.layouts[0]
    _, compact_h = fits.wrap(width, full_h - 1)
    assert fits._chosen is fits.layouts[1] and compact_h < full_h
    # Too little room for either: nothing, so the plan is not pushed back.
    assert fits.wrap(width, 20) == (width, 0)
