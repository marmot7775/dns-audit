"""The web short answer and PDF page 1 say the same thing in two edge cases.

redrooster.com sends and receives no mail. Its verdict ends "Nothing to fix."
The web page leaves out the "Nothing urgent" line under it, which would
contradict the verdict, and PDF page 1 printed that line anyway.

When a lookup did not complete the audit cannot rank risks
(biggest_risk_severity "unknown"). The PDF showed the could-not-read message
alone, and the web showed it above a "Do these first" list. Both now show the
message alone, and the backend sends no do_first list in that case.
"""
import copy
import io
import os
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pdf_report  # noqa: E402
from conftest import FakeZone  # noqa: E402
from test_status_semantics import PARKED, _parked_zone  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401

DOMAIN = "unread-shape.test"
UNREAD = "This audit could not read part of this domain's DNS"


def _page_one(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join((reader.pages[0].extract_text() or "").split())


def _unread_zone():
    return FakeZone({
        DOMAIN: {"MX": [(10, f"mx.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.10"], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"mx.{DOMAIN}": {"A": ["203.0.113.11"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    }).fail(f"_dmarc.{DOMAIN}", "TXT")


def _first_box(page):
    return page.evaluate("""() => {
        const box = document.querySelector('#executive-summary .es-first');
        return {notes: [...box.querySelectorAll('.es-first-note')].map(e => e.textContent),
                items: box.querySelectorAll('.es-first-item').length};
    }""")


# ---------------------------------------------------------------
# No mail, nothing to fix
# ---------------------------------------------------------------

def test_pdf_page_one_does_not_contradict_nothing_to_fix(audit):
    result = audit(_parked_zone(), PARKED)
    es = result["executive_summary"]
    assert es["verdict"].endswith("Nothing to fix."), es["verdict"]
    assert es["do_first"] == []

    page = _page_one(result)
    assert "Nothing to fix." in page
    assert "Nothing urgent" not in page, page


def test_the_web_says_the_same_for_the_same_result(browser, audit):  # noqa: F811
    result = audit(_parked_zone(), PARKED)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, result)
        assert _first_box(page) == {"notes": [], "items": 0}
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# A lookup did not complete
# ---------------------------------------------------------------

def test_the_backend_sends_no_actions_when_it_cannot_rank_them(audit):
    es = audit(_unread_zone(), DOMAIN)["executive_summary"]

    assert es["biggest_risk_severity"] == "unknown"
    assert es["biggest_risk"].startswith(UNREAD)
    assert es["do_first"] == []


def test_web_and_pdf_both_show_the_message_alone(browser, audit):  # noqa: F811
    result = audit(_unread_zone(), DOMAIN)
    # A cached result from before this change still carries a list; neither
    # surface shows it.
    stale = copy.deepcopy(result)
    stale["executive_summary"]["do_first"] = [
        {"plain_head": "A head.", "title": "An action", "priority": "medium",
         "protocol": "MTA-STS"}]
    for data in (result, stale):
        page_one = _page_one(data)
        assert UNREAD in page_one
        assert "Do these first" not in page_one

        ctx, page, errors = _page(browser, "dark", 1280)
        try:
            _render(page, data)
            box = _first_box(page)
            assert box["items"] == 0, box
            assert len(box["notes"]) == 1 and box["notes"][0].startswith(UNREAD), box
            assert errors == []
        finally:
            ctx.close()
