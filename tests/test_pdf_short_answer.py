"""Doc 92: the PDF's first two pages are the short answer and the plan.

Page 1 carries the plain verdict and at most three things to do first. Page 2
is the plan, with the check tally once, as one line. The tiles, the attack
surface table and the contents open Part 2. The "Do these first" box is red
only when an item is critical: a missing rua used to print red here and
amber on the web.

The backend adds plain_head and who to roadmap items and do_first to the
executive summary. Until it does, the PDF falls back to the action, no
"Who does this" line, and the first roadmap items that are not low.
"""
import copy
import io
import os
import re
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report

DOMAIN = "doc92.test"


def _zone(dmarc):
    zone = {
        DOMAIN: {"MX": [(10, f"mx1.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.92"], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"mx1.{DOMAIN}": {"A": ["203.0.113.93"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    }
    if dmarc:
        zone[f"_dmarc.{DOMAIN}"] = {"TXT": [dmarc]}
    return zone


def _pages(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return [" ".join((p.extract_text() or "").split()) for p in reader.pages]


@pytest.fixture
def monitoring(audit):
    """p=none with no rua: the top row is high, not critical."""
    return audit(_zone("v=DMARC1; p=none"), DOMAIN)


@pytest.fixture
def no_dmarc(audit):
    return audit(_zone(None), DOMAIN)


def _without_backend_fields(result):
    """The result as it looked before the result_transformer change: no
    plain_head, who, optional or do_first. The fallback paths read this."""
    result = copy.deepcopy(result)
    for item in result["security_roadmap"]["items"]:
        for key in ("plain_head", "who", "optional"):
            item.pop(key, None)
    result["executive_summary"].pop("do_first", None)
    for card in result.get("checks", []):
        card.pop("plain_name", None)
    return result


def _with_backend_fields(result):
    """The fields the result_transformer change adds, set by hand."""
    result = copy.deepcopy(result)
    items = result["security_roadmap"]["items"]
    for n, item in enumerate(items):
        item["plain_head"] = f"Plain consequence number {n}."
        item["who"] = "Your DNS host"
    result["executive_summary"]["do_first"] = [
        {"plain_head": i["plain_head"], "title": i["action"],
         "priority": i["priority"], "protocol": i["protocol"]}
        for i in items if i["priority"] != "low"][:3]
    return result


def _box_colours(result):
    box = pdf_report._do_first_box(result, pdf_report._styles())[0]
    return {cmd[3] for cmd in box._bkgrndcmds if cmd[0] == "BACKGROUND"}


# ---------------------------------------------------------------
# Page 1: the short answer
# ---------------------------------------------------------------

def test_page_one_is_the_short_answer(monitoring):
    first = _pages(monitoring)[0]

    assert "The short answer" in first
    # The headline the web page shows, not the longer policy verdict.
    assert " ".join(monitoring["executive_summary"]["headline"].split()) in first
    assert "Do these first" in first
    assert pdf_report.SHORT_ANSWER_POINTER in first
    # The tally, the tiles and the contents moved off it.
    for gone in ("checks total", "Across", "Table of Contents", "Contents",
                 "Forged mail blocked", "Spoofing Protection", "Attack surface"):
        assert gone not in first, gone


def test_do_these_first_falls_back_to_the_first_items_that_are_not_low(monitoring):
    monitoring = _without_backend_fields(monitoring)
    first = _pages(monitoring)[0]
    # Not low, and not an optional protocol that is simply not set up.
    wanted = [i for i in monitoring["security_roadmap"]["items"]
              if i["priority"] != "low" and i.get("status") != "absent"][:3]

    assert wanted
    for n, item in enumerate(wanted, 1):
        assert f"{n}. {item['action']}" in first, item["action"]
    assert "4." not in first.split("Do these first", 1)[1].split("Page 2 is")[0]


def test_do_these_first_uses_the_backend_list_when_present(monitoring):
    result = _with_backend_fields(monitoring)
    first = _pages(result)[0]

    for n, item in enumerate(result["executive_summary"]["do_first"], 1):
        # The consequence first, then the instruction, then the term.
        assert f"{n}. {item['plain_head']} {item['title']} ({item['protocol']})" in first


def test_an_empty_do_first_list_says_nothing_is_urgent(monitoring):
    result = copy.deepcopy(monitoring)
    result["executive_summary"]["do_first"] = []
    result["executive_summary"]["biggest_risk"] = "No urgent problems. Smaller improvements are under What to do."
    first = _pages(result)[0]

    assert "Do these first" not in first
    assert "No urgent problems. Smaller improvements are under What to do." in first


def test_the_box_is_amber_for_a_missing_rua(monitoring):
    top = monitoring["security_roadmap"]["items"][0]
    assert top["priority"] == "high", top

    assert _box_colours(monitoring) == {pdf_report.WARN_BG}


def test_the_box_is_red_only_for_a_critical_item(no_dmarc):
    assert no_dmarc["security_roadmap"]["items"][0]["priority"] == "critical"

    assert _box_colours(no_dmarc) == {pdf_report.FAIL_BG}


# ---------------------------------------------------------------
# Page 2: the plan
# ---------------------------------------------------------------

def test_page_two_is_the_plan_with_the_tally_once(monitoring):
    pages = _pages(monitoring)

    assert "2 What to do" in pages[1]
    assert re.search(r"Across \d+ checks: \d+ needs? fixing, \d+ could be stronger, \d+ pass, "
                     r"\d+ optional and not set up", pages[1]), pages[1][:600]
    assert sum(p.count("Across ") for p in pages) == 1
    # The five counter tiles are gone.
    assert "Not configured Not checked" not in " ".join(pages)


def test_plan_rows_lead_with_the_plain_head_and_name_who_does_it(monitoring):
    result = _with_backend_fields(monitoring)
    text = " ".join(_pages(result))

    for item in result["security_roadmap"]["items"]:
        assert f"{item['plain_head']} {item['action']}" in text, item["action"]
    assert text.count("Who does this: Your DNS host") == len(result["security_roadmap"]["items"])


def test_plan_rows_without_the_new_fields_print_no_who_line(monitoring):
    text = " ".join(_pages(_without_backend_fields(monitoring)))

    assert "Who does this" not in text


# ---------------------------------------------------------------
# Part 2 opens with the evidence and the contents
# ---------------------------------------------------------------

def test_part_two_opens_with_the_tiles_the_attack_surface_and_the_contents(monitoring):
    pages = _pages(monitoring)
    divider = next(i for i, p in enumerate(pages) if "Nothing in it changes the plan in Part 1." in p)
    page = pages[divider]

    for part in ("Part 2: Appendix", "Technical summary", "Forged mail blocked",
                 "Ready for the 2026 DMARC standard (RFC 9989)", "Records published",
                 "Attack surface overview", "Contents", "1. The short answer",
                 "2. What to do", "3. Checks"):
        assert part in page, part
    assert page.index("Technical summary") < page.index("Attack surface overview") < page.index("Contents")


def test_the_pdf_carries_no_email_address_of_ours(monitoring):
    text = " ".join(_pages(_with_backend_fields(monitoring)))
    addresses = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text)

    # Every address is an example at the audited domain or one of its
    # subdomains; none is the site's or its owner's.
    assert addresses
    assert not [a for a in addresses if not a.lower().endswith(DOMAIN)], addresses
    assert not [a for a in addresses if "dns-audit" in a.lower()], addresses
