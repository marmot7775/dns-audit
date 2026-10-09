"""The PDF plan groups optional extras the way the web plan does.

The web plan puts MTA-STS, TLS-RPT and DANE, when not set up, under
"Optional extras (3)", and its heading count reads "2 important, 3 optional".
PDF page 2 showed the same rows as MEDIUM, in the tier bar and on each row,
mixed in with the rows that need doing. The PDF now uses the web's tier words,
counts those rows as optional, and lists them last under their own heading.
"""
import io
import os
import re
import shutil
import subprocess
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pdf_report  # noqa: E402
from test_status_semantics import DOMAIN, MONITORING, _js_functions, _zone  # noqa: E402


def _plan_text(result):
    pages = [" ".join((p.extract_text() or "").split()) for p in
             PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages]
    start = next(i for i, p in enumerate(pages) if "The plan" in p and "Across " in p)
    end = next(i for i, p in enumerate(pages) if "Part 2: Appendix" in p)
    return " ".join(pages[start:end])


@pytest.fixture
def result(audit):
    # p=none with rua: two important DMARC rows, and MTA-STS, TLS-RPT and
    # DANE not set up.
    return audit(_zone(f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}"), DOMAIN, dkim_selector="s1")


def test_optional_rows_are_labelled_optional_and_listed_last(result):
    items = result["security_roadmap"]["items"]
    extras = [i for i in items if i["optional"]]
    assert {i["protocol"] for i in extras} == {"MTA-STS", "TLS-RPT", "DANE"}
    assert all(i["priority"] == "medium" for i in extras)

    text = _plan_text(result)
    heading = text.index(f"Optional extras ({len(extras)})")
    for item in items:
        at = text.index(item["action"])
        assert (at > heading) == item["optional"], item["action"]
    # Each extra carries the Optional label, and no row says MEDIUM.
    assert "MEDIUM" not in text
    assert text[heading:].count("OPTIONAL") >= len(extras)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_tier_bar_counts_what_the_web_heading_counts(result):
    program = _js_functions("isOptionalPlanItem", "planCounts", "priorityTierSummary") + """
const OPTIONAL_PROTOCOLS = ['MTA-STS', 'TLS-RPT', 'BIMI', 'DNSSEC', 'CAA', 'DANE'];
const rm = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(priorityTierSummary(rm));
"""
    web = subprocess.run(["node", "-e", program],
                         input=__import__("json").dumps(result["security_roadmap"]),
                         capture_output=True, text=True, timeout=60, check=True).stdout
    assert "3 optional" in web, web

    text = _plan_text(result)
    bar = dict((label, int(n)) for n, label in
               re.findall(r"(\d+) (FIX NOW|IMPORTANT|RECOMMENDED|OPTIONAL)", text)[:4])
    # All four tiers must be on the bar, or the loop below checks nothing.
    assert set(bar) == {"FIX NOW", "IMPORTANT", "RECOMMENDED", "OPTIONAL"}, text[:600]
    words = {"FIX NOW": "to fix now", "IMPORTANT": "important",
             "RECOMMENDED": "recommended", "OPTIONAL": "optional"}
    for label, n in bar.items():
        if n:
            assert f"{n} {words[label]}" in web, (label, n, web)
        else:
            assert words[label] not in web, (label, web)


def test_a_plan_with_no_extras_has_no_extras_heading(audit):
    result = audit(_zone(MONITORING), DOMAIN, dkim_selector="s1")
    for item in result["security_roadmap"]["items"]:
        item["optional"] = False
    assert "Optional extras" not in _plan_text(result)
