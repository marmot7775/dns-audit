"""A box taller than a page breaks across pages instead of failing the PDF.

ReportLab cannot break a table inside a row unless splitInRow is set. On
9 Oct 2026 github.com's DKIM record made one cell 688pt on a 686pt frame,
ReportLab raised LayoutError and /api/audit/{domain}/pdf returned 500
(fixed for that block in 9222dcb). The Table subclass now defaults
splitInRow to 1, so every one-cell box (callouts, verdicts, remediation
steps, the brand box) can split. This test repeats every long string so
those boxes outgrow a page; before the default it raised LayoutError.
"""
import copy
import os
import sys

import pytest

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


def _inflate(obj, n):
    if isinstance(obj, dict):
        return {k: _inflate(v, n) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_inflate(v, n) for v in obj]
    if isinstance(obj, str) and len(obj) > 25 and not obj.startswith("http"):
        return " ".join([obj] * n)
    return obj


def test_table_defaults_to_split_in_row():
    assert pdf_report.Table([["x"]]).splitInRow == 1


def test_text_taller_than_a_page_still_renders(result):
    pdf = pdf_report.generate_pdf(_inflate(copy.deepcopy(result), 25))
    assert pdf[:5] == b"%PDF-"
