"""The page's PDF button downloads the report without its appendix.

PDF Report is Part 1 (short answer, plan, checks) and the About page; Full
report adds Part 2, the technical appendix (2026-10-25). Nothing in the
short report points at an appendix it does not carry.
"""
import io
import os
import sys

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
from conftest import fake_dns
from test_dmarc_grades import DOMAIN, RUA, _run, _zone


def _text(pdf):
    reader = PdfReader(io.BytesIO(pdf))
    return len(reader.pages), " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)


@pytest.mark.parametrize("scope", ["deliverability", "complete"])
def test_the_short_report_has_no_appendix_and_no_pointer_to_one(audit, scope):
    result = _run(audit, f"v=DMARC1; p=none; {RUA}", scope=scope)
    full_pages, full = _text(pdf_report.generate_pdf(result))
    short_pages, short = _text(pdf_report.generate_pdf(result, appendix=False))
    assert "Part 2: Appendix" in full
    assert short_pages < full_pages
    for gone in ("Part 2", "Appendix", "DMARC in depth", "Tag-by-Tag"):
        assert gone not in short, gone
    for kept in ("The short answer", "What to do", "About this report",
                 "linkedin.com/in/neilanuskiewicz"):
        assert kept in short, kept


def test_the_endpoint_takes_appendix(monkeypatch):
    import audit_engine
    import server as server_module
    monkeypatch.setattr(server_module, "RATE_LIMIT_MAX", 10_000)
    monkeypatch.setattr(server_module, "_cache", {})
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "run_full_audit", audit_engine.run_full_audit)
    with fake_dns(_zone(f"v=DMARC1; p=none; {RUA}")):
        c = TestClient(server_module.app)
        short = c.get(f"/api/audit/{DOMAIN}/pdf", params={"scope": "deliverability", "appendix": 0})
        full = c.get(f"/api/audit/{DOMAIN}/pdf", params={"scope": "deliverability"})
    assert short.status_code == full.status_code == 200
    assert "Part 2: Appendix" not in _text(short.content)[1]
    assert "Part 2: Appendix" in _text(full.content)[1]
    assert "-full.pdf" in full.headers["content-disposition"]
    assert "-full.pdf" not in short.headers["content-disposition"]
