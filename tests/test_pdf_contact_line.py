"""
Doc 90: the PDF's About page ends with a way to reach the person who
built the tool: LinkedIn and the About page, both clickable, and no email
address anywhere in the document.
"""
import io
import os
import re
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pdf_report  # noqa: E402

DOMAIN = "example.com"
ZONE = {
    DOMAIN: {"NS": [f"ns1.{DOMAIN}"], "MX": [(10, f"mx1.{DOMAIN}")],
             "TXT": ["v=spf1 mx -all"]},
    f"mx1.{DOMAIN}": {"A": ["203.0.113.11"]},
    f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject"]},
}


def _reader(audit):
    return PdfReader(io.BytesIO(pdf_report.generate_pdf(audit(ZONE, DOMAIN))))


def test_last_page_names_linkedin_and_the_about_page(audit):
    reader = _reader(audit)
    last = " ".join((reader.pages[-1].extract_text() or "").split())
    assert "Questions about this report? Neil Anuskiewicz built dns-audit.com" in last
    assert "linkedin.com/in/neilanuskiewicz" in last
    assert "dns-audit.com/about" in last
    uris = set()
    for annot in reader.pages[-1].get("/Annots") or []:
        action = annot.get_object().get("/A") or {}
        if action.get("/URI"):
            uris.add(action["/URI"])
    assert {"https://www.linkedin.com/in/neilanuskiewicz/",
            "https://dns-audit.com/about"} <= uris


def test_the_pdf_carries_no_address_of_ours(audit):
    # The report suggests rua addresses at the audited domain; those are the
    # client's. No address at dns-audit.com, or any other of ours, appears.
    text = " ".join(p.extract_text() or "" for p in _reader(audit).pages)
    addresses = set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text))
    assert all(a.endswith("@" + DOMAIN) for a in addresses), addresses
