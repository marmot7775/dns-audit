"""Doc 52: the PDF is set in the site's typefaces.

DM Sans for text and JetBrains Mono for records, embedded as subsets from
fonts/ at the repo root. DM Sans has no check or cross glyph, so those two
are set in JetBrains Mono. A missing font file falls back to ReportLab's
built-in Helvetica and Courier with one warning instead of failing the
endpoint.
"""
import io
import logging
import os
import sys

from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
from test_ui_consistency_a11y import DOMAIN, _run, _zone

# The Doc 45 long record: 25 rua addresses on one DMARC line.
_RUA25 = ",".join(f"mailto:reports-{k}@{DOMAIN}" for k in range(25))


def _base_fonts(pdf_bytes):
    names = set()
    for page in PdfReader(io.BytesIO(pdf_bytes)).pages:
        for ref in page["/Resources"].get("/Font", {}).values():
            names.add(str(ref.get_object()["/BaseFont"]).lstrip("/"))
    return names


def _text(pdf_bytes):
    return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf_bytes)).pages)


def test_the_pdf_embeds_dm_sans_and_jetbrains_mono_only():
    pdf = pdf_report.generate_pdf(_run(_zone()))
    names = _base_fonts(pdf)

    for face in ("DMSans", "DMSans-Bold", "JetBrainsMono"):
        assert any(face in n for n in names), (face, names)
    assert not any("Helvetica" in n or "Courier" in n for n in names), names
    assert len(pdf) < 250 * 1024, f"{len(pdf)} bytes: a full font was embedded, not a subset"


def test_check_cross_and_bullet_glyphs_reach_the_text():
    text = _text(pdf_report.generate_pdf(_run(_zone())))

    for glyph in ("✓", "✗", "•"):
        assert glyph in text, f"U+{ord(glyph):04X} missing from the PDF text"


def test_the_long_record_fixture_renders_in_the_site_faces():
    pdf = pdf_report.generate_pdf(_run(_zone(dmarc=f"v=DMARC1; p=reject; rua={_RUA25}")))

    assert pdf[:5] == b"%PDF-"
    assert any("JetBrainsMono" in n for n in _base_fonts(pdf))
    assert len(pdf) < 250 * 1024


def test_a_missing_font_directory_falls_back_to_helvetica(tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="dns-auditor.pdf"):
        fonts = pdf_report._load_fonts(str(tmp_path))
    assert fonts["sans"] == "Helvetica" and fonts["mono"] == "Courier"
    assert len([r for r in caplog.records if "PDF fonts not loaded" in r.getMessage()]) == 1

    monkeypatch.setattr(pdf_report, "FONTS", fonts)
    pdf = pdf_report.generate_pdf(_run(_zone()))
    names = _base_fonts(pdf)

    assert pdf[:5] == b"%PDF-"
    assert "Helvetica" in names, names
    assert not any("DMSans" in n or "JetBrainsMono" in n for n in names), names


def test_font_paths_do_not_depend_on_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fonts = pdf_report._load_fonts()

    assert fonts["sans"] == "DMSans"
