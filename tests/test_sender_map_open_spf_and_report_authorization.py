"""Sendermap 0.1.13's new risks and warnings, through every surface that shows them.

0.1.12 and 0.1.13 added: a bare `all` and an SPF term that matches every
address of a family (ip4:0.0.0.0/0, ip6:::/0, a/0, mx//0) are risks; a DMARC
report address outside the domain is credited only when its domain publishes
the <domain>._report._dmarc.<host> record (RFC 9990 section 4), and is a
warning otherwise; and two new optional fields (Checked.dkim_skipped, gap
kind dkim_stopped) that stay empty because the audit never passes
stop_early.

The map cites the domain's own SPF and DMARC records for these, which no
service claims, so the web map shows them under "Across the domain". The
PDF carries no map; it says the same through the SPF card (fail) and the
DMARC card (unauthorized destination). An unauthorized report service drops
out of the vendor panel, the page's and the PDF's alike. Real audits over a
fake zone, so nothing reaches the network.
"""
import io
import json
import os
import sys

import jsonschema
import pytest
import sendermap
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import pdf_report  # noqa: E402
from conftest import FakeZone, fake_dns  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser  # noqa: E402,F401

D = "open.test"
REPORT_HOST = "ag.dmarcian.com"


def _zone(spf, authorized=False):
    zone = {
        D: {"MX": [(1, "aspmx.l.google.com")], "TXT": [spf], "NS": [f"ns1.{D}"]},
        "_spf.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"]},
        f"_dmarc.{D}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:x@{REPORT_HOST}"]},
    }
    if authorized:
        zone[f"{D}._report._dmarc.{REPORT_HOST}"] = {"TXT": ["v=DMARC1"]}
    return zone


def _audit(spf, authorized=False, scope="senders"):
    with fake_dns(FakeZone(_zone(spf, authorized))):
        result = audit_engine.run_full_audit(D, scope=scope)
    # What the API sends: enums as their values.
    return json.loads(json.dumps(result, default=str))


def _findings(result, severity):
    return [f["title"] for f in result["sendermap"]["findings"] if f["severity"] == severity]


def _card(result, name):
    return next(c for c in result["checks"] if c.get("name") == name)


@pytest.mark.parametrize("spf,title", [
    ("v=spf1 include:_spf.google.com all", f"SPF at {D} authorizes every server"),
    ("v=spf1 include:_spf.google.com ip4:0.0.0.0/0 -all", f"SPF at {D} authorizes every IPv4 server"),
    ("v=spf1 include:_spf.google.com ip6:::/0 -all", f"SPF at {D} authorizes every IPv6 server"),
])
def test_an_spf_record_open_to_every_server_is_a_map_risk_and_fails_the_spf_card(spf, title):
    result = _audit(spf)
    assert title in _findings(result, "risk")
    assert _card(result, "SPF")["status"] == "fail"
    jsonschema.validate(result["sendermap"], sendermap.schema())


def test_an_unauthorized_report_address_is_a_warning_and_no_reporting_vendor():
    result = _audit("v=spf1 include:_spf.google.com -all")
    assert f"DMARC reports for {D} to {REPORT_HOST} are not authorized" in _findings(result, "warning")
    assert [v["name"] for v in result["vendors"] if v["role"] == "reporting"] == []
    assert _card(result, "DMARC")["status"] == "warn"


def test_an_authorized_report_address_is_credited_with_no_warning():
    result = _audit("v=spf1 include:_spf.google.com -all", authorized=True)
    assert not [t for t in _findings(result, "warning") if "not authorized" in t]
    assert [v["name"] for v in result["vendors"] if v["role"] == "reporting"] == ["DMARCian"]


def test_the_early_stop_fields_stay_empty_because_the_audit_never_stops_early():
    result = _audit("v=spf1 include:_spf.google.com -all")
    smap = result["sendermap"]
    assert all(not c.get("dkim_skipped") for c in smap["checked"])
    assert "dkim_stopped" not in {g["kind"] for g in smap["gaps"]}


def test_the_pdf_says_what_the_map_says():
    result = _audit("v=spf1 include:_spf.google.com all")
    pdf = pdf_report.generate_pdf(result, appendix=False)
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in PdfReader(io.BytesIO(pdf)).pages)
    assert "authorizes every server" in text
    assert "not authorized" in text and REPORT_HOST in text
    # The vendor list is the panel's: no credit for the unauthorized address.
    assert "DMARCian" not in text


@pytest.mark.parametrize("theme,width", [("dark", 1280), ("light", 375)])
def test_the_web_map_shows_them_across_the_domain(browser, theme, width):  # noqa: F811
    result = _audit("v=spf1 include:_spf.google.com all")
    ctx, page, errors = _page(browser, theme, width)
    try:
        _render(page, result)
        box = page.inner_text(".smap-domain-findings")
        assert "authorizes every server" in box
        assert f"to {REPORT_HOST} are not authorized" in box
        assert page.evaluate("() => document.documentElement.scrollWidth") == width
        assert not errors, errors
    finally:
        ctx.close()
