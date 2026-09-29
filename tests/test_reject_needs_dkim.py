"""A domain at p=reject with no DKIM key found gets a note (follow-up to Doc 81).

RFC 9989 sections 7.4 and 8: a domain that publishes p=reject MUST NOT rely
on SPF alone for a DMARC pass and MUST sign with DKIM, because forwarding
breaks SPF. The audit cannot see which streams sign, only which keys it
found, so the note is info level: it changes no status, verdict or plan row.
"""

import base64
import io
import re

import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pypdf import PdfReader

import pdf_report
from conftest import FakeZone
from result_transformer import REJECT_DKIM_NOTE_TITLE, attach_reject_dkim_note

D = "rejectdkim.test"
SUB = f"mail.{D}"
RUA = f"rua=mailto:dmarc@{D}"


def _key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


_P = _key()


def _zone(dmarc, dkim=False, mx=True, spf="v=spf1 mx -all", sub=False):
    records = {
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "TXT": [spf]},
        f"_dmarc.{D}": {"TXT": [dmarc]},
    }
    if mx:
        records[D]["MX"] = [(10, f"mx1.{D}")]
        records[f"mx1.{D}"] = {"A": ["203.0.113.11"]}
    else:
        records[D]["MX"] = [(0, ".")]
    if dkim:
        records[f"google._domainkey.{D}"] = {"TXT": ["v=DKIM1; k=rsa; p=" + _P]}
    if sub:
        records[SUB] = {"A": ["203.0.113.10"], "MX": [(10, f"mx1.{D}")],
                        "TXT": ["v=spf1 mx -all"]}
    zone = FakeZone(records)
    if sub:
        zone.fail(SUB, "SOA", dns.resolver.NoAnswer())
    return zone


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def _notes(result):
    cw = _dmarc(result)["tag_breakdown"]["config_warnings"]
    return [w for w in cw if w["title"] == REJECT_DKIM_NOTE_TITLE]


def test_reject_with_no_dkim_key_found_gets_the_note(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}"), D)
    notes = _notes(result)
    assert len(notes) == 1
    note = notes[0]
    assert note["level"] == "info"
    assert "RFC 9989 sections 7.4 and 8" in note["text"]
    assert "does not prove the domain is unsigned" in note["text"]
    assert "aligned DKIM pass" in note["text"]


def test_the_note_changes_no_grade_verdict_or_plan(audit):
    without = audit(_zone(f"v=DMARC1; p=reject; {RUA}"), D)
    signed = audit(_zone(f"v=DMARC1; p=reject; {RUA}", dkim=True), D)
    assert _notes(without) and not _notes(signed)
    a, b = _dmarc(without), _dmarc(signed)
    assert a["status"] == b["status"]
    assert a["tag_breakdown"]["health"] == b["tag_breakdown"]["health"]
    rows = [i for i in without["security_roadmap"]["items"]
            if REJECT_DKIM_NOTE_TITLE in (i.get("action") or "")]
    assert rows == []


def test_quarantine_and_none_get_no_note(audit):
    for p in ("quarantine", "none"):
        assert _notes(audit(_zone(f"v=DMARC1; p={p}; {RUA}"), D)) == [], p


def test_a_domain_that_sends_no_mail_gets_no_note(audit):
    # Null MX, null SPF, p=reject and no DKIM is the right setup for it.
    result = audit(_zone("v=DMARC1; p=reject", mx=False, spf="v=spf1 -all"), D)
    assert _notes(result) == []


def test_an_inherited_reject_gets_the_note(audit):
    result = audit(_zone(f"v=DMARC1; p=quarantine; sp=reject; {RUA}", sub=True), SUB)
    assert _dmarc(result)["effective_policy"] == "reject"
    assert len(_notes(result)) == 1


def test_an_inherited_quarantine_gets_no_note(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; sp=quarantine; {RUA}", sub=True), SUB)
    assert _dmarc(result)["effective_policy"] == "quarantine"
    assert _notes(result) == []


def _checks():
    return [
        {"name": "DMARC", "effective_policy": "reject",
         "tag_breakdown": {"config_warnings": []}},
        {"name": "DKIM", "status": "unavailable"},
    ]


def test_nothing_is_said_when_dkim_was_not_learned():
    # Out of scope, timed out, dropped queries, lookup unavailable.
    for raw in (None, {"found_selectors": [], "timed_out": True},
                {"found_selectors": [], "status": "unavailable"}):
        checks = attach_reject_dkim_note(_checks(), raw)
        assert checks[0]["tag_breakdown"]["config_warnings"] == [], raw
    checks = attach_reject_dkim_note(_checks()[:1], {"found_selectors": []})
    assert checks[0]["tag_breakdown"]["config_warnings"] == []


def test_retired_keys_alone_still_get_the_note():
    # An empty p= retires a key; nothing signs with it.
    raw = {"found_selectors": [{"selector": "old", "record": "v=DKIM1; p="}]}
    checks = attach_reject_dkim_note(_checks(), raw)
    assert [w["title"] for w in checks[0]["tag_breakdown"]["config_warnings"]] == [
        REJECT_DKIM_NOTE_TITLE]


def test_the_pdf_prints_the_note(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}"), D)
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages))
    assert REJECT_DKIM_NOTE_TITLE in text
