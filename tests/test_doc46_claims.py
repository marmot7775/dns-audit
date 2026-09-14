"""Doc 46: no generated string, page or README line claims what the RFC or
the vendor's own page contradicts.

The banned list pins every replaced sentence so none can come back. The
fixture cases run declared zones through run_full_audit, and the PDF where
the text reaches it, and check the replacement sentences land where they
should.
"""
import glob
import io
import json
import os
import re
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
import result_transformer as rt
from test_doc44_dmarc_grades import DOMAIN, RUA, _card, _run, _zone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BANNED = [
    "Safe to test",
    "close gaps in the old standard",
    "tightens parsing",
    "strictly required",
    "fall back to the Public Suffix List",
    "monitoring for 2 weeks",
    # The doc's own replacement says "not in the admin center", so the ban is
    # on the claim it replaced.
    "can be configured in the Microsoft 365 admin center",
    "no longer send failure reports",
    "treating your SPF as if",
    "Fails at most receivers",
    "30 or more days",
    "pass, warning, or fail",
    "(likely)",
]

SOURCES = (
    [os.path.join(REPO, f) for f in (
        "result_transformer.py", "audit_engine.py", "spf_recursive.py", "anomaly_detector.py",
        "checks_extra.py", "pdf_report.py", "README.md",
        "static/app.js", "static/index.html")]
    + glob.glob(os.path.join(REPO, "static", "articles", "*.html"))
)


def _flat(text):
    # Source strings are often split across adjacent literals; join them.
    return re.sub(r'"\s*\n\s*f?"', "", text)


@pytest.mark.parametrize("phrase", BANNED)
def test_no_replaced_sentence_comes_back(phrase):
    hits = []
    for path in SOURCES:
        with open(path, encoding="utf-8") as f:
            if phrase.lower() in _flat(f.read()).lower():
                hits.append(os.path.relpath(path, REPO))
    assert not hits, f"{phrase!r} is back in {hits}"


def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)


# ---------------------------------------------------------------
# Item 1: migration steps carry every tag and do not call t=y safe
# ---------------------------------------------------------------

def _migration_steps(card):
    bd = card["tag_breakdown"]
    return (bd.get("migration") or {}).get("steps", [])


def test_migration_steps_carry_every_tag(audit):
    card = _card(_run(audit, f"v=DMARC1; p=none; sp=none; adkim=r; aspf=r; {RUA}"))
    records = [s["record_after"] for s in _migration_steps(card) if s.get("record_after")]

    assert records, _migration_steps(card)
    for rec in records:
        assert rec.startswith("v=DMARC1; ")
        for tag in ("adkim=r", "aspf=r", f"rua=mailto:d@{DOMAIN}"):
            assert tag in rec, (tag, rec)
        assert "sp=" in rec, rec
    whys = " ".join(s["why"] for s in _migration_steps(card))
    assert "Receivers still on RFC 7489 ignore t and quarantine in full." in whys
    assert "Receivers still on RFC 7489 ignore t and reject in full." in whys


# ---------------------------------------------------------------
# Items 2 and 3: np is from RFC 9091; the tag notes say what the RFCs say
# ---------------------------------------------------------------

def test_np_row_is_marked_as_from_rfc_9091(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}")
    rows = {t["tag"]: t for t in _card(result)["tag_breakdown"]["tags"]}

    assert rows["np"]["dmarcbis"] == "imported"
    assert rows["psd"]["dmarcbis"] == "new" and rows["t"]["dmarcbis"] == "new"
    assert "Receivers determine the organizational domain with the tree walk." in rows["psd"]["explanation"]
    assert rows["v"]["dmarcbis_note"] == (
        "Both RFC 7489 and RFC 9989 require v=DMARC1 to be the first tag. "
        "A record with it anywhere else is not a DMARC record.")
    assert "From RFC 9091" in _pdf_text(result)


# ---------------------------------------------------------------
# Item 5: one PermError sentence
# ---------------------------------------------------------------

PERMERROR = ("Past 10 lookups, receivers must return PermError (RFC 7208 section 4.6.4). "
             "PermError is not a pass, so SPF cannot satisfy DMARC for any message from this domain.")


def test_over_limit_spf_uses_the_permerror_sentence(audit):
    spf = "v=spf1 " + " ".join(f"include:i{k}.{DOMAIN}" for k in range(11)) + " -all"
    extra = {f"i{k}.{DOMAIN}": {"TXT": ["v=spf1 -all"]} for k in range(11)}
    card = _card(_run(audit, f"v=DMARC1; p=reject; {RUA}", spf=spf, extra=extra), "SPF")

    assert any(PERMERROR in d["text"] for d in card["details"]), card["details"]
    assert "Fails at most receivers" not in card["verdict"]


# ---------------------------------------------------------------
# Items 4 and 7: vendor sentences, once per card
# ---------------------------------------------------------------

def test_google_yahoo_requirement_appears_once_on_the_no_dmarc_card(audit):
    card = _card(_run(audit, None))
    blob = re.sub(r"<[^>]+>", "", json.dumps(card))

    assert blob.count("rate limited, blocked, or sent to spam") == 1, card
    assert "rfc-editor.org/rfc/rfc9989.html" in card["explanation"]
    assert "deprioritize" not in blob and "throttled" not in blob


def test_bimi_gmail_sentence_appears_once(audit):
    card = _card(_run(audit, f"v=DMARC1; p=reject; {RUA}"), "BIMI")
    blob = json.dumps(card)

    assert blob.count("Gmail requires a certificate in the a= tag") == 1
    assert "requires a VMC for BIMI" not in blob and "domain-validated" not in blob


def test_capabilities_without_a_source_are_not_known():
    caps = rt._PROVIDER_META["google_workspace"]["capabilities"]
    assert caps["dkim_auto_rotation"] is None
    assert rt._PROVIDER_META["microsoft_365"]["capabilities"]["dkim_auto_rotation"] is True


def test_selector1_is_microsoft_only_with_evidence():
    key = "v=DKIM1; k=rsa; p=MIIB"
    txt_only = {"dkim": {"found_selectors": [{"selector": "selector1", "record": key}]}}
    cname = {"dkim": {"found_selectors": [{
        "selector": "selector1", "record": key,
        "cname_target": "selector1-contoso-com._domainkey.contoso.onmicrosoft.com"}]}}
    mx = dict(txt_only, mx={"records": ["0 contoso-com.mail.protection.outlook.com"]})

    assert "microsoft_365" not in rt._detect_providers(txt_only)
    assert "microsoft_365" in rt._detect_providers(cname)
    assert "microsoft_365" in rt._detect_providers(mx)
    analysis = rt._build_dkim_key_analysis(txt_only["dkim"])
    assert analysis["keys"][0]["provider"] == "Vendor: unknown", analysis["keys"][0]


# ---------------------------------------------------------------
# Item 8: surfaces agree with the cards
# ---------------------------------------------------------------

def test_absent_transport_cards_score_no_not_unknown(audit):
    features = rt._check_domain_features({}, _run(audit, f"v=DMARC1; p=reject; {RUA}")["checks"])

    assert (features["mta_sts"], features["tls_rpt"]) == ("no", "no"), features


def test_pdf_does_not_call_an_unenumerated_dkim_a_failed_lookup(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}"), DOMAIN)  # no selector supplied
    dkim = _card(result, "DKIM")
    text = _pdf_text(result)

    if dkim.get("unavailable_kind") != "not_enumerable":
        pytest.skip(f"DKIM was not left unconfirmed here: {dkim['status']}")
    assert ("Not confirmed: DKIM (no selector was supplied and the name cannot be "
            "enumerated from DNS)") in text
    assert not re.search(r"Not checked:[^()]*DKIM", text)


# ---------------------------------------------------------------
# Item 9: a domain that sends and receives no mail
# ---------------------------------------------------------------

def test_no_mx_no_spf_resilience_is_not_applicable(audit):
    from test_doc45_other_checks import _zone as zone45, D as D45
    result = audit(zone45(spf=None, mx=[], dkim=False), D45)
    res = result["resilience"]

    assert res["level"] == "not_applicable"
    assert res["summary"] == ("This domain does not send or receive mail. Publish v=spf1 -all "
                              "and a DMARC record at p=reject to stop others sending as it.")
