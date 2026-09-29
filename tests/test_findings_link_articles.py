"""Doc 86: five findings end with one sentence linking to the article that
answers them.

Each finding is checked on a real audit twice: the link is there when the
finding fires, and absent on the same domain when it does not. A last test
runs a spread of zones and checks that no clean card carries an article link.
"""
import io
import json
import os
import re
import sys

import dns.resolver
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pdf_report  # noqa: E402
import result_transformer as rt  # noqa: E402
import test_ui_consistency_a11y as ui  # noqa: E402
from conftest import FakeZone  # noqa: E402

# The headless browser the Doc 48 tests set up; skips where Chromium is absent.
browser = ui.browser

D = "links.test"
SUB = f"mail.{D}"
RUA = f"rua=mailto:dmarc@{D}"
KEY = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxkQ3E9J8m0mNQn1s5y3Kc2Wv"
       "Jb6x0nY8m1Uq3e6k0yq5Yp9n7m0x6c2q1s4r8t0u2w4y6a8c0e2g4i6k8m0o2q4s6u8"
       "w0y2a4c6e8g0i2k4m6o8q0s2u4w6y8a0c2e4g6i8k0m2o4q6s8u0w2y4a6c8e0g2i4k6"
       "m8o0q2s4u6w8y0a2c4e6g8i0k2m4o6q8s0u2w4y6a8c0e2g4i6k8m0o2q4s6u8w0y2a4"
       "c6e8g0i2k4m6o8q0s2u4w6y8a0c2e4g6i8k0m2o4q6s8u0w2y4a6c8e0g2i4k6m8o0q2"
       "s4u6w8y0IDAQAB")


def _zone(dmarc=f"v=DMARC1; p=reject; {RUA}", lookups=1, dkim=True,
          dnssec=True, tlsa=False, mx=True, sub=False):
    records = {
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "A": ["203.0.113.1"],
            "TXT": ["v=spf1 " + " ".join(f"a:h{i}.{D}" for i in range(lookups)) + " -all"]},
        f"_dmarc.{D}": {"TXT": [dmarc]},
        f"ns1.{D}": {"A": ["203.0.113.53"]},
        f"ns2.{D}": {"A": ["198.51.100.53"]},
    }
    for i in range(lookups):
        records[f"h{i}.{D}"] = {"A": ["203.0.113.3"]}
    if mx:
        records[D]["MX"] = [(10, f"mx1.{D}")]
        records[f"mx1.{D}"] = {"A": ["203.0.113.11"]}
    else:
        records[D]["MX"] = []
    if dkim:
        records[f"google._domainkey.{D}"] = {"TXT": ["v=DKIM1; k=rsa; p=" + KEY]}
    if dnssec:
        records[D]["DNSKEY"] = [13]
    if tlsa:
        records[f"_25._tcp.mx1.{D}"] = {"TLSA": [(3, 1, 1, "aa" * 32)]}
    if sub:
        records[SUB] = {"A": ["203.0.113.10"], "MX": [(10, f"mx1.{D}")],
                        "TXT": ["v=spf1 mx -all"]}
    zone = FakeZone(records)
    if sub:
        zone.fail(SUB, "SOA", dns.resolver.NoAnswer())
    return zone


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def _card_html(card):
    """Every string on the card that a renderer can show as markup."""
    parts = [card.get("explanation") or ""]
    parts += [d.get("text") or "" for d in card.get("details") or []]
    tb = card.get("tag_breakdown") or {}
    parts += [w.get("text") or "" for w in tb.get("config_warnings") or []]
    return " ".join(parts)


def _links(card):
    return re.findall(r'href="(/articles/[^"]*)"', _card_html(card))


# 1. SPF lookup count ------------------------------------------------------

def test_spf_over_and_near_link_the_lookup_article(audit):
    for lookups in (9, 10, 11):
        card = _card(audit(_zone(lookups=lookups), D), "SPF")
        assert "/articles/spf-lookups" in _links(card), lookups
        assert rt.ARTICLE_SPF_LOOKUPS in card["explanation"], lookups
    card = _card(audit(_zone(lookups=8), D), "SPF")
    assert "/articles/spf-lookups" not in _links(card)


# 2. DKIM required at p=reject --------------------------------------------

def test_reject_dkim_note_links_the_p_reject_article(audit):
    card = _card(audit(_zone(dkim=False), D), "DMARC")
    notes = [w for w in card["tag_breakdown"]["config_warnings"]
             if w["title"] == rt.REJECT_DKIM_NOTE_TITLE]
    assert len(notes) == 1 and notes[0]["html"] is True
    assert notes[0]["text"].endswith(rt.ARTICLE_P_REJECT)
    card = _card(audit(_zone(dkim=True), D), "DMARC")
    assert "/articles/p-reject" not in _links(card)


# 3. RFC 9989: pct row and inherited tree walk ----------------------------

def test_pct_row_links_the_dmarcbis_article(audit):
    card = _card(audit(_zone(dmarc=f"v=DMARC1; p=quarantine; pct=50; {RUA}"), D), "DMARC")
    rows = [d for d in card["details"] if d.get("tag") == "pct"]
    assert len(rows) == 1 and rows[0]["html"] is True
    assert rows[0]["text"].endswith(rt.ARTICLE_DMARCBIS)
    card = _card(audit(_zone(dmarc=f"v=DMARC1; p=quarantine; {RUA}"), D), "DMARC")
    assert "/articles/dmarcbis" not in _links(card)


def test_tree_walk_inheritance_links_the_dmarcbis_article(audit):
    zone = _zone(dmarc=f"v=DMARC1; p=quarantine; sp=reject; {RUA}", sub=True)
    card = _card(audit(zone, SUB), "DMARC")
    assert card.get("inherited_from")
    assert "tree walk" in card["explanation"]
    assert card["explanation"].rstrip().endswith(rt.ARTICLE_DMARCBIS)
    # The organizational domain itself inherits nothing.
    card = _card(audit(zone, D), "DMARC")
    assert "/articles/dmarcbis" not in _links(card)


def test_the_plan_never_carries_an_article_link(audit):
    for zone in (_zone(dmarc=f"v=DMARC1; p=quarantine; pct=50; {RUA}"),
                 _zone(dkim=False), _zone(lookups=11), _zone(dnssec=False)):
        result = audit(zone, D)
        for item in result["security_roadmap"]["items"]:
            assert "/articles/" not in repr(item), item


# 4. DNSSEC ---------------------------------------------------------------

def test_dnssec_links_the_dnssec_article_unless_it_passes(audit):
    for zone in (_zone(dnssec=False), _zone(dnssec=True)):
        card = _card(audit(zone, D), "DNSSEC")
        assert card["status"] != "pass", card["verdict"]
        assert card["explanation"].endswith(rt.ARTICLE_DNSSEC), card["verdict"]
    card = rt.transform_dnssec({
        "has_dnssec": True, "dnssec_state": "secure", "key_count": 2,
        "algorithms": [{"number": 13, "name": "ECDSAP256SHA256", "deprecated": False}],
        "has_ds": True, "validated_by_resolver": True, "issues": [], "status": "ok",
    }, D)
    assert card["status"] == "pass", card["verdict"]
    assert "/articles/" not in _card_html(card)


# 5. DANE -----------------------------------------------------------------

def test_dane_links_the_dane_article_except_with_no_mx(audit):
    card = _card(audit(_zone(tlsa=False), D), "DANE")
    assert card["status"] != "pass"
    assert card["explanation"].endswith(rt.ARTICLE_DANE)
    no_mx = _card(audit(_zone(mx=False), D), "DANE")
    assert no_mx["status"] != "pass"
    assert "/articles/dane" not in _links(no_mx)


def test_dane_pass_card_has_no_link():
    card = rt.transform_dane({
        "has_tlsa": True, "dnssec_validated": True, "mx_hosts_checked": 1,
        "mx_hosts_with_tlsa": 1,
        "tlsa_records": [{
            "mx_host": f"mx1.{D}", "found": True, "validated": True,
            "records": [{"usage_name": "DANE-EE", "selector_name": "SPKI",
                         "matching_type_name": "SHA-256"}],
        }],
        "issues": [],
    }, D)
    assert card["status"] == "pass", card["verdict"]
    assert "/articles/" not in _card_html(card)


# Every link, and clean cards ----------------------------------------------

def test_links_use_the_rfc_anchor_form():
    for sentence in rt.ARTICLE_SENTENCES:
        assert re.search(r'<a href="/articles/[a-z-]+" target="_blank" '
                         r'rel="noopener">[^<]+</a>', sentence), sentence


def test_no_clean_card_carries_an_article_link(audit):
    """A pass card carries a link only when one of the Doc 86 findings sits
    on it: the p=reject note and an inherited tree-walk explanation are info,
    and leave the DMARC card at pass on purpose."""
    zones = [(_zone(), D), (_zone(lookups=11), D), (_zone(dkim=False), D),
             (_zone(dnssec=False, tlsa=True), D), (_zone(mx=False), D),
             (_zone(dmarc=f"v=DMARC1; p=none; pct=50; {RUA}"), D),
             (_zone(dmarc=f"v=DMARC1; p=quarantine; sp=reject; {RUA}", sub=True), SUB)]
    fired = {"DMARC": ("/articles/p-reject", "/articles/dmarcbis"),
             "SPF": ("/articles/spf-lookups",)}
    for zone, name in zones:
        for card in audit(zone, name)["checks"]:
            if card.get("status") != "pass":
                continue
            stray = [p for p in _links(card) if p not in fired.get(card["name"], ())]
            assert stray == [], (name, card["name"], stray)
    clean = audit(_zone(), D)
    for card in clean["checks"]:
        if card.get("status") == "pass":
            assert _links(card) == [], card["name"]


def test_the_pdf_prints_link_text_not_markup(audit):
    result = audit(_zone(dkim=False, dnssec=False,
                         dmarc=f"v=DMARC1; p=reject; pct=50; {RUA}"), D)
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages))
    assert "What to check before you publish p=reject covers this" in text
    assert "What RFC 9989 changes for your DMARC record explains" in text
    assert "href=" not in text and "&lt;a" not in text and "<a " not in text


# The page ---------------------------------------------------------------

def test_the_page_renders_each_link_as_a_link(audit, browser):
    """Detail rows and config warnings are escaped unless flagged html, and
    the sanitizer used to drop every href that was not http(s). Both would
    have shown the reader markup or a dead link."""
    result = audit(_zone(dkim=False, dnssec=False, lookups=11,
                         dmarc=f"v=DMARC1; p=reject; pct=50; {RUA}"), D)
    data = json.loads(json.dumps(result, default=str))
    ctx, page, errors = ui._page(browser, "dark", 1280)
    ui._render(page, data)
    hrefs = page.evaluate("""() => Array.from(
        document.querySelectorAll('#results-list a[href^="/articles/"]'))
        .map(a => [a.getAttribute('href'), a.target])""")
    text = page.evaluate("() => document.getElementById('results-list').textContent")
    ctx.close()
    got = {h for h, _ in hrefs}
    assert {"/articles/spf-lookups", "/articles/p-reject", "/articles/dmarcbis",
            "/articles/dnssec", "/articles/dane"} <= got, hrefs
    assert all(t == "_blank" for _, t in hrefs)
    assert "href=" not in text and "<a " not in text
    assert errors == []
