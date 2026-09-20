"""Doc 67: every check says what it is before it says what it found.

A reader who knows DNS and not email met twelve cards that named a protocol,
a status and a finding, and the only definition anywhere was a hover tooltip
that a phone never showed and the PDF never carried. The text now lives in
result_transformer.WHAT_THIS_IS, reaches the page and the PDF from there, and
the tooltip is gone.

The browser checks render the Doc 38 fixture zone in headless Chromium
through renderResults(), the way tests/test_ui_consistency_a11y.py does; they
skip where Chromium is not installed, and CI installs it.
"""
import copy
import io
import json
import os
import re
import sys

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report  # noqa: E402
import result_transformer as rt  # noqa: E402
import test_ui_consistency_a11y as ui  # noqa: E402
from result_transformer import WHAT_THIS_IS, transform_ct  # noqa: E402
from test_tone_and_repetition import BANNED  # noqa: E402

_page = ui._page
_render = ui._render
browser = ui.browser
fixture_result = ui.fixture_result
DOMAIN = ui.DOMAIN

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The twelve cards a complete run produces, by the names the cards carry.
TWELVE = [
    "DMARC", "SPF", "DKIM", "MX Records", "Nameservers", "MTA-STS",
    "TLS-RPT", "DANE", "DNSSEC", "CAA", "BIMI", "Certificate Transparency",
]


# ---------------------------------------------------------------
# One source for the text
# ---------------------------------------------------------------

def test_the_dict_covers_the_twelve_checks_and_nothing_else():
    assert sorted(WHAT_THIS_IS) == sorted(TWELVE)


def test_every_check_carries_its_line_and_the_string_matches_the_dict(fixture_result):
    names = [c["name"] for c in fixture_result["checks"]]
    assert sorted(names) == sorted(TWELVE), names
    for check in fixture_result["checks"]:
        text = check.get("what_this_is")
        assert text, f"{check['name']} carries no what_this_is"
        assert text == WHAT_THIS_IS[check["name"]], check["name"]


def test_each_line_is_two_sentences_of_plain_text():
    for name, text in WHAT_THIS_IS.items():
        assert "<" not in text and ">" not in text, name
        assert len(re.findall(r"[.!?](?:\s|$)", text)) == 2, f"{name}: {text!r}"


def test_a_check_the_dict_does_not_carry_is_left_alone():
    checks = [{"name": "Kittens"}, {"name": "DMARC"}]
    rt.attach_what_this_is(checks)
    assert "what_this_is" not in checks[0]
    assert checks[1]["what_this_is"] == WHAT_THIS_IS["DMARC"]


@pytest.mark.parametrize("phrase", BANNED)
def test_the_new_strings_pass_the_banned_string_list(phrase):
    hits = [name for name, text in WHAT_THIS_IS.items() if phrase in text]
    assert hits == [], f"{phrase!r} in {hits}"


def test_the_tooltip_dict_and_its_styles_are_gone():
    with open(os.path.join(REPO, "static", "app.js"), encoding="utf-8") as f:
        app_js = f.read()
    with open(os.path.join(REPO, "static", "style.css"), encoding="utf-8") as f:
        css = f.read()
    assert "PROTOCOL_TOOLTIPS" not in app_js
    assert "data-tooltip" not in app_js
    assert "protocol-name-tip" not in app_js
    assert "protocol-name-tip" not in css


# ---------------------------------------------------------------
# Where it shows: the page
# ---------------------------------------------------------------

@pytest.mark.parametrize("theme", ["dark", "light"])
def test_each_card_opens_with_the_two_labelled_parts(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, fixture_result)
        cards = page.evaluate("""() => [...document.querySelectorAll('.result-card')].map(c => {
            const inner = c.querySelector('.result-body-inner');
            const labels = [...inner.querySelectorAll('.check-part-label')]
                .map(l => l.textContent.trim());
            const line = inner.querySelector('.what-this-is');
            const kids = [...inner.children].map(k => k.className.split(' ')[0]);
            return {
                name: c.querySelector('.result-title').textContent.trim(),
                labels,
                line: line ? line.textContent.trim() : null,
                firstThree: kids.slice(0, 3),
                titleHasTooltip: !!c.querySelector('.result-title[data-tooltip]'),
            };
        })""")
        assert len(cards) == 12, [c["name"] for c in cards]
        by_name = {c["name"]: c for c in cards}
        assert sorted(by_name) == sorted(TWELVE)
        for name, card in by_name.items():
            assert card["labels"][:2] == ["What this is", "What we found"], (name, card["labels"])
            assert card["line"] == WHAT_THIS_IS[name], name
            assert card["firstThree"] == ["check-part-label", "what-this-is",
                                          "check-part-label"], (name, card["firstThree"])
            assert not card["titleHasTooltip"], name
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_check_with_no_line_renders_no_label_and_no_line(browser, fixture_result, theme):
    data = copy.deepcopy(fixture_result)
    for check in data["checks"]:
        if check["name"] == "CAA":
            del check["what_this_is"]
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, data)
        m = page.evaluate("""() => {
            const caa = document.querySelector('#check-caa .result-body-inner');
            return {
                labels: caa.querySelectorAll('.check-part-label').length,
                lines: caa.querySelectorAll('.what-this-is').length,
                explanations: caa.querySelectorAll('.explanation').length,
                others: document.querySelectorAll('.what-this-is').length,
            };
        }""")
        assert m["labels"] == 0 and m["lines"] == 0
        assert m["explanations"] >= 1, "the CAA card lost its explanation too"
        assert m["others"] == 11
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Where it shows: the PDF
# ---------------------------------------------------------------

def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join(" ".join(p.extract_text() or "" for p in reader.pages).split())


@pytest.fixture(scope="module")
def pdf_text(fixture_result):
    return _pdf_text(fixture_result)


def test_the_checks_section_carries_the_label_once_per_check(pdf_text):
    assert pdf_text.count("What this is") == 12


def test_every_line_reaches_the_pdf(pdf_text):
    for name, text in WHAT_THIS_IS.items():
        flat = " ".join(text.split())
        assert flat in pdf_text, name


def test_the_appendix_still_carries_the_long_explanations(fixture_result, pdf_text):
    assert "What each check means" in pdf_text
    for check in fixture_result["checks"]:
        explanation = pdf_report._strip_html(check.get("explanation") or "")
        if not explanation:
            continue
        head = " ".join(explanation.split())[:60]
        assert head in pdf_text, check["name"]


def test_a_check_with_no_line_prints_no_label_in_the_pdf(fixture_result):
    data = copy.deepcopy(fixture_result)
    for check in data["checks"]:
        if check["name"] == "CAA":
            del check["what_this_is"]
    text = _pdf_text(data)
    assert text.count("What this is") == 11
    assert " ".join(WHAT_THIS_IS["CAA"].split()) not in text


# ---------------------------------------------------------------
# The last duplicate: one CAA mismatch line, the engine's wording
# ---------------------------------------------------------------

def _ct_raw_with_a_mismatch():
    """Run the engine's own CT analysis over a fake crt.sh response.

    The mismatch detail and the issue that repeated it are both built in
    that function, so the fixture has to come through it rather than be
    hand-written.
    """
    import audit_engine
    import requests

    later = "2030-01-01T00:00:00"
    rows = [{
        "serial_number": "01",
        "issuer_name": "C=US, O=Acme, CN=Acme R1",
        "common_name": f"www.{DOMAIN}",
        "name_value": f"www.{DOMAIN}",
        "not_before": "2026-01-01T00:00:00",
        "not_after": later,
    }]

    class _Resp:
        status_code = 200
        text = json.dumps(rows)
        content = text.encode()

        def raise_for_status(self):
            pass

        def json(self):
            return rows

    real_get = requests.get
    requests.get = lambda *a, **kw: _Resp()
    try:
        return audit_engine._raw_check_ct_uncached(
            DOMAIN, {"caa": {"authorized_cas": ["digicert.com"]}})
    finally:
        requests.get = real_get


def test_the_ct_card_prints_the_caa_mismatch_once_in_the_engines_words():
    raw = _ct_raw_with_a_mismatch()
    assert raw["caa_mismatches"], "the fixture produced no CAA mismatch"

    card = transform_ct(raw, DOMAIN)
    texts = [d["text"] for d in card["details"]]
    mismatch = [t for t in texts if "Acme R1" in t and "CAA" in t]
    assert len(mismatch) == 1, mismatch
    assert mismatch[0].startswith("CT logs show certificates issued by Acme R1"), mismatch[0]
    assert "CAA only allows: digicert.com" in mismatch[0]
    assert not any(t.startswith("CAA allows [") for t in texts), texts


def test_the_caa_mismatch_fix_text_is_unchanged():
    card = transform_ct(_ct_raw_with_a_mismatch(), DOMAIN)
    assert "Acme R1" in card["fix"]
    assert "add them to your CAA record" in card["fix"]
