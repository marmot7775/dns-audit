"""No-mail domains, the pass disposition, BIMI escaping and RFC chip labels (Doc 78).

Five findings from the Doc 75 review:
- on a null MX domain with v=spf1 -all, the DMARC Evaluation said SPF gave
  "a path to DMARC pass" and ended with the RFC 9989 mailing list note,
  although -all authorizes no host and the domain sends nothing;
- the resilience block called DKIM inconclusive ("may well be configured")
  beside a DKIM card reading N/A;
- "no action requested" sat beside policy: reject, where it read as the
  policy's effect instead of what happens to passing mail;
- the BIMI plan row printed "&lt;svg&gt;" on the page and in the PDF;
- three link chips were lowercase ("rfc7208", "rfc9989", "rfc9990 &sect;4").
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import _pdf_text
from test_non_dmarc_checks import _BIMI, _run, _zone
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

NM = "nomail.test"
# Relative dimensions and no viewBox: the BIMI card warns, and its fix names
# the root <svg> element.
_RELATIVE_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
                 'baseProfile="tiny-ps" width="100%" height="100%"><title>x</title></svg>')

_OPEN_ALL_JS = """() => {
    document.querySelectorAll('.result-header').forEach(h => h.click());
    document.querySelectorAll('.cd-body.is-hidden').forEach(b => b.classList.remove('is-hidden'));
    document.querySelectorAll('.priority-body.is-hidden').forEach(b => b.classList.remove('is-hidden'));
    // Doc 92: optional extras (BIMI among them) sit in a closed group.
    document.querySelectorAll('.plan-optional-toggle[aria-expanded="false"]').forEach(t => t.click());
}"""


def _json(result):
    return json.loads(json.dumps(result, default=str))


@pytest.fixture
def no_mail(audit):
    return _json(audit({
        NM: {"MX": [(0, ".")], "TXT": ["v=spf1 -all"], "A": ["203.0.113.9"],
             "NS": [f"ns1.{NM}"]},
        f"_dmarc.{NM}": {"TXT": ["v=DMARC1; p=reject;"]},
    }, NM))


@pytest.fixture
def reject_bimi(audit):
    # p=reject with SPF and DKIM both configured, so DMARC can pass.
    return _json(_run(audit, _zone(extra=_BIMI), bimi_logo=_RELATIVE_SVG))


# --- No-mail domain ----------------------------------------------------------

def test_null_spf_is_not_a_path_to_dmarc_pass(no_mail):
    ev = no_mail["dmarc_eval"]
    assert ev["no_mail"] is True
    assert ev["spf_aligned"] is False
    assert ev["spf_result"] == "authorizes no servers"
    assert "path to DMARC pass" not in ev["explanation"]
    assert ev["explanation"].startswith("SPF authorizes no servers")


def test_resilience_dkim_is_not_applicable_like_the_card(no_mail):
    dkim_card = next(c for c in no_mail["checks"] if c["name"] == "DKIM")
    assert dkim_card["pill_label"] == "N/A"
    mech = no_mail["resilience"]["mechanisms"]["dkim"]
    assert mech["status"] == "not_applicable"
    assert "may well be configured" not in mech["note"]


def test_no_mail_page_has_no_pass_path_or_mailing_list_note(browser, no_mail):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, no_mail)
        page.evaluate(_OPEN_ALL_JS)
        assert page.query_selector(".dmarc-eval") is not None
        assert page.query_selector(".de-mailing-list-note") is None
        body = page.inner_text("#results-list")
        assert "path to DMARC pass" not in body
        assert "SPF authorizes no servers" in body
        spf_row = page.inner_text(".dmarc-eval .de-row")
        assert "alignment possible" not in spf_row
        mech = page.eval_on_selector_all(
            ".resilience-mech", "els => els.map(e => e.innerText)")
        dkim = [m for m in mech if m.startswith("DKIM")]
        assert dkim and "Inconclusive" not in dkim[0] and "Not applicable" in dkim[0]
        assert not errors, errors
    finally:
        ctx.close()


# --- Pass disposition --------------------------------------------------------

def test_reject_page_does_not_say_no_action_requested(browser, reject_bimi):  # noqa: F811
    ev = reject_bimi["dmarc_eval"]
    assert ev["policy"] == "reject" and ev["dmarc_result"] == "configured"
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, reject_bimi)
        page.evaluate(_OPEN_ALL_JS)
        body = page.inner_text("#results-list")
        assert "no action requested" not in body
        assert "passing mail gets no DMARC action" in page.inner_text(".de-disposition")
        # A sending domain at p=reject still gets the mailing list note.
        assert page.query_selector(".de-mailing-list-note") is not None
        assert not errors, errors
    finally:
        ctx.close()


# --- BIMI plan row -----------------------------------------------------------

def _bimi_row(result):
    rows = [i for i in result["security_roadmap"]["items"] if i["protocol"] == "BIMI"]
    assert rows
    return rows[0]


def test_bimi_plan_row_is_plain_text(reject_bimi):
    action = _bimi_row(reject_bimi)["action"]
    assert "<svg>" in action
    assert "&lt;" not in action and "&gt;" not in action


def test_bimi_plan_row_reads_svg_in_the_pdf(reject_bimi):
    text = _pdf_text(reject_bimi)
    assert "root <svg> element" in text
    assert "&lt;svg&gt;" not in text


def test_bimi_plan_row_reads_svg_on_the_page(browser, reject_bimi):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, reject_bimi)
        page.evaluate(_OPEN_ALL_JS)
        plan = page.inner_text("#priorities-list") if page.query_selector("#priorities-list") \
            else page.inner_text("body")
        assert "root <svg> element" in plan
        assert "&lt;svg&gt;" not in page.inner_text("body")
        assert not errors, errors
    finally:
        ctx.close()


# --- RFC chip labels ---------------------------------------------------------

@pytest.mark.parametrize("which", ["no_mail", "reject_bimi"])
def test_no_link_text_is_a_lowercase_rfc_label(browser, request, which):  # noqa: F811
    result = request.getfixturevalue(which)
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, result)
        page.evaluate(_OPEN_ALL_JS)
        texts = page.eval_on_selector_all(
            "a", "els => els.map(e => e.textContent.trim())")
        assert any(t.startswith("RFC ") for t in texts)
        bad = [t for t in texts if re.match(r"^rfc\d", t)]
        assert not bad, bad
        assert not errors, errors
    finally:
        ctx.close()


def test_app_js_has_no_lowercase_rfc_link_text():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "static", "app.js"), encoding="utf-8") as f:
        js = f.read()
    assert not re.findall(r">\s*rfc\d", js)
