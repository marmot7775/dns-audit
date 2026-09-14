"""Doc 44: DMARC grades and verdicts follow RFC 9989.

Every case runs a declared zone through run_full_audit and asserts on what
the transformer produced: the card, the executive summary, the attack
surface and, for items 6 and 11, the rendered PDF.
"""
import base64
import io
import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import dmarc_tree_walk as tw
import pdf_report
from conftest import FakeZone
from test_status_semantics import _js_functions

DOMAIN = "doc44.test"
RUA = f"rua=mailto:d@{DOMAIN}"


def _dkim_public_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


_DKIM_P = _dkim_public_key()


def _zone(dmarc, spf="v=spf1 mx -all", extra=None):
    records = {
        DOMAIN: {"MX": [(10, f"mx1.{DOMAIN}"), (20, f"mx2.{DOMAIN}")],
                 "TXT": [spf], "A": ["203.0.113.10"],
                 "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"s1._domainkey.{DOMAIN}": {"TXT": ["v=DKIM1; k=rsa; p=" + _DKIM_P]},
        f"mx1.{DOMAIN}": {"A": ["203.0.113.11"]},
        f"mx2.{DOMAIN}": {"A": ["203.0.113.12"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    }
    if dmarc is not None:
        records[f"_dmarc.{DOMAIN}"] = {"TXT": dmarc if isinstance(dmarc, list) else [dmarc]}
    records.update(extra or {})
    return FakeZone(records)


def _run(audit, dmarc, domain=DOMAIN, **kwargs):
    zone_kwargs = {k: kwargs.pop(k) for k in ("spf", "extra") if k in kwargs}
    return audit(_zone(dmarc, **zone_kwargs), domain, dkim_selector="s1", **kwargs)


def _card(result, name="DMARC"):
    return {c["name"]: c for c in result["checks"]}[name]


def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)


def _strict_checks(card):
    return [c for cat in card["strict_validation"]["categories"] for c in cat["checks"]]


# ---------------------------------------------------------------
# Item 1: what receivers ignore is a warning; what invalidates is a failure
# ---------------------------------------------------------------

IGNORED = ["foo=bar", "adkim=x", "fo=2", "pct=abc", "ri=-5", "rf=iodef"]


@pytest.mark.parametrize("extra", IGNORED)
def test_a_tag_receivers_ignore_grades_warn_and_p_still_applies(audit, extra):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}; {extra}")
    card = _card(result)

    assert card["status"] == "warn", (extra, card["status"])
    assert "p=reject" in card["verdict"], card["verdict"]
    assert not [d for d in card["details"] if d["type"] == "error"], card["details"]
    # The cover's Issues figure and the summary no longer inherit a fail.
    assert pdf_report._tally(result["checks"])[2] == 0
    verdict = result["executive_summary"]["verdict"]
    assert "well-protected" in verdict or "blocks spoofed email" in verdict, verdict


def test_absent_p_with_a_valid_rua_is_read_as_p_none(audit):
    card = _card(_run(audit, f"v=DMARC1; {RUA}"))

    assert card["status"] == "warn"
    assert "p=none" in card["verdict"], card["verdict"]
    # The strict validator applies the same rule as the recovery block.
    p_missing = [c for c in _strict_checks(card) if c["code"] == "P_MISSING"]
    assert [c["status"] for c in p_missing] == ["warn"], p_missing
    assert "4.7" in p_missing[0]["message"]


@pytest.mark.parametrize("dmarc", [
    f"p=reject; v=DMARC1; {RUA}",
    [f"v=DMARC1; p=reject; {RUA}", f"v=DMARC1; p=none; {RUA}"],
    "v=DMARC1; adkim=r",
], ids=["v-not-first", "two-records", "no-p-no-rua"])
def test_what_invalidates_the_record_still_fails(audit, dmarc):
    assert _card(_run(audit, dmarc))["status"] == "fail"


# ---------------------------------------------------------------
# Item 2: p= may appear anywhere after v=
# ---------------------------------------------------------------

def test_p_after_rua_is_not_a_syntax_error(audit):
    card = _card(_run(audit, f"v=DMARC1; {RUA}; p=reject"))

    assert card["status"] == "pass", card["details"]
    texts = " ".join(d["text"] for d in card["details"])
    assert "second tag" not in texts and "immediately after" not in texts


# ---------------------------------------------------------------
# Item 3: *WSP around the equals sign
# ---------------------------------------------------------------

def test_whitespace_around_equals_passes_strict_validation(audit):
    record = f"v=DMARC1; p = reject; {RUA}"
    card = _card(_run(audit, record))

    codes = {c["code"]: c["status"] for c in _strict_checks(card)}
    assert "MALFORMED_TAG" not in codes and "P_MISSING" not in codes, codes
    assert "fail" not in codes.values(), codes
    strict = audit_engine._validate_dmarc_strict(record)
    assert strict["has_structural_errors"] is False
    assert "will reject" not in strict["summary"]
    assert card["status"] == "pass"


# ---------------------------------------------------------------
# Item 4: the tree walk reads a record the way the card does
# ---------------------------------------------------------------

def test_tree_walk_accepts_the_whitespace_the_card_accepts(audit):
    sub = f"sub.{DOMAIN}"
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}", domain=sub, extra={
        sub: {"A": ["203.0.113.20"]},
        f"_dmarc.{sub}": {"TXT": ["v = DMARC1; p=none"]},
    })

    assert _card(result)["verdict"].startswith("p=none"), _card(result)["verdict"]
    assert result["tree_walk"]["effective_policy"] == "none", result["tree_walk"]


def test_tree_walk_survives_an_undecodable_byte():
    rdata = SimpleNamespace(strings=[b"v=DMARC1; p=reject; rua=mailto:d@x.test; x=\xff"])
    resolver = SimpleNamespace(resolve=lambda name, rdtype: [rdata])
    with patch.object(tw, "get_resolver", return_value=resolver):
        record = tw._query_dmarc("x.test")

    assert isinstance(record, str) and record.startswith("v=DMARC1; p=reject"), record


# ---------------------------------------------------------------
# Item 5: a name that does not exist falls back np, sp, p
# ---------------------------------------------------------------

def test_nonexistent_name_takes_sp_before_p(audit):
    result = _run(audit, f"v=DMARC1; p=reject; sp=quarantine; {RUA}", domain=f"ghost.{DOMAIN}")

    walk = result["tree_walk"]
    assert (walk["effective_policy"], walk["applied_tag"]) == ("quarantine", "sp"), walk


# ---------------------------------------------------------------
# Item 6: p=reject without np is fully protected on every surface
# ---------------------------------------------------------------

def test_p_reject_without_np_is_fully_protected(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}")
    surface = _card(result)["attack_surface"]
    nx = next(v for v in surface["vectors"] if v["name"] == "Non-Existent Subdomain Spoofing")

    assert (nx["status"], nx["color"]) == ("protected", "green"), nx
    assert "np=reject would state it explicitly" in nx["detail"]
    assert (surface["overall"]["label"], surface["overall"]["color"]) == ("Low Risk", "green")
    assert surface["attacker_path"] == ""
    assert "partially" not in result["executive_summary"]["verdict"]

    text = _pdf_text(result)
    for phrase in ("Moderate Risk", "partially blocks", "no np policy", "Protected by fallback",
                   "recommends setting np"):
        assert phrase not in text, phrase


def test_published_p_none_is_moderate_amber(audit):
    card = _card(_run(audit, f"v=DMARC1; p=none; {RUA}"))
    overall = card["attack_surface"]["overall"]

    assert card["status"] == "warn"
    assert (overall["label"], overall["color"]) == ("Moderate Risk", "amber"), overall


def test_a_record_with_no_usable_policy_is_still_red(audit):
    card = _card(_run(audit, "v=DMARC1; adkim=r"))

    assert card["status"] == "fail"
    assert card["attack_surface"]["overall"]["color"] == "red"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_card_readiness_block_shows_the_tile_label_and_colour(audit):
    result = _run(audit, f"v=DMARC1; p=none; {RUA}")
    tile = result["executive_summary"]["dmarcbis_readiness"]
    program = _js_functions("iconSvg", "ICON", "tagClass", "safeClass",
                            "renderDmarcbisReadiness") + """
const COLOR_STATE = { green: 'pass', amber: 'warn', red: 'fail' };
function escapeHtml(t) {
    return String(t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
_execSummary = d.es;
process.stdout.write(renderDmarcbisReadiness(d.readiness));
""".replace("function renderDmarcbisReadiness", "let _execSummary = null;\nfunction renderDmarcbisReadiness", 1)
    payload = {"es": result["executive_summary"],
               "readiness": _card(result)["dmarcbis_readiness"]}
    html = subprocess.run(["node", "-e", program], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=60, check=True).stdout

    assert (tile["label"], tile["color"]) == ("In progress", "amber"), tile
    assert 'class="tag tag-warn">In progress<' in html, html[:600]
    assert "Needs Update" not in html


def test_app_js_colour_map_matches_the_one_the_test_uses():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "static", "app.js"), encoding="utf-8") as f:
        assert "const COLOR_STATE = { green: 'pass', amber: 'warn', red: 'fail' };" in f.read()


# ---------------------------------------------------------------
# Item 7: Doc 38's warn rules
# ---------------------------------------------------------------

def test_spf_softfail_is_warn(audit):
    assert _card(_run(audit, f"v=DMARC1; p=reject; {RUA}", spf="v=spf1 mx ~all"),
                 "SPF")["status"] == "warn"


def test_sp_weaker_than_p_is_warn(audit):
    assert _card(_run(audit, f"v=DMARC1; p=reject; sp=none; {RUA}"))["status"] == "warn"


def test_mta_sts_testing_mode_is_warn(audit):
    policy = f"version: STSv1\nmode: testing\nmx: mx1.{DOMAIN}\nmx: mx2.{DOMAIN}\nmax_age: 604800\n"
    card = _card(_run(audit, f"v=DMARC1; p=reject; {RUA}", mta_sts_policy=policy,
                      extra={f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20260913"]}}), "MTA-STS")

    assert card["verdict"] == "Monitoring TLS, not yet enforcing"
    assert card["status"] == "warn"


def test_p_none_without_rua_is_warn_not_fail(audit):
    assert _card(_run(audit, "v=DMARC1; p=none"))["status"] == "warn"


# ---------------------------------------------------------------
# Item 8: pct wording follows the policy
# ---------------------------------------------------------------

def _pct_row(card):
    # The row this item rewrote opens with pct; the removed-tag finding
    # beside it also names pct and RFC 9989.
    return next(d["text"] for d in card["details"] if d["text"].startswith("pct"))


def test_pct_row_at_p_none_says_pct_does_nothing(audit):
    row = _pct_row(_card(_run(audit, f"v=DMARC1; p=none; pct=50; {RUA}")))

    assert row == ("pct has no effect at p=none: there is no action to apply to a fraction "
                   "of failing mail. Remove it; RFC 9989 removed the tag.")


def test_pct_row_at_reject_names_quarantine_for_the_rest(audit):
    row = _pct_row(_card(_run(audit, f"v=DMARC1; p=reject; pct=50; {RUA}")))

    assert row.endswith("RFC 7489 receivers reject the selected fraction and quarantine the rest "
                        "(RFC 7489 section 6.6.4); RFC 9989 receivers ignore pct and reject all "
                        "of them."), row


def test_pct_row_at_quarantine_is_unchanged(audit):
    row = _pct_row(_card(_run(audit, f"v=DMARC1; p=quarantine; pct=50; {RUA}")))

    assert "ignore pct and quarantine all of them" in row


def test_pct_business_risk_is_right_at_reject():
    text = audit_engine.BUSINESS_RISK["DMARC_PCT_LOW"]

    assert "reaches inboxes" not in text
    assert "quarantine under p=reject and none under p=quarantine" in text


# ---------------------------------------------------------------
# Item 9: the subdomain callout counts names that exist
# ---------------------------------------------------------------

def test_subdomain_callout_counts_and_names_existing_subdomains(audit):
    result = _run(audit, f"v=DMARC1; p=reject; sp=none; {RUA}",
                  extra={f"support.{DOMAIN}": {"A": ["203.0.113.30"]}})
    sa = result["subdomain_audit"]

    assert sa["callout"] == (f"Your subdomain policy gap (sp=none) affects 1 subdomain "
                             f"that exists, support.{DOMAIN}."), sa["callout"]
    assert "1 existing subdomain exposed due to policy gaps" in sa["summary_lines"]


def test_a_domain_with_no_subdomains_reports_none_exposed(audit):
    sa = _run(audit, f"v=DMARC1; p=reject; sp=none; {RUA}")["subdomain_audit"]

    assert sa["callout"] is None, sa["callout"]
    assert not any("exposed" in line for line in sa["summary_lines"]), sa["summary_lines"]


# ---------------------------------------------------------------
# Item 10: the no-rua fix does not point at reports
# ---------------------------------------------------------------

def test_no_rua_fix_asks_for_rua_first(audit):
    fix = _card(_run(audit, "v=DMARC1; p=none"))["fix"]

    assert fix.startswith("Add an rua address first; without it there are no reports to review."), fix
    assert "Review your DMARC aggregate reports" not in fix


# ---------------------------------------------------------------
# Item 11: absent tags read as absent; removed, not deprecated
# ---------------------------------------------------------------

def test_absent_rf_and_ri_rows_read_as_absent(audit):
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}")
    rows = {t["tag"]: t for t in _card(result)["tag_breakdown"]["tags"]}

    for tag in ("rf", "ri"):
        row = rows[tag]
        assert (row["value"], row["is_absent"], row["dmarcbis"]) == (None, True, ""), row
        assert row["explanation"] == "Not in this record. RFC 9989 removed the tag."

    text = _pdf_text(result)
    assert "afrf" not in text and "86400" not in text
    assert "Not in this record. RFC 9989 removed the tag." in text
    assert "Deprecated" not in text


def test_removed_tags_are_called_removed(audit):
    result = _run(audit, f"v=DMARC1; p=reject; pct=50; {RUA}")
    bd = _card(result)["tag_breakdown"]

    assert any(w["title"] == "Removed tags present" for w in bd["config_warnings"])
    assert "Removed tags: pct" in bd["health"]["reasons"]
    text = _pdf_text(result)
    assert "Removed" in text and "Deprecated" not in text
