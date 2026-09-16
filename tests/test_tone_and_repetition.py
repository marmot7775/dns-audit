"""Doc 47: tone, repetition, plurals, placeholders and plain wording.

The banned list pins every replaced phrase in the strings the site and the
PDF actually print (Python string literals outside docstrings, and app.js
string literals outside comments). The repetition test runs Doc 44 fixture
zones through run_full_audit and checks no card prints the same long
sentence twice.
"""
import io
import json
import os
import re
import sys
from collections import Counter

import pytest
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
import result_transformer as rt
from test_plurals_and_tone import _python_strings
from test_dmarc_grades import DOMAIN, RUA, _card, _run

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BANNED = [
    "delivered normally",
    "still delivered",
    "delivered to their inbox",
    "increasingly penalize",
    "hurting your inbox placement",
    "serves no purpose",
    "immediately",
    "We are now tracking",
    "We found",
    "OVER LIMIT",
    "yourdomain.com",
    "(s)",
    "&mdash;",
    "—",
    "only way to know",
    "Comprehensive",
]

PY_SOURCES = ("result_transformer.py", "audit_engine.py", "anomaly_detector.py",
              "checks_extra.py", "pdf_report.py",
              "spf_recursive.py")


def _js_strings(src):
    """The literal text of every string in app.js, comments skipped.

    Template literals contribute their text parts; ${...} expressions are
    code and are skipped.
    """
    out, i, n = [], 0, len(src)
    prev = ""  # last non-space code character, to tell a regex from a division
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif c == "/" and prev in "(,=:[!&|?{};+":
            # A regex literal: skip to its closing slash, minding classes.
            i, in_class = i + 1, False
            while i < n and (in_class or src[i] != "/"):
                if src[i] == "\\":
                    i += 1
                elif src[i] == "[":
                    in_class = True
                elif src[i] == "]":
                    in_class = False
                i += 1
            i += 1
            prev = "/"
        elif c in "'\"`":
            prev = c
            quote, buf, i = c, [], i + 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    buf.append(src[i:i + 2])
                    i += 2
                elif quote == "`" and src.startswith("${", i):
                    out.append("".join(buf))
                    buf, depth, i = [], 1, i + 2
                    while i < n and depth:
                        depth += {"{": 1, "}": -1}.get(src[i], 0)
                        i += 1
                else:
                    buf.append(src[i])
                    i += 1
            out.append("".join(buf))
            i += 1
        else:
            if not c.isspace():
                prev = c
            i += 1
    return out


def _generated_strings():
    for name in PY_SOURCES:
        for lineno, value in _python_strings(os.path.join(REPO, name)):
            yield f"{name}:{lineno}", value
    with open(os.path.join(REPO, "static", "app.js"), encoding="utf-8") as f:
        for k, value in enumerate(_js_strings(f.read())):
            yield f"app.js string #{k}", value


@pytest.mark.parametrize("phrase", BANNED)
def test_no_banned_phrase_in_generated_text(phrase):
    hits = [f"{where}: {value[:90]!r}" for where, value in _generated_strings()
            if phrase in value]
    assert not hits, "\n".join(hits)


# Doc 56: the About and Privacy pages lost their launch-post register, and
# these pin it out along with the Doc 47 list.
PAGE_BANNED = BANNED + ["So I built it", "built for you", "Worth knowing", "as web servers do"]
PROSE_PAGES = ("about.html", "privacy.html")


@pytest.mark.parametrize("page", PROSE_PAGES)
@pytest.mark.parametrize("phrase", PAGE_BANNED)
def test_no_banned_phrase_on_prose_pages(page, phrase):
    with open(os.path.join(REPO, "static", page), encoding="utf-8") as f:
        text = f.read()
    assert phrase not in text, f"{page}: {phrase!r}"


# ---------------------------------------------------------------
# Repetition: no sentence over eight words twice on one card
# ---------------------------------------------------------------

# Keys whose string values reach the rendered card. strict_validation is shown
# in the default (RFC 9989) view; legacy_validation and spec_comparison belong
# to the other view, and the record builder is an editor, not prose.
_TEXT_KEYS = {"verdict", "explanation", "text", "business_risk", "fix", "deliverability",
              "summary", "detail", "why", "dmarcbis_note", "message", "reasons"}
_SKIP_KEYS = {"legacy_validation", "spec_comparison", "record_builder"}


def _card_strings(node):
    if isinstance(node, dict):
        if node.get("hidden"):
            return
        for key, value in node.items():
            if key in _SKIP_KEYS:
                continue
            if key in _TEXT_KEYS and isinstance(value, str):
                yield value
            elif key in _TEXT_KEYS and isinstance(value, list):
                yield from (v for v in value if isinstance(v, str))
            if isinstance(value, (dict, list)):
                yield from _card_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _card_strings(item)


def _repeated_sentences(card):
    counts = Counter()
    for text in _card_strings(card):
        plain = re.sub(r"<[^>]+>", "", text)
        for sentence in re.split(r"(?<=[.!?])\s+", plain):
            sentence = sentence.strip()
            if len(sentence.split()) > 8:
                counts[sentence] += 1
    return {s: n for s, n in counts.items() if n > 1}


# Three Doc 44 zones, plus the enforcing record without rua that item 6 names.
ZONES = [
    f"v=DMARC1; p=none; {RUA}",
    f"v=DMARC1; p=reject; sp=none; {RUA}",
    f"v=DMARC1; p=quarantine; pct=50; {RUA}",
    "v=DMARC1; p=quarantine",
]


@pytest.mark.parametrize("dmarc", ZONES)
def test_no_card_repeats_a_sentence(audit, dmarc):
    result = _run(audit, dmarc)
    problems = {c["name"]: _repeated_sentences(c) for c in result["checks"]}
    problems = {k: v for k, v in problems.items() if v}
    assert not problems, json.dumps(problems, indent=1)


# ---------------------------------------------------------------
# The replacements land where they should
# ---------------------------------------------------------------

SENTENCE = "p=none requests no action, so each receiver applies only its own filtering to mail that fails."


def test_p_none_card_uses_the_sentence_and_predicts_no_delivery(audit):
    result = _run(audit, f"v=DMARC1; p=none; {RUA}")
    card = _card(result)
    rows = {t["tag"]: t for t in card["tag_breakdown"]["tags"]}
    blob = json.dumps(card).lower()

    assert SENTENCE in rows["p"]["explanation"]
    # The Monitoring mode warning sits under the p row, so it does not repeat it.
    monitoring = next(w for w in card["tag_breakdown"]["config_warnings"]
                      if w["title"] == "Monitoring mode")
    assert monitoring["text"] == ("Monitoring mode. Review your aggregate reports and progress to "
                                  "p=quarantine then p=reject once every legitimate sender aligns.")
    for phrase in ("delivered", "inbox placement", "erode trust"):
        assert phrase not in blob, phrase
    impacts = [i["impact"] for i in result["security_roadmap"]["items"]]
    assert "Nothing is blocked yet, and every receiver is making its own call on mail that fails." in impacts
    assert result["executive_summary"]["dmarcbis_readiness"]["label"] == "In progress"


def test_enforcing_without_rua_says_it_once_in_the_explanation_and_once_in_details(audit):
    card = _card(_run(audit, "v=DMARC1; p=quarantine"))
    details = [d["text"] for d in card["details"]]

    assert "No aggregate reporting (rua) is configured." in card["explanation"]
    assert sum("aggregate reporting" in t.lower() for t in details) == 1, details
    shown = [w for w in card["tag_breakdown"]["config_warnings"] if not w.get("hidden")]
    assert not any(w["title"] == "No aggregate reporting" for w in shown)


def test_removed_tag_rows_do_not_repeat_their_explanation(audit):
    card = _card(_run(audit, f"v=DMARC1; p=reject; pct=50; rf=afrf; ri=3600; {RUA}"))
    rows = {t["tag"]: t for t in card["tag_breakdown"]["tags"]}

    for tag in ("pct", "rf", "ri"):
        assert rows[tag]["warnings"] == [], rows[tag]


def test_one_weak_dkim_key_is_singular():
    from test_dkim_2048_is_a_recommendation import _rsa_key_record
    card = rt.transform_dkim({"found_selectors": [{"selector": "s1", "record": _rsa_key_record(1024)}],
                              "tested_count": 1}, "example.com")
    item = next(i for i in rt.build_security_roadmap([card])["items"] if i["protocol"] == "DKIM")

    assert item["action"] == "Rotate the weak DKIM key to 2048-bit"
    assert item["impact"] == "This key is below current recommendations and should be rotated."


def test_placeholders_use_the_audited_domain(audit):
    # No p= and no rua: the fix text that used to print dmarc-reports@yourdomain.com.
    result = _run(audit, "v=DMARC1; adkim=r")
    blob = json.dumps(result)

    assert "yourdomain.com" not in blob
    assert f"rua=mailto:dmarc-reports@{DOMAIN}" in blob


def test_pdf_labels_are_sentence_case_and_name_the_scope(audit):
    result = _run(audit, f"v=DMARC1; p=none; {RUA}")
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)

    assert "Audit type: Complete Audit" in text, text[:3000]
    assert "Comprehensive" not in text and "PROTECTED" not in text and "EXPOSED" not in text
    assert "Re-run the audit at dns-audit.com" in text or "field above" not in text
    assert reader.metadata.subject == f"Complete Audit report for {DOMAIN}"
