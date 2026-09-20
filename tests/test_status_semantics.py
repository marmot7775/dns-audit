"""Doc 38 sections 1 and 2: four states, and no sentence predicts an attack.

absent is an optional protocol the domain has not published. It is not a
warning and it is not a pass. These tests pin that on every surface that
counts statuses: the cards, the web tiles, tab title and share text (the
functions app.js runs, executed under node), and the PDF cover.
"""
import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import pdf_report
from conftest import FakeZone
from result_transformer import build_executive_summary, build_security_roadmap

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOMAIN = "doc38.test"
PARKED = "parked38.test"
OPTIONAL = {"MTA-STS", "TLS-RPT", "DNSSEC", "CAA", "DANE", "BIMI"}
ESSENTIAL = {"DMARC", "SPF", "DKIM", "MX Records", "Nameservers"}

ENFORCING = f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"
# The doc's fixture: DMARC p=none pct=50, two MX, nothing optional published.
MONITORING = f"v=DMARC1; p=none; pct=50; rua=mailto:d@{DOMAIN}"


def _dkim_public_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


_DKIM_P = _dkim_public_key()


def _zone(dmarc=ENFORCING, ns_ips=("203.0.113.53", "198.51.100.53")):
    records = {
        DOMAIN: {"MX": [(10, f"mx1.{DOMAIN}"), (20, f"mx2.{DOMAIN}")],
                 "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.10"],
                 "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"s1._domainkey.{DOMAIN}": {"TXT": ["v=DKIM1; k=rsa; p=" + _DKIM_P]},
        f"mx1.{DOMAIN}": {"A": ["203.0.113.11"]},
        f"mx2.{DOMAIN}": {"A": ["203.0.113.12"]},
        f"ns1.{DOMAIN}": {"A": [ns_ips[0]]},
        f"ns2.{DOMAIN}": {"A": [ns_ips[1]]},
    }
    if dmarc:
        records[f"_dmarc.{DOMAIN}"] = {"TXT": [dmarc]}
    return FakeZone(records)


def _parked_zone():
    return FakeZone({
        PARKED: {"MX": [(0, ".")], "TXT": ["v=spf1 -all"], "A": ["203.0.113.20"],
                 "NS": [f"ns1.{PARKED}", f"ns2.{PARKED}"]},
        f"_dmarc.{PARKED}": {"TXT": ["v=DMARC1; p=reject;"]},
        f"ns1.{PARKED}": {"A": ["203.0.113.53"]},
        f"ns2.{PARKED}": {"A": ["198.51.100.53"]},
    })


def _by_name(result):
    return {c["name"]: c for c in result["checks"]}


def _names_with(result, status):
    return {c["name"] for c in result["checks"] if c["status"] == status}


# ---------------------------------------------------------------
# Section 1: the cards
# ---------------------------------------------------------------

def test_essentials_passing_and_nothing_optional_is_no_warning_and_no_issue(audit):
    result = audit(_zone(), DOMAIN, dkim_selector="s1")

    assert _names_with(result, "fail") == set(), _by_name(result)
    assert _names_with(result, "warn") == set(), (
        "a domain whose essentials pass opened to warnings about protocols it "
        f"simply has not adopted: {sorted(_names_with(result, 'warn'))}"
    )
    assert _names_with(result, "absent") == OPTIONAL


def test_the_six_optional_cards_say_not_configured(audit):
    cards = _by_name(audit(_zone(), DOMAIN, dkim_selector="s1"))
    for name in OPTIONAL:
        assert cards[name]["status"] == "absent", name
        assert cards[name]["pill_label"] == "Not configured", (
            f"{name} pill reads {cards[name]['pill_label']!r}"
        )


@pytest.mark.parametrize("which", ["mail", "parked"])
def test_every_unconfigured_optional_card_is_absent(audit, which):
    if which == "mail":
        result = audit(_zone(), DOMAIN, dkim_selector="s1")
    else:
        result = audit(_parked_zone(), PARKED)
    unconfigured = [c for c in result["checks"]
                    if c.get("configured") is False
                    and c["name"] not in ESSENTIAL
                    and c["status"] != "unavailable"]

    assert unconfigured, "the fixture should leave optional protocols unpublished"
    wrong = {c["name"]: c["status"] for c in unconfigured if c["status"] != "absent"}
    assert wrong == {}, f"optional protocols with nothing published but not absent: {wrong}"


def test_bimi_with_nothing_published_is_absent_not_pass(audit):
    bimi = _by_name(audit(_zone(), DOMAIN, dkim_selector="s1"))["BIMI"]

    assert bimi["status"] == "absent", (
        "a pass with nothing published is a contradiction"
    )
    assert bimi["status"] != "pass"


def test_absent_counts_as_assessed_so_the_roadmap_still_offers_it(audit):
    result = audit(_zone(), DOMAIN, dkim_selector="s1")
    protocols = {i["protocol"] for i in result["security_roadmap"]["items"]}

    assert {"MTA-STS", "TLS-RPT", "DANE"} <= protocols, protocols


def test_protocol_coverage_counts_absent_as_not_configured(audit):
    pc = audit(_zone(), DOMAIN, dkim_selector="s1")["executive_summary"]["protocol_coverage"]

    assert pc["total"] == 9
    assert pc["configured"] == 3


# ---------------------------------------------------------------
# Section 1: the Spoofing Protection tile agrees with the counters
# ---------------------------------------------------------------

def test_p_none_spoofing_tile_is_amber_monitoring_only(audit):
    result = audit(_zone(MONITORING), DOMAIN, dkim_selector="s1")
    sp = result["executive_summary"]["spoofing_protection"]

    assert _by_name(result)["DMARC"]["status"] == "warn"
    assert (sp["label"], sp["color"]) == ("Monitoring only", "amber")


def test_missing_dmarc_spoofing_tile_is_red_none(audit):
    result = audit(_zone(dmarc=None), DOMAIN, dkim_selector="s1")
    sp = result["executive_summary"]["spoofing_protection"]

    assert _by_name(result)["DMARC"]["status"] == "fail"
    assert (sp["label"], sp["color"]) == ("None", "red")


def test_spoofing_tile_is_never_red_unless_the_dmarc_card_fails(audit):
    # Doc 44: a real audit, so the card's warn is the transformer's own
    # grade rather than a hand-built one. sp weaker than p is warn.
    result = audit(_zone(f"v=DMARC1; p=reject; sp=none; rua=mailto:d@{DOMAIN}"),
                   DOMAIN, dkim_selector="s1")
    sp = result["executive_summary"]["spoofing_protection"]

    assert _by_name(result)["DMARC"]["status"] == "warn"
    assert sp["color"] != "red", sp


# ---------------------------------------------------------------
# Section 1: web tiles, tab title, share text and PDF cover agree
# ---------------------------------------------------------------

def _js_functions(*names):
    """Top-level function or object-literal const definitions from app.js."""
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        src = f.read()
    out = []
    for name in names:
        n = re.escape(name)
        m = (re.search(r"^function %s\(.*?^}\n" % n, src, re.S | re.M)
             or re.search(r"^const %s = \{.*?^\};\n" % n, src, re.S | re.M))
        assert m, f"app.js no longer defines {name}"
        out.append(m.group(0))
    return "\n".join(out)


def _run_app_js(result):
    program = _js_functions("statusCounts", "auditTabTitle", "shareTweetText",
                            "_buildShareSummary") + """
function _getShareUrl() { return 'https://dns-audit.com/'; }
const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const counts = statusCounts(d.checks);
process.stdout.write(JSON.stringify({
    counts, title: auditTabTitle(counts, d.domain),
    tweet: shareTweetText(d), summary: _buildShareSummary(d),
}));
"""
    done = subprocess.run(["node", "-e", program], input=json.dumps(result, default=str),
                          capture_output=True, text=True, timeout=60, check=True)
    return json.loads(done.stdout)


def _cover_count(text, label):
    m = re.search(r"(\d+)\s*%s" % label, text)
    assert m, f"PDF cover has no {label!r} figure: {text[:400]!r}"
    return int(m.group(1))


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_web_counters_tab_title_share_text_and_pdf_cover_agree(audit):
    # Both nameservers in one /24, as in the doc's fixture: that is the second
    # warning beside DMARC p=none, and the reason the baseline had seven amber
    # cards. BIMI is the sixth absent card, which the doc's "5" left out.
    result = audit(_zone(MONITORING, ns_ips=("203.0.113.53", "203.0.113.54")),
                   DOMAIN, dkim_selector="s1")
    web = _run_app_js(result)
    counts = web["counts"]

    assert (counts["warn"], counts["fail"], counts["absent"]) == (2, 0, 6), counts
    assert pdf_report._tally(result["checks"]) == (
        counts["pass"], counts["warn"], counts["fail"], counts["absent"], counts["unavailable"])

    cover = PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages[0].extract_text()
    assert _cover_count(cover, r"issues?\b") == counts["fail"]
    assert _cover_count(cover, r"warnings?\b") == counts["warn"]
    assert _cover_count(cover, r"not configured") == counts["absent"]
    assert _cover_count(cover, r"passing") == counts["pass"]

    assert web["title"] == f"(2 warnings) {DOMAIN} | DNS Audit"
    assert web["tweet"].endswith("0 issues, 2 warnings")
    assert "0 Issues | 2 Warnings" in web["summary"]
    for text in (web["title"], web["tweet"], web["summary"]):
        assert "configured" not in text.lower(), (
            "the tab title and share text count only issues and warnings"
        )


# ---------------------------------------------------------------
# Section 2: two sentences that predicted attacks
# ---------------------------------------------------------------

def test_p_none_business_risk_is_the_doc38_sentence():
    assert audit_engine.BUSINESS_RISK["DMARC_P_NONE"] == (
        "DMARC monitoring-only mode collects reports but does not block anything. "
        "p=none requests no action, so each receiver applies only its own filtering "
        "to mail that fails."
    )


def test_one_exposed_vector_verdict_says_it_is_open():
    checks = [
        {"name": "DMARC", "status": "warn", "configured": True,
         "record": "v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com",
         "tag_breakdown": {"health": {"status": "ready"}, "config_warnings": []},
         "attack_surface": {"vectors": [
             {"name": "Direct Domain Spoofing", "status": "protected"},
             {"name": "Subdomain Spoofing", "status": "exposed"},
             {"name": "Non-Existent Subdomain Spoofing", "status": "protected"},
         ]}},
        {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
        {"name": "DKIM", "status": "pass", "configured": True},
    ]
    verdict = build_executive_summary(checks, build_security_roadmap(checks))["verdict"]

    assert verdict == "Your domain has email authentication, but subdomain spoofing is still open."


# ---------------------------------------------------------------
# Section 4: the DMARC card says each thing once
# ---------------------------------------------------------------

def test_p_none_is_mentioned_by_exactly_one_dmarc_detail_row(audit):
    result = audit(_zone(f"v=DMARC1; p=none; rua=mailto:d@{DOMAIN}"), DOMAIN, dkim_selector="s1")
    rows = [d["text"] for d in _by_name(result)["DMARC"]["details"] if "p=none" in d["text"]]

    assert len(rows) == 1, rows


def test_pct_is_mentioned_by_one_warning_row(audit):
    dmarc = _by_name(audit(_zone(MONITORING), DOMAIN, dkim_selector="s1"))["DMARC"]
    rows = [d for d in dmarc["details"]
            if d["type"] == "warning" and re.search(r"\bpct\b", d["text"])]

    assert len(rows) == 1, [d["text"] for d in rows]


def test_the_pdf_prints_the_same_deduplicated_dmarc_rows(audit):
    result = audit(_zone(MONITORING), DOMAIN, dkim_selector="s1")
    text = "\n".join(p.extract_text() or "" for p in
                     PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages)

    assert text.count("Policy p=none requests no action from receivers when authentication fails") == 0
    assert "Policy p=none: monitoring only" in text


# ---------------------------------------------------------------
# Section 3: one prioritized list
# ---------------------------------------------------------------

from reportlab.platypus import Table  # noqa: E402


def _one_fail_one_warn_one_absent():
    return [
        {"name": "DMARC", "status": "fail", "pill_label": "Missing", "configured": False},
        {"name": "SPF", "status": "warn", "configured": True,
         "record": "v=spf1 include:a.test include:b.test ~all",
         "spf_deep": {"lookup_count": 9}},
        {"name": "MTA-STS", "status": "absent", "pill_label": "Not configured",
         "configured": False},
    ]


def test_roadmap_rows_carry_their_status_and_run_fail_warn_absent():
    rm = build_security_roadmap(_one_fail_one_warn_one_absent())

    assert [(i["protocol"], i["status"]) for i in rm["items"]] == [
        ("DMARC", "fail"), ("SPF", "warn"), ("MTA-STS", "absent")]


def test_within_a_tier_a_warning_row_comes_before_an_absent_one(audit):
    # Doc 44: a real audit, so the DMARC warn is the transformer's own grade.
    # p=reject with pct=50 is warn and lands in the medium tier beside the
    # absent MTA-STS, TLS-RPT and DANE rows.
    result = audit(_zone(f"v=DMARC1; p=reject; pct=50; rua=mailto:d@{DOMAIN}"),
                   DOMAIN, dkim_selector="s1")
    medium = [(i["protocol"], i["status"]) for i in result["security_roadmap"]["items"]
              if i["priority"] == "medium"]

    assert _by_name(result)["DMARC"]["status"] == "warn"
    assert medium == [("DMARC", "warn"), ("MTA-STS", "absent"), ("TLS-RPT", "absent"),
                      ("DANE", "absent")], medium


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_web_priorities_list_has_one_row_per_item_in_order():
    checks = _one_fail_one_warn_one_absent()
    rm = build_security_roadmap(checks)
    # Doc 64: a row is a head plus a body, and the link into the card is a
    # control inside the body, so the anchor is read from that link.
    program = _js_functions("iconSvg", "ICON", "safeClass", "renderPriorities",
                            "_planWhy", "_planWhat", "_planConfirm", "_planText",
                            "_planRecordBlock", "_dmarcPolicy") + """
function escapeHtml(t) {
    return String(t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function sanitizeHtml(h) { return h; }
function renderPropagationWarning() { return ''; }
const END_STATE_NOTE_PLAN = '';
const lastAuditData = {domain: 'doc.test'};
let _planSeq = 0;
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(renderPriorities(input.rm, input.checks, null));
"""
    html = subprocess.run(["node", "-e", program],
                          input=json.dumps({"rm": rm, "checks": checks}),
                          capture_output=True, text=True, timeout=60, check=True).stdout
    rows = re.findall(r'class="status-icon (\w+)".*?'
                      r'class="plan-card-link" data-scroll-to="check-([a-z0-9-]+)"',
                      html, re.S)

    assert rows == [("fail", "dmarc"), ("warn", "spf"), ("absent", "mta-sts")]
    assert html.count('class="priority-row"') == 3


def test_pdf_priorities_section_lists_each_protocol_once_in_order():
    checks = _one_fail_one_warn_one_absent()
    data = {"checks": checks, "security_roadmap": build_security_roadmap(checks)}
    els = pdf_report._roadmap_page(data, pdf_report._styles())
    tables = [e for e in els if isinstance(e, Table) and len(e._cellvalues[0]) > 2
              and "Protocol" in getattr(e._cellvalues[0][2], "text", "")]

    assert len(tables) == 1
    assert [row[2].text for row in tables[0]._cellvalues[1:]] == ["DMARC", "SPF", "MTA-STS"]
    assert not any("Priority Fixes" in getattr(e, "text", "") for e in els)


def test_complete_pdf_has_priorities_and_no_priority_fixes(audit):
    result = audit(_zone(MONITORING), DOMAIN, dkim_selector="s1")
    text = "\n".join(p.extract_text() or "" for p in
                     PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages)

    assert "2. Priorities" in text
    assert "Priority Fixes" not in text
    assert "Email Security Roadmap" not in text
    assert "priority_fixes" not in result, "Doc 49 removed the field after its last release"


def test_the_web_page_renders_priorities_not_key_findings_or_the_roadmap():
    with open(os.path.join(REPO_ROOT, "static", "index.html"), encoding="utf-8") as f:
        html = f.read()
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        js = f.read()

    assert "Key Findings" not in html
    # Doc 64 renamed the section heading; the list is the same list.
    assert ">What to do<" in html
    assert "renderSecurityRoadmap" not in js
    assert "priority_fixes" not in js


# ---------------------------------------------------------------
# Section 5: one icon set
# ---------------------------------------------------------------

_BANNED_GLYPHS = ("&#10003;", "&#10005;", "&#9888;", "&#8505;", "&#9632;", "&#9650;",
                  "&#9679;", "&#x2705;", "&#x26A0;", "&#x1F534;")


def test_app_js_carries_no_glyph_icons_and_no_emoji():
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        src = f.read()

    left = [g for g in _BANNED_GLYPHS if g in src]
    assert left == [], f"glyph icons still in app.js: {left}"
    escaped = re.findall(r"\\u(?:2705|274[Cc]|26[Aa]0|[Ff][Ee]0[Ff]|2713|2717)|\\u\{1[Ff][0-9A-Fa-f]{3}\}", src)
    assert escaped == [], f"escaped emoji or glyphs in app.js: {escaped}"
    literal = [ch for ch in src if 0x1F300 <= ord(ch) <= 0x1FAFF or 0x2600 <= ord(ch) <= 0x27BF]
    assert literal == [], f"emoji or dingbat characters in app.js: {sorted(set(literal))}"


def test_icon_set_has_five_distinct_status_shapes():
    icons = _js_functions("iconSvg", "ICON")
    shapes = {}
    for st in ("pass", "warn", "fail", "absent", "unavailable"):
        m = re.search(r"^    %s: iconSvg\('(.*?)'\)," % st, icons, re.M)
        assert m, st
        shapes[st] = m.group(1)
    assert len(set(shapes.values())) == 5
    assert "stroke-dasharray" in shapes["absent"]
    assert 'stroke-width="1.75"' in icons and 'viewBox="0 0 16 16"' in icons

