"""The headline at the top of the results answers whether the domain is
protected, and the subline says whether anything needs doing.

One test per headline row and per subline case, plus the one message a
domain that does not exist gets. The headline is chosen from the DMARC
state; a run that never read DMARC says so or says nothing, never a fact
about a record it did not read (Doc 20).
"""
import os
import sys

import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from conftest import FakeZone  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401

D = "headline.test"

PROTECTED = "Your domain is protected against spoofing."
SPAM = "Mail that fakes your domain goes to spam."
SUBDOMAINS_OPEN = "Your domain is protected, but its subdomains are not."
P_NONE = "Your domain does not yet ask receivers to block mail that fakes it."
NO_RECORD = "Your domain publishes no protection against spoofing."
INVALID = "Your spoofing protection record has an error, so receivers ignore it."
UNAVAILABLE = "We couldn't check your spoofing protection. Run the audit again."


def _zone(dmarc=None):
    records = {
        D: {"MX": [(10, f"mx.{D}")], "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.10"],
            "NS": [f"ns1.{D}", f"ns2.{D}"]},
        f"mx.{D}": {"A": ["203.0.113.11"]},
        f"ns1.{D}": {"A": ["203.0.113.53"]},
        f"ns2.{D}": {"A": ["198.51.100.53"]},
    }
    if dmarc is not None:
        records[f"_dmarc.{D}"] = {"TXT": [dmarc]}
    return FakeZone(records)


def _es(audit, dmarc=None, zone=None, scope="complete"):
    return audit(zone or _zone(dmarc), D, scope=scope)["executive_summary"]


# ---------------------------------------------------------------
# Part 1: one test per row
# ---------------------------------------------------------------

@pytest.mark.parametrize("sp", ["", " sp=reject;", " sp=quarantine;"])
def test_reject_with_subdomains_covered_is_protected(audit, sp):
    es = _es(audit, f"v=DMARC1; p=reject;{sp} rua=mailto:d@{D}")
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        PROTECTED, "pass", "shield-check")


@pytest.mark.parametrize("sp", ["", " sp=reject;", " sp=quarantine;"])
def test_quarantine_with_subdomains_covered_goes_to_spam(audit, sp):
    es = _es(audit, f"v=DMARC1; p=quarantine;{sp} rua=mailto:d@{D}")
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        SPAM, "warn", "shield-check")


@pytest.mark.parametrize("p", ["reject", "quarantine"])
def test_sp_none_leaves_subdomains_open(audit, p):
    es = _es(audit, f"v=DMARC1; p={p}; sp=none; rua=mailto:d@{D}")
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        SUBDOMAINS_OPEN, "warn", "shield-half")


def test_p_none_does_not_ask_receivers_to_block(audit):
    es = _es(audit, f"v=DMARC1; p=none; rua=mailto:d@{D}")
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        P_NONE, "warn", "warning")


def test_no_dmarc_record_publishes_no_protection(audit):
    es = _es(audit)
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        NO_RECORD, "fail", "shield-x")


@pytest.mark.parametrize("records", [
    ["v=dmarc1; p=reject; rua=mailto:d@headline.test"],
    ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
], ids=["lowercase-version", "two-records"])
def test_invalid_record_is_ignored(audit, records):
    zone = _zone()
    zone.add(f"_dmarc.{D}", "TXT", records)
    es = _es(audit, zone=zone)
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        INVALID, "fail", "shield-x")


def test_dmarc_lookup_unavailable_asks_for_a_rerun(audit):
    es = _es(audit, zone=_zone().fail(f"_dmarc.{D}", "TXT"))
    assert (es["headline"], es["headline_state"], es["headline_icon"]) == (
        UNAVAILABLE, "neutral", "refresh")


def test_dmarc_out_of_scope_has_no_headline(audit):
    es = _es(audit, f"v=DMARC1; p=reject; rua=mailto:d@{D}", scope="dns_infra")
    assert es["headline"] is None
    assert es["headline_icon"] is None


def test_headline_strings_follow_the_copy_rules():
    for s in (PROTECTED, SPAM, SUBDOMAINS_OPEN, P_NONE, NO_RECORD, INVALID, UNAVAILABLE):
        assert "!" not in s and " - " not in s and "—" not in s and "–" not in s


def test_an_older_result_without_a_headline_shows_its_verdict(browser):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        html = page.evaluate("es => _headlineHtml(es, {items: []})",
                             {"verdict": "Older verdict sentence."})
        assert "Older verdict sentence." in html
        html = page.evaluate("es => _headlineHtml(es, {items: []})",
                             {"verdict": "Out of scope sentence.", "headline": None})
        assert "Out of scope sentence." not in html
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Part 2: the subline, from the same counts as What to do
# ---------------------------------------------------------------

SUBLINE_CASES = [
    ([{"priority": "critical", "protocol": "DMARC"}, {"priority": "high", "protocol": "SPF"},
      {"priority": "low", "protocol": "DMARC"}], "2 fixes needed below."),
    ([{"priority": "medium", "protocol": "DMARC"}], "1 fix needed below."),
    ([{"priority": "low", "protocol": "DMARC"},
      {"priority": "medium", "protocol": "MTA-STS", "status": "absent"}],
     "2 optional improvements below."),
    ([{"priority": "medium", "protocol": "MTA-STS", "optional": True}],
     "1 optional improvement below."),
    ([], "Nothing to fix."),
]


@pytest.mark.parametrize("items,expected", SUBLINE_CASES,
                         ids=["fixes", "one-fix", "optional", "one-optional", "nothing"])
def test_subline(browser, items, expected):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        assert page.evaluate("rm => headlineSubline(rm)", {"items": items}) == expected
    finally:
        ctx.close()


def test_subline_agrees_with_the_what_to_do_heading(browser, fixture_result):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => ({
            sub: (document.querySelector('#executive-summary .es-subline') || {}).textContent,
            summary: document.getElementById('priority-summary').textContent,
            optional: document.querySelectorAll('.plan-optional-body .priority-row').length,
            main: document.querySelectorAll('#priority-list > .priority-row').length,
        })""")
        if m["main"]:
            n = m["main"]
            assert m["sub"] == (f"{n} fixes needed below." if n > 1 else "1 fix needed below.")
        else:
            assert "optional improvement" in m["sub"] or m["sub"] == "Nothing to fix."
        assert errors == []
    finally:
        ctx.close()


# ---------------------------------------------------------------
# Part 4c: a domain that does not exist gets one message
# ---------------------------------------------------------------

def test_a_domain_that_does_not_exist_gets_one_message(monkeypatch):
    import server

    def _nx(*_a, **_k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(server._preflight_resolver, "resolve", _nx)
    out = server._preflight_dns_check("example.comds")
    assert out["checks"] == []
    assert out["error"] == "domain_not_found"
    assert "does not exist in DNS" in out["error_message"]
