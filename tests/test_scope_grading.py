"""Doc 104: grade p=none by the question the scope asks.

Under Email Deliverability a p=none record, published or inherited, meets
the mailbox providers' requirement and grades pass. complete,
email_security and dmarc still grade it amber, as a spoofing question.
One fixture, run under every scope: p=none with rua, aligned SPF, a live
DKIM key.
"""

import json
import os
import sys
from collections import Counter

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
from conftest import fake_dns
from result_transformer import DELIVERABILITY_P_NONE_NOTE
from test_dmarc_grades import _DKIM_P, DOMAIN, RUA, _card, _pdf_text, _run, _zone
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

P_NONE = f"v=DMARC1; p=none; {RUA}"
HEADLINE = ("Your domain publishes the DMARC record mailbox providers ask bulk "
            "senders for. It does not block forged mail yet.")
ENFORCEMENT_ROW = "Progress from p=none to enforcement"
SPOOFING_SCOPES = ["complete", "email_security", "dmarc"]


def _actions(result):
    return [i.get("action") for tier in result["security_roadmap"].values()
            if isinstance(tier, list) for i in tier]


def _p_none_rows(card):
    return [d for d in card["details"] if "p=none" in d["text"] or "none (inherited" in d["text"]]


# ---------------------------------------------------------------
# The card and the summary, scope by scope
# ---------------------------------------------------------------

def test_deliverability_grades_p_none_pass(audit):
    result = _run(audit, P_NONE, scope="deliverability")
    card = _card(result)
    es = result["executive_summary"]
    assert card["status"] == "pass"
    assert card["graded_for_scope"] == "deliverability"
    assert card["verdict"] == "p=none (monitoring only, no enforcement)"
    assert card["details"][0] == {"type": "info", "text": DELIVERABILITY_P_NONE_NOTE}
    # The policy rows are notes, not warnings, and keep their text.
    assert _p_none_rows(card)
    assert all(d["type"] == "info" for d in _p_none_rows(card))
    assert not [d for d in card["details"] if d["type"] in ("warning", "error")]
    assert es["headline_state"] == "pass"
    assert es["headline_icon"] == "shield-check"
    assert es["headline"] == HEADLINE
    assert ENFORCEMENT_ROW not in _actions(result)
    assert "p=none" not in es["deliverability_summary"]
    # The tile answers the spoofing question, so it stays amber.
    assert es["spoofing_protection"]["label"] == "Monitoring only"
    assert es["spoofing_protection"]["color"] == "amber"


@pytest.mark.parametrize("scope", SPOOFING_SCOPES)
def test_the_other_email_scopes_still_grade_p_none_amber(audit, scope):
    result = _run(audit, P_NONE, scope=scope)
    card = _card(result)
    assert card["status"] == "warn"
    assert card["graded_for_scope"] is None
    assert DELIVERABILITY_P_NONE_NOTE not in [d["text"] for d in card["details"]]
    assert any(d["type"] == "warning" for d in _p_none_rows(card))
    assert result["executive_summary"]["headline_state"] == "warn"
    assert ENFORCEMENT_ROW in _actions(result)


def test_dns_security_has_no_dmarc_card(audit):
    result = _run(audit, P_NONE, scope="dns_security")
    assert "DMARC" not in {c["name"] for c in result["checks"]}


def test_the_raw_policy_issue_is_left_alone_for_other_surfaces():
    """transform_dmarc lowers the policy issue on a copy."""
    from result_transformer import DMARC_P_NONE_ISSUE, transform_dmarc
    raw = {"domain": DOMAIN, "status": "warning", "record": P_NONE, "policy": "none",
           "rua": [f"mailto:d@{DOMAIN}"],
           "issues": [{"severity": "warning", "issue": DMARC_P_NONE_ISSUE,
                       "plain_english": "x", "fix": "y"}]}
    card = transform_dmarc(raw, scope="deliverability")
    assert card["status"] == "pass"
    assert raw["issues"][0]["severity"] == "warning"


def test_without_rua_deliverability_still_warns_on_the_rua(audit):
    result = _run(audit, "v=DMARC1; p=none", scope="deliverability")
    card = _card(result)
    assert card["status"] == "warn"
    assert card["graded_for_scope"] is None
    warnings = [d["text"] for d in card["details"] if d["type"] == "warning"]
    assert warnings and all("rua" in w or "aggregate report" in w for w in warnings)
    assert all(d["type"] == "info" for d in _p_none_rows(card))
    assert "Add aggregate reporting (rua=)" in _actions(result)
    assert ENFORCEMENT_ROW not in _actions(result)
    assert result["executive_summary"]["headline_state"] == "warn"


SUB = f"mail.{DOMAIN}"


def _inherited_zone():
    return _zone(P_NONE, extra={
        SUB: {"MX": [(10, f"mx1.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
              "A": ["203.0.113.20"]},
        f"s1._domainkey.{SUB}": {"TXT": ["v=DKIM1; k=rsa; p=" + _DKIM_P]},
    })


@pytest.mark.parametrize("scope,status,graded", [
    ("deliverability", "pass", "deliverability"),
    ("email_security", "warn", None),
])
def test_an_inherited_p_none_follows_the_scope(audit, scope, status, graded):
    result = audit(_inherited_zone(), SUB, scope=scope, dkim_selector="s1")
    card = _card(result)
    assert card["pill_label"] == "Inherited"
    assert card["effective_policy"] == "none"
    assert card["status"] == status
    assert card["graded_for_scope"] == graded


# ---------------------------------------------------------------
# Cache: one domain, two scopes, two grades
# ---------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    import server as server_module

    monkeypatch.setattr(server_module, "RATE_LIMIT_MAX", 10_000)
    monkeypatch.setattr(server_module, "_cache", {})
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    with fake_dns(_zone(P_NONE)):
        yield TestClient(server_module.app)


def test_the_cache_keeps_each_scope_s_grade(client):
    first = client.get("/api/audit", params={"domain": DOMAIN, "scope": "deliverability"})
    second = client.get("/api/audit", params={"domain": DOMAIN, "scope": "email_security"})
    again = client.get("/api/audit", params={"domain": DOMAIN, "scope": "deliverability"})
    assert first.status_code == second.status_code == again.status_code == 200
    assert _card(first.json())["status"] == "pass"
    assert _card(second.json())["status"] == "warn"
    assert _card(again.json())["status"] == "pass"
    assert again.json()["audited_at"] == first.json()["audited_at"]


# ---------------------------------------------------------------
# PDF
# ---------------------------------------------------------------

def test_the_deliverability_pdf_agrees_with_the_page(audit):
    result = _run(audit, P_NONE, scope="deliverability")
    text = _pdf_text(result)
    assert "Progress from p=none" not in text
    assert "monitoring mode (p=none)" not in text
    assert HEADLINE in text
    counts = Counter(c["status"] for c in result["checks"])
    passes, warns, fails, absent, unavailable, na = pdf_report._tally(result["checks"])
    assert (passes, warns, fails) == (counts["pass"], counts["warn"], counts["fail"])
    assert f"Across {len(result['checks'])} checks:" in text
    assert f"{warns} could be stronger, {passes} pass" in text


def test_the_email_security_pdf_keeps_the_enforcement_row(audit):
    text = _pdf_text(_run(audit, P_NONE, scope="email_security"))
    assert "Progress from p=none" in text


# ---------------------------------------------------------------
# Rendered page
# ---------------------------------------------------------------

@pytest.mark.parametrize("scope,status,state", [
    ("deliverability", "pass", "pass"),
    ("email_security", "warn", "warn"),
])
def test_the_results_page_shows_the_scope_s_grade(browser, audit, scope, status, state):  # noqa: F811
    data = json.loads(json.dumps(_run(audit, P_NONE, scope=scope), default=str))
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, data)
        assert page.get_attribute("#check-dmarc", "data-status") == status
        assert page.eval_on_selector(
            "#executive-summary", f"e => e.classList.contains('es-state-{state}')")
        if scope == "deliverability":
            assert HEADLINE in page.text_content("#executive-summary")
        assert not errors, errors
    finally:
        ctx.close()


def test_who_sends_as_you_grades_p_none_like_inbox_readiness(audit):
    result = _run(audit, P_NONE, scope="senders")
    card = _card(result)
    assert card["status"] == "pass"
    assert card["graded_for_scope"] == "senders"
    assert result["executive_summary"]["headline"] == HEADLINE
    assert ENFORCEMENT_ROW not in _actions(result)
