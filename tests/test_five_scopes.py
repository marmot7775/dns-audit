"""Five audit scopes grouped by the visitor's question (Doc 103).

complete, deliverability, email_security, dmarc and dns_security replace
the six record-type scopes. The four old keys still work: resolve_scope
maps each to the scope that runs at least its checks, before the cache
key, the log, the result or the page sees it.
"""

import json
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
from audit_engine import LEGACY_SCOPES, SCOPE_CHECKS, resolve_scope
from conftest import fake_dns
from test_dmarc_grades import DOMAIN, RUA, _run, _zone
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401

# Every scope the API takes. The first four are the pills (2026-10-25);
# dmarc and dns_security stay valid API scopes with no pill.
NEW_KEYS = ["deliverability", "senders", "email_security", "complete", "dmarc", "dns_security"]
PILLS = NEW_KEYS[:4]

DESCRIPTIONS = {
    "deliverability": "Will your mail reach the inbox: the records Gmail, Yahoo, and "
                      "Microsoft require of senders (SPF, DKIM, DMARC) and where your "
                      "mail is delivered (MX).",
    "senders": "Every service that sends mail as your domain, found from its SPF, DKIM, "
               "DMARC, and MX records, and whether each one is set up to pass.",
    "email_security": "Can someone send mail that fakes your domain, and the path to "
                      "p=reject: DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, DANE, and BIMI.",
    "complete": "Every check: DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, "
                "DANE, nameservers, and Certificate Transparency.",
}


def _keys_in(detail):
    return re.search(r"Valid scopes: (.*)$", detail).group(1).split(", ")


# ---------------------------------------------------------------
# resolve_scope
# ---------------------------------------------------------------

def test_the_scope_table_is_the_four_pills_then_the_api_only_keys():
    assert list(SCOPE_CHECKS) == NEW_KEYS
    assert list(audit_engine.SCOPE_LABELS) == NEW_KEYS
    assert audit_engine.PILL_SCOPES == PILLS


@pytest.mark.parametrize("old,new", [
    ("email_full", "email_security"),
    ("transport", "email_security"),
    ("dns_infra", "dns_security"),
    ("security_scan", None),
])
def test_legacy_keys_resolve_to_the_scope_they_map_to(old, new):
    assert resolve_scope(old) == new


def test_every_legacy_key_maps_to_a_superset_of_its_old_checks():
    old_sets = {
        "email_full": {"dmarc", "mx", "spf", "dkim", "mta_sts", "tls_rpt", "bimi"},
        "transport": {"mx", "mta_sts", "tls_rpt", "dane"},
        "dns_infra": {"dnssec", "caa", "dane", "nameservers", "ct"},
        "security_scan": {"dmarc", "spf", "dkim", "dnssec", "dane", "ct", "caa", "mta_sts"},
    }
    assert set(LEGACY_SCOPES) == set(old_sets)
    for old, checks in old_sets.items():
        new = SCOPE_CHECKS[LEGACY_SCOPES[old]]
        assert new is None or checks <= new, old


@pytest.mark.parametrize("key", ["deliverability", "senders", "email_security", "dmarc", "dns_security"])
def test_new_keys_pass_through(key):
    assert resolve_scope(key) == key


@pytest.mark.parametrize("key", [None, "", "complete"])
def test_complete_and_nothing_resolve_to_none(key):
    assert resolve_scope(key) is None


@pytest.mark.parametrize("key", ["bogus", "Transport", "email"])
def test_anything_else_raises_naming_the_valid_keys(key):
    with pytest.raises(ValueError) as exc:
        resolve_scope(key)
    assert sorted(_keys_in(str(exc.value))) == sorted(NEW_KEYS)


def test_a_direct_caller_passing_a_legacy_key_gets_the_new_scope(audit):
    result = _run(audit, f"v=DMARC1; p=none; {RUA}", scope="dns_infra")
    assert result["scope"] == "dns_security"
    assert {c["name"] for c in result["checks"]} == {
        "DNSSEC", "CAA", "DANE", "Nameservers", "Certificate Transparency"}


# ---------------------------------------------------------------
# Server
# ---------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    import server as server_module

    calls = []

    def counting(domain, **kw):
        calls.append(kw.get("scope"))
        return audit_engine.run_full_audit(domain, **kw)

    monkeypatch.setattr(server_module, "RATE_LIMIT_MAX", 10_000)
    monkeypatch.setattr(server_module, "_cache", {})
    monkeypatch.setattr(server_module, "run_full_audit", counting)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    with fake_dns(_zone(f"v=DMARC1; p=none; {RUA}")):
        yield TestClient(server_module.app), calls


def test_a_legacy_key_shares_the_cache_entry_of_its_new_key(client):
    c, calls = client
    first = c.get("/api/audit", params={"domain": DOMAIN, "scope": "transport"})
    assert first.status_code == 200, first.text
    assert first.json()["scope"] == "email_security"
    second = c.get("/api/audit", params={"domain": DOMAIN, "scope": "email_security"})
    assert second.status_code == 200, second.text
    assert second.json()["scope"] == "email_security"
    # One audit ran, with the new key; the second request was the cached one.
    assert calls == ["email_security"]
    assert second.json()["audited_at"] == first.json()["audited_at"]


def test_security_scan_is_a_complete_run(client):
    c, calls = client
    legacy = c.get("/api/audit", params={"domain": DOMAIN, "scope": "security_scan"})
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["scope"] == "complete"
    complete = c.get("/api/audit", params={"domain": DOMAIN})
    assert len(legacy.json()["checks"]) == len(complete.json()["checks"]) == 12
    assert calls == [None]


@pytest.mark.parametrize("path", ["/api/audit", "/api/audit/stream"])
def test_a_bogus_scope_is_400_naming_the_valid_keys(client, path):
    c, calls = client
    response = c.get(path, params={"domain": DOMAIN, "scope": "bogus"})
    assert response.status_code == 400
    assert sorted(_keys_in(response.json()["detail"])) == sorted(NEW_KEYS)
    assert calls == []


def test_the_pdf_endpoint_accepts_a_legacy_key(client):
    c, calls = client
    response = c.get(f"/api/audit/{DOMAIN}/pdf", params={"scope": "dns_infra"})
    assert response.status_code == 200, response.text[:200]
    assert calls == ["dns_security"]


# ---------------------------------------------------------------
# APRF
# ---------------------------------------------------------------

@pytest.mark.parametrize("scope,queried", [("deliverability", True), ("dns_security", False)])
def test_deliverability_queries_aprf_and_dns_security_does_not(scope, queried):
    zone = _zone(f"v=DMARC1; p=none; {RUA}")
    with fake_dns(zone):
        audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope=scope)
    assert any(n.startswith(f"_aprf._domainkey.{DOMAIN}") for n, _ in zone.queries) is queried


# ---------------------------------------------------------------
# Home page
# ---------------------------------------------------------------

def test_the_pills_are_the_four_questions_in_order(browser):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        pills = page.eval_on_selector_all(
            ".scope-btn", "els => els.map(e => [e.dataset.scope, e.textContent.trim()])")
        assert pills == [
            ["deliverability", "Inbox readiness"],
            ["senders", "Who sends as you"],
            ["email_security", "Spoofing protection"],
            ["complete", "Full audit"],
        ]
        # The home page starts on Inbox readiness.
        assert page.get_attribute(".scope-btn.active", "data-scope") == "deliverability"
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("key", PILLS)
def test_each_scope_shows_its_sentence_under_the_pills(browser, key):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.click(f".scope-btn[data-scope='{key}']")
        assert page.text_content("#scope-desc") == DESCRIPTIONS[key]
        assert page.get_attribute(f".scope-btn[data-scope='{key}']", "aria-checked") == "true"
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("path,pill", [
    ("/?scope=dns_infra", "complete"),
    ("/?scope=dns_security", "complete"),
    ("/?scope=dmarc", "email_security"),
    ("/?scope=transport", "email_security"),
    ("/?d=example.test", "complete"),
    ("/", "deliverability"),
])
def test_a_link_lights_the_pill_it_maps_to(browser, path, pill):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280, path=path)
    try:
        page.wait_for_load_state("domcontentloaded")
        lit = page.eval_on_selector_all(
            ".scope-btn.active", "els => els.map(e => e.dataset.scope)")
        assert lit == [pill]
        assert page.text_content("#scope-desc") == DESCRIPTIONS[pill]
    finally:
        ctx.close()


def test_a_shared_link_always_names_its_scope(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        data = json.loads(json.dumps(_run(audit, f"v=DMARC1; p=none; {RUA}"), default=str))
        _render(page, data)
        assert "scope=complete" in page.evaluate("() => _getShareUrl()")
        assert not errors, errors
    finally:
        ctx.close()


def test_who_sends_as_you_opens_the_services_under_the_plan(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        data = json.loads(json.dumps(
            _run(audit, f"v=DMARC1; p=none; {RUA}", scope="senders"), default=str))
        data["vendors"] = data.get("vendors") or [
            {"name": "Example ESP", "tier": "In use", "sources": ["SPF"], "signals": [], "missing": []}]
        _render(page, data)
        assert page.evaluate("""() => document.getElementById('priority-section')
            .nextElementSibling.id""") == "services-section"
        assert page.get_attribute("#services-toggle", "aria-expanded") == "true"
        # Another scope puts it back at the end, closed.
        data["scope"] = "deliverability"
        _render(page, data)
        assert page.get_attribute("#services-toggle", "aria-expanded") == "false"
        assert page.evaluate("""() => document.getElementById('priority-section')
            .nextElementSibling.id""") != "services-section"
        assert not errors, errors
    finally:
        ctx.close()
