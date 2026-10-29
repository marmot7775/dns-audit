"""The Sender Map on Who sends as you (2026-10-25).

The domain sits in the middle and each service Sendermap found sits around
it, coloured by whether its own setup is complete. Selecting a service
shows its setup, the risks that cite its records, and the evidence. Below
640px the nodes stack as a list. Rendered from a synthetic map so the test
does not depend on any live domain.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import RUA, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401


def _ev(name, rtype, value):
    return {"name": name, "rtype": rtype, "value": value, "checked_at": "2026-10-25T00:00:00Z"}


def _svc(name, tier, role, claims, items, category="Marketing"):
    return {"name": name, "category": category, "tier": tier, "role": role, "claims": claims,
            "setups": [{"service": name, "where": "doc44.test", "items": items,
                        "complete": all(i["state"] != "missing" for i in items)}]}


def _item(record, need, state, asked=""):
    return {"record": record, "need": need, "state": state, "evidence": [], "asked": asked, "detail": ""}


GOOGLE_MX = _ev("doc44.test", "MX", "1 aspmx.l.google.com")
MAP = {
    "story": "Google Workspace receives the domain's mail. Not checked: the website (turned off) "
             "and sending subdomains (turned off).",
    "findings": [
        {"severity": "risk", "title": "The k1 key is missing", "detail": "Add it.",
         "evidence": [_ev("k1._domainkey.doc44.test", "CNAME", "dkim.mcsv.net")]},
        {"severity": "warning", "title": "Something about the apex", "detail": "x",
         "evidence": [_ev("doc44.test", "TXT", "MS=ms1")]},
    ],
    "services": [
        _svc("Google Workspace", "In use", "sender",
             [{"kind": "receives the domain's mail (MX)", "evidence": GOOGLE_MX},
              {"kind": "receives the domain's mail (MX)", "evidence": _ev("doc44.test", "MX", "5 alt1.aspmx.l.google.com")},
              {"kind": "included in SPF", "evidence": _ev("doc44.test", "TXT", "include:_spf.google.com")}],
             [_item("spf", "required", "present"), _item("dkim", "required", "present"),
              _item("return_path", "none", "not needed")], category="Mailbox"),
        _svc("Mailchimp", "Configured", "sender",
             [{"kind": "hosts a DKIM key (CNAME)", "evidence": _ev("k1._domainkey.doc44.test", "CNAME", "dkim.mcsv.net")}],
             [_item("dkim", "required", "missing", "CNAME at k1._domainkey.doc44.test")]),
        _svc("Microsoft 365", "Account only", "sender",
             [{"kind": "verification token", "evidence": _ev("doc44.test", "TXT", "MS=ms1")}],
             [_item("spf", "required", "missing", "TXT at doc44.test")], category="Mailbox"),
        _svc("Valimail", None, "reporting",
             [{"kind": "receives DMARC reports", "evidence": _ev("_dmarc.doc44.test", "TXT", RUA)}], [],
             category="DMARC reporting"),
    ],
}


@pytest.fixture
def senders_data(audit):
    data = json.loads(json.dumps(_run(audit, f"v=DMARC1; p=none; {RUA}", scope="senders"), default=str))
    data["sendermap"] = MAP
    return data


def _map_state(page):
    return page.evaluate("""() => [...document.querySelectorAll('.smap-node')].map(n => ({
        name: n.querySelector('.smap-node-name').textContent,
        state: [...n.classList].find(c => ['smap-ready','smap-missing','smap-risk','smap-unverified','smap-account','smap-reporting'].includes(c)),
        badges: [...n.querySelectorAll('.smap-badge')].map(b => b.textContent + ':' + b.className.split('smap-badge-')[1]),
    }))""")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_map_draws_every_service_around_the_domain(browser, senders_data, theme):  # noqa: F811
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        _render(page, senders_data)
        nodes = _map_state(page)
        assert [n["name"] for n in nodes] == ["Google Workspace", "Mailchimp", "Microsoft 365", "Valimail"]
        assert [n["state"] for n in nodes] == ["smap-ready", "smap-missing", "smap-account", "smap-reporting"]
        assert nodes[0]["badges"] == ["SPF:ok", "DKIM:ok"]
        assert nodes[1]["badges"] == ["DKIM:missing"]
        # An account only service has no checklist it is failing.
        assert nodes[2]["badges"] == []
        assert page.locator(".smap-lines line").count() == 4
        assert "turned off" not in page.text_content(".smap-story")
        # The map replaces the vendor cards, and sits above the plan.
        assert page.evaluate("() => document.getElementById('vendors-section').style.display") == "none"
        assert page.evaluate("""() => document.getElementById('sender-map-slot')
            .compareDocumentPosition(document.getElementById('priority-section'))
            & Node.DOCUMENT_POSITION_FOLLOWING""")
        assert page.evaluate("() => document.documentElement.scrollWidth") == 1280
        assert not errors, errors
    finally:
        ctx.close()


def test_it_opens_on_the_service_that_needs_attention(browser, senders_data):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, senders_data)
        assert page.get_attribute(".smap-node:has-text('Mailchimp')", "aria-pressed") == "true"
        detail = page.inner_text("#smap-detail")
        assert "Needs setup: DKIM missing." in detail
        assert "Add it at k1._domainkey.doc44.test" in detail
        assert "The k1 key is missing" in detail
        assert "Something about the apex" not in detail
    finally:
        ctx.close()


def test_selecting_a_service_shows_its_own_records(browser, senders_data):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, senders_data)
        page.click(".smap-node:has-text('Google Workspace')")
        detail = page.inner_text("#smap-detail")
        assert "receives the domain's mail (MX) and 1 more" in detail
        assert "Something about the apex" not in detail
        page.click(".smap-node:has-text('Microsoft 365')")
        detail = page.inner_text("#smap-detail")
        assert "If you start sending through it" in page.text_content("#smap-detail")
        assert "It would go at doc44.test" in detail
        assert "Add it at" not in detail
        assert "Something about the apex" in detail
        assert not errors, errors
    finally:
        ctx.close()


def test_on_a_phone_the_nodes_stack(browser, senders_data):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 390)
    try:
        _render(page, senders_data)
        lefts = page.eval_on_selector_all(".smap-node", "els => els.map(e => Math.round(e.getBoundingClientRect().left))")
        assert len(set(lefts)) == 1
        assert page.evaluate("() => document.documentElement.scrollWidth") == 390
        assert not errors, errors
    finally:
        ctx.close()


def test_other_scopes_draw_no_map(browser, senders_data):  # noqa: F811
    senders_data["scope"] = "deliverability"
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, senders_data)
        assert page.locator(".smap").count() == 0
    finally:
        ctx.close()


def test_a_complete_service_with_a_risk_on_its_own_record_is_amber(browser, senders_data):  # noqa: F811
    # A DKIM alias of Google Workspace's that points at a name with no key.
    alias = _ev("google._domainkey.doc44.test", "CNAME", "gone.example")
    senders_data["sendermap"] = json.loads(json.dumps(MAP))
    senders_data["sendermap"]["services"][0]["claims"].append(
        {"kind": "DKIM CNAME to a missing key", "evidence": alias})
    senders_data["sendermap"]["findings"].append(
        {"severity": "risk", "title": "The google DKIM record points at a name that does not exist",
         "detail": "Remove it.", "evidence": [alias]})
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, senders_data)
        nodes = {n["name"]: n["state"] for n in _map_state(page)}
        assert nodes["Google Workspace"] == "smap-risk"
        assert page.get_attribute(".smap-node:has-text('Google Workspace')", "aria-pressed") == "true"
        assert "Has a risk." in page.inner_text("#smap-detail")
        assert not errors, errors
    finally:
        ctx.close()


def test_a_risk_no_service_claims_shows_above_the_map(browser, senders_data):  # noqa: F811
    # An SPF include of a name with no SPF record cites the apex TXT, which no
    # service claims, so no node would carry it. Notes stay out.
    senders_data["sendermap"] = json.loads(json.dumps(MAP))
    senders_data["sendermap"]["findings"] += [
        {"severity": "risk", "title": "SPF at doc44.test includes ses.amazonaws.com, which publishes no SPF record",
         "detail": "SPF fails.", "evidence": [_ev("doc44.test", "TXT", "include:ses.amazonaws.com")]},
        {"severity": "note", "title": "Just so you know", "detail": "x",
         "evidence": [_ev("doc44.test", "TXT", "include:ses.amazonaws.com")]},
    ]
    ctx, page, errors = _page(browser, "light", 375)
    try:
        _render(page, senders_data)
        box = page.inner_text(".smap-domain-findings")
        assert "includes ses.amazonaws.com" in box
        # Claimed findings stay on their nodes; notes are not shown.
        assert "k1 key" not in box and "apex" not in box and "Just so you know" not in box
        assert not errors, errors
    finally:
        ctx.close()


def test_no_domain_findings_box_when_every_finding_has_a_service(browser, senders_data):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, senders_data)
        assert page.locator(".smap-domain-findings").count() == 0
        assert not errors, errors
    finally:
        ctx.close()
