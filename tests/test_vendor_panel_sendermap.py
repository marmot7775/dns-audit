"""The vendor panel, the DKIM card and the API read Sendermap's map.

Sendermap step 2: the audit runs sendermap_adapter.map_senders where the
fingerprinter ran, and _format_vendors builds the panel's rows from the
map's services. Each row keeps the fields the page and the PDF read (name,
tier, detected_via, sources, role, missing) and adds signals, every claim
with the record it shows. missing comes from the service's setups: a
required record the map shows missing, with what was asked.

The map here is real: allbirds.com mapped on 2026-10-22 through the audit's
resolver, its DNS answers recorded with sendermap.testing.RecordingResolver
in fixtures/sendermap/allbirds.com.dns.json (questions later releases ask
filled live on 2026-10-28) and replayed, so nothing here
reaches the network.
"""
import asyncio
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sendermap
from sendermap.engine import map_domain
from sendermap.model import (Claim, Evidence, Kind, Need, Role, Run, SenderMap, Service,
                             Setup, SetupItem, State, Tier)
from sendermap.testing import ReplayResolver

import audit_engine
import pdf_report
import result_transformer
from audit_engine import _format_vendors

ROOT = Path(__file__).resolve().parent.parent
RECORDING = Path(__file__).parent / "fixtures" / "sendermap" / "allbirds.com.dns.json"
CHECKED_AT = datetime(2026, 10, 22, tzinfo=timezone.utc)


def _replayed(domain="allbirds.com"):
    replay = ReplayResolver(RECORDING, "system")
    smap = asyncio.run(map_domain(domain, checked_at=CHECKED_AT, resolver=replay,
                                  use_web=False, use_subdomains=False, use_ct=False))
    assert replay.missed == [], replay.missed
    return smap


@pytest.fixture(scope="module")
def allbirds():
    return _replayed()


@pytest.fixture(scope="module")
def panel(allbirds):
    return {v["name"]: v for v in _format_vendors(allbirds)}


# ---------------------------------------------------------------------------
# _format_vendors from the recorded map
# ---------------------------------------------------------------------------

def test_every_service_in_the_map_is_a_row(allbirds, panel):
    assert set(panel) == {s.name for s in allbirds.services}


def test_tiers_are_the_maps_four_words_strongest_first(allbirds):
    rows = _format_vendors(allbirds)
    assert {r["tier"] for r in rows} <= {"In use", "Configured", "Likely", "Account only"}
    ranks = [audit_engine.VENDOR_TIERS.index(r["tier"]) for r in rows]
    assert ranks == sorted(ranks)


def test_tier_and_role_follow_the_record_that_decided_it(panel):
    assert panel["Microsoft 365"]["tier"] == "In use"  # MX
    assert panel["Mailchimp"]["tier"] == "Configured"  # k1 CNAME into Mailchimp's zone
    assert panel["Customer.io"]["tier"] == "Likely"    # krs key known by its name
    assert all(v["role"] == "sender" for v in panel.values())


def test_sides_come_from_the_claim_kinds(panel):
    # MX is inbound; SPF and DKIM are outbound.
    assert panel["Microsoft 365"]["detected_via"] == "outbound + inbound"
    # A link tracking CNAME and a bounce CNAME are outbound.
    assert panel["Iterable"]["detected_via"] == "outbound"
    assert panel["Iterable"]["sources"] == ["tracking CNAME"]
    assert panel["Postmark"]["sources"] == ["return path CNAME"]
    assert panel["Mailchimp"]["sources"] == ["DKIM CNAME"]


def test_signals_carry_the_record_the_first_one_decided_the_tier(allbirds, panel):
    m365 = panel["Microsoft 365"]["signals"]
    assert m365[0] == {"source": "MX", "where": "allbirds.com",
                       "record": "allbirds.com MX 0 allbirds-com.mail.protection.outlook.com"}
    assert any(s["record"] == "allbirds.com TXT include:spf.protection.outlook.com" for s in m365)
    by_name = {s.name: s for s in allbirds.services}
    for name, row in panel.items():
        assert row["signals"][0]["record"] == str(by_name[name].decided_by.evidence), name
        assert len(row["signals"]) == len(by_name[name].claims), name


def test_missing_lists_required_records_with_what_was_asked(panel):
    assert panel["Mailjet"]["missing"] == [
        "No DKIM for Mailjet at allbirds.com: no key at mailjet._domainkey, a name that "
        "does not exist. Asked: TXT at mailjet._domainkey.allbirds.com."
    ]


def test_an_optional_record_not_published_is_not_missing(panel):
    # Google Workspace's MX is optional in its setup and allbirds.com's MX is
    # Microsoft's; SendGrid's return path and tracking CNAMEs are optional.
    assert panel["Google Workspace"]["missing"] == []
    assert panel["SendGrid"]["missing"] == []


def test_no_confidence_filter_every_service_shows(panel):
    # The fingerprinter dropped anything under 0.5; the map has no such floor,
    # so a key known only by its name still shows, as Likely.
    assert "Mandrill" in panel and panel["Mandrill"]["tier"] == "Likely"


def _service(name, tier, role, kind, record, setups=()):
    evidence = Evidence("example.test", "TXT", record, CHECKED_AT)
    claim = Claim(name, kind, "example.test", evidence)
    return Service(name, "Mailbox", tier, role, (claim,), setups)


def _map(*services):
    return SenderMap("example.test", tuple(services), Run(CHECKED_AT, 0.1, 3, "system"))


def test_account_only_and_reporting_rows_claim_nothing_missing():
    missing_spf = Setup("Microsoft 365", "example.test", (
        SetupItem("spf", Need.REQUIRED, State.MISSING, (), "TXT at example.test",
                  "the record does not authorize spf.protection.outlook.com"),), False)
    rows = _format_vendors(_map(
        _service("dmarcian", None, Role.REPORTING, Kind.DMARC_REPORTS,
                 "v=DMARC1; p=reject; rua=mailto:x@ag.dmarcian.com"),
        _service("Microsoft 365", Tier.ACCOUNT_ONLY, Role.SENDER, Kind.TOKEN,
                 "MS=ms12345678", (missing_spf,)),
    ))
    by_name = {r["name"]: r for r in rows}
    assert by_name["Microsoft 365"]["role"] == "account"
    assert by_name["Microsoft 365"]["missing"] == []
    assert by_name["dmarcian"]["role"] == "reporting"
    assert by_name["dmarcian"]["tier"] is None
    assert by_name["dmarcian"]["sources"] == ["DMARC reports"]
    # Reporting services go last, where the panel shows them today.
    assert [r["name"] for r in rows] == ["Microsoft 365", "dmarcian"]


def test_no_map_gives_no_rows():
    assert _format_vendors(None) == []


# ---------------------------------------------------------------------------
# The audit: the map in the payload, and a map that did not finish
# ---------------------------------------------------------------------------

ZONE = {
    "allbirds.com": {"TXT": ["v=spf1 include:spf.protection.outlook.com -all"],
                     "MX": [(0, "allbirds-com.mail.protection.outlook.com")]},
    "_dmarc.allbirds.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@allbirds.com"]},
}


def test_the_audit_carries_the_map_and_builds_the_panel_from_it(audit, allbirds, monkeypatch):
    monkeypatch.setattr(audit_engine, "map_senders", lambda domain, budget: allbirds)
    result = audit(ZONE, "allbirds.com", scope="email_security")
    assert result["vendors_status"] == "assessed"
    assert result["sendermap"] == allbirds.to_dict()
    assert [v["name"] for v in result["vendors"]] == [v["name"] for v in _format_vendors(allbirds)]


def test_a_map_that_does_not_finish_leaves_the_panel_not_assessed(audit, monkeypatch):
    monkeypatch.setattr(audit_engine, "map_senders", lambda domain, budget: None)
    result = audit(ZONE, "allbirds.com", scope="email_security")
    assert result["vendors_status"] == "unavailable"
    assert result["vendors"] == []
    assert result["sendermap"] is None
    # No missing records claimed anywhere: the SPF card asks for no include.
    spf = next(c for c in result["checks"] if c["name"] == "SPF")
    assert "Detected services" not in (spf.get("fix") or "")


def test_the_budget_reaches_the_map_inside_the_deadline(audit, monkeypatch):
    seen = {}

    def fake(domain, budget):
        seen["budget"] = budget
        return None

    monkeypatch.setattr(audit_engine, "map_senders", fake)
    audit(ZONE, "allbirds.com", scope="email_security")
    assert 0 < seen["budget"] <= audit_engine.SENDER_MAP_BUDGET == 8


def test_a_scope_without_email_checks_runs_no_map(audit, monkeypatch):
    def fail(domain, budget):
        raise AssertionError("the map ran for a scope with no email checks")

    monkeypatch.setattr(audit_engine, "map_senders", fail)
    result = audit(ZONE, "allbirds.com", scope="dns_security")
    assert result["vendors_status"] is None
    assert result["sendermap"] is None


# allbirds.com's record as published on 2026-10-22: EasyDMARC's flattened
# include, whose ranges the map credits to Google Workspace, Mailgun, Mailjet
# and Zendesk among others.
EASYDMARC_ZONE = {
    "allbirds.com": {"TXT": ["v=spf1 include:allbirds_com._es.easydmarc.com "
                             "include:spf.protection.outlook.com ~all"],
                     "MX": [(0, "allbirds-com.mail.protection.outlook.com")]},
    "_dmarc.allbirds.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@allbirds.com"]},
}


def _spf_fix(result):
    spf = next(c for c in result["checks"] if c["name"] == "SPF")
    return spf.get("fix") or ""


def test_a_vendor_the_map_found_in_the_apex_spf_is_not_sent_to_check_it(audit, allbirds,
                                                                         monkeypatch):
    monkeypatch.setattr(audit_engine, "map_senders", lambda domain, budget: allbirds)
    assert "Detected services" not in _spf_fix(audit(EASYDMARC_ZONE, "allbirds.com",
                                                     scope="email_security"))
    # Without the map's SPF signals the same audit asks about them, so the
    # skip is what removes the hint.
    monkeypatch.setattr(audit_engine, "_spf_signal_at", lambda v, domain: False)
    assert "Detected services" in _spf_fix(audit(EASYDMARC_ZONE, "allbirds.com",
                                                 scope="email_security"))


def test_an_spf_signal_counts_only_at_the_domain_itself():
    row = {"signals": [{"source": "SPF", "where": "Allbirds.com.", "record": "x"}]}
    assert audit_engine._spf_signal_at(row, "allbirds.com")
    row = {"signals": [{"source": "SPF", "where": "mail.allbirds.com", "record": "x"},
                       {"source": "MX", "where": "allbirds.com", "record": "x"}]}
    assert not audit_engine._spf_signal_at(row, "allbirds.com")


def test_dropped_nameservers_read_the_same_on_the_page_and_in_the_pdf():
    app = (ROOT / "static" / "app.js").read_text()
    m = re.search(r"const VENDORS_DROPPED = '((?:[^'\\]|\\.)+)';", app)
    assert m and m.group(1).replace("\\'", "'") == pdf_report.VENDORS_DROPPED
    els = pdf_report._vendors({"vendors": [], "vendors_status": "unavailable",
                               "vendors_reason": "queries_dropped"}, pdf_report._styles())
    assert any("stopped answering" in getattr(e, "text", "") for e in els)


def test_not_assessed_reads_the_same_on_the_page_and_in_the_pdf():
    app = (ROOT / "static" / "app.js").read_text()
    m = re.search(r"const VENDORS_UNCHECKED = '([^']+)';", app)
    assert m and m.group(1) == pdf_report.VENDORS_UNCHECKED
    els = pdf_report._vendors({"vendors": [], "vendors_status": "unavailable"},
                              pdf_report._styles())
    assert any(pdf_report.VENDORS_UNCHECKED in getattr(e, "text", "") for e in els)


# ---------------------------------------------------------------------------
# The DKIM card: the map first, then the catalog
# ---------------------------------------------------------------------------

DKIM_RECORD = ("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwQ7hD3Cj2Nk5vH9g"
               "YxBf3m6QeZ4j1T2nYh6uJ0rP8kL5sA7dE9fG2hI4jK6lM8nO0pQ2rS4tU6vW8xY0zA2bC4dE6fG8hI"
               "0jK2lM4nO6pQ8rS0tU2vW4xY6zA8bC0dE2fG4hI6jK8lM0nO2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hI"
               "2jK4lM6nO8pQ0rS2tU4vW6xY8zA0bC2dE4fG6hI8jK0lM2nO4pQ6rS8tU0vW2xY4zA6bC8dE0fG2hI"
               "4jK6lM8nO0pQ2rS4tU6vW8xY0zA2bC4dE6fG8hI0jK2lM4nO6pQ8rS0tU2vW4xY6zA8bC0dE2fG4hI"
               "6jK8lM0nO2pQ4rS6tU8vW0xY2zA4bC6dE8fG0hI2jK4lM6nO8pQ0rS2tU4vW6xY8zA0bC2dE4fG6hI"
               "8jK0lM2nO4pQIDAQAB")


def _raw_dkim(selectors, map_providers=None, cname=None):
    raw = {"configured": True, "status": "pass", "discovery_method": "spf_intelligent",
           "tested_count": 86, "issues": [],
           "found_selectors": [{"selector": s, "record": DKIM_RECORD, "vendor": None,
                                **({"cname_target": cname, "cname_chain": [cname]} if cname else {})}
                               for s in selectors]}
    if map_providers:
        raw["map_providers"] = map_providers
    return raw


def _providers(raw):
    return {k["selector"]: k["provider"]
            for k in result_transformer._build_dkim_key_analysis(raw)["keys"]}


def test_the_card_names_a_key_from_the_map_first():
    # krs is Customer.io in the map; the map's word wins over the catalog's.
    raw = _raw_dkim(["krs"], map_providers={"krs": "Customer.io"})
    card = result_transformer.transform_dkim(raw, "allbirds.com")
    assert "Sending providers detected: Customer.io." in card["explanation"]
    assert _providers(raw) == {"krs": "Customer.io"}


def test_the_map_beats_a_selector_name_the_catalog_reads_otherwise():
    # k1 is Mailchimp by name; on a domain whose map credits it to another
    # service, the card says what the map says.
    raw = _raw_dkim(["k1"], map_providers={"k1": "Mailgun"})
    card = result_transformer.transform_dkim(raw, "example.test")
    assert "Sending providers detected: Mailgun." in card["explanation"]


def test_a_key_the_map_did_not_see_is_named_from_the_catalog():
    raw = _raw_dkim(["mandrill"])
    assert _providers(raw) == {"mandrill": "Mandrill"}
    # The CNAME target before the selector name.
    raw = _raw_dkim(["k1"], cname="k1.domainkey.u1.wl.sendgrid.net")
    assert _providers(raw) == {"k1": "SendGrid"}


def test_the_audit_hands_the_maps_providers_to_the_card(audit, allbirds, monkeypatch):
    zone = dict(ZONE)
    zone["krs._domainkey.allbirds.com"] = {"TXT": [DKIM_RECORD]}
    monkeypatch.setattr(audit_engine, "map_senders", lambda domain, budget: allbirds)
    # Only the map can name it here.
    monkeypatch.setattr(result_transformer, "dkim_key_provider", lambda *a, **k: None)
    result = audit(zone, "allbirds.com", scope="email_security", dkim_selector="krs")
    card = next(c for c in result["checks"] if c["name"] == "DKIM")
    assert "Customer.io" in card["explanation"], card["explanation"]


# ---------------------------------------------------------------------------
# The API payload
# ---------------------------------------------------------------------------

def test_the_api_payload_carries_the_map_and_it_validates(allbirds, monkeypatch):
    from fastapi.testclient import TestClient
    from conftest import FakeZone, fake_dns
    import server as server_module

    monkeypatch.setattr(audit_engine, "map_senders", lambda domain, budget: allbirds)
    monkeypatch.setattr(server_module, "RATE_LIMIT_MAX", 10_000)
    # A fresh audit, whatever earlier tests left in the cache or patched in.
    monkeypatch.setattr(server_module, "_cache", {})
    monkeypatch.setattr(server_module, "run_full_audit", audit_engine.run_full_audit)
    with fake_dns(FakeZone(ZONE)):
        response = TestClient(server_module.app).get(
            "/api/audit", params={"domain": "allbirds.com", "scope": "email_security"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "sendermap" in payload, (sorted(payload), payload.get("error"), payload.get("vendors"))
    assert payload["sendermap"]["schema"] == "sendermap/1"
    jsonschema.validate(payload["sendermap"], sendermap.schema())
    assert {v["name"] for v in payload["vendors"]} == {s.name for s in allbirds.services}
