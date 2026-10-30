"""Fixes from the 2026-10-30 nightly run."""
import logging

import pytest

import audit_engine
import result_transformer
import sendermap_adapter
from conftest import fake_dns
from test_dkim_dropped_queries import DOMAIN, _zone


@pytest.mark.parametrize("digit", ["²", "٥", "５"])
def test_non_ascii_digits_are_not_a_pct(digit):
    record = f"v=DMARC1; p=quarantine; pct={digit}; rua=mailto:d@x.test"
    assert result_transformer._dmarc_pct_kept(record) is None


def test_ascii_pct_below_100_is_still_kept():
    assert result_transformer._dmarc_pct_kept("v=DMARC1; p=quarantine; pct=5") == 5


def test_superscript_pct_does_not_abort_the_audit(audit):
    domain = "pct.test"
    record = "v=DMARC1; p=quarantine; pct=²; rua=mailto:d@pct.test"
    result = audit({
        domain: {"NS": [f"ns1.{domain}", f"ns2.{domain}"], "MX": [(10, f"mx.{domain}")],
                 "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.5"]},
        f"mx.{domain}": {"A": ["203.0.113.6"]},
        f"_dmarc.{domain}": {"TXT": [record]},
    }, domain, scope="dmarc")
    assert "security_roadmap" in result


def test_skipped_sender_map_still_completes_its_step():
    seen = []
    with fake_dns(_zone()):
        audit_engine.run_full_audit(
            DOMAIN, scope="email_security",
            progress_callback=lambda step, done, total: seen.append((step, done, total)))
    _, done, total = seen[-1]
    assert done == total


def test_sender_map_failure_is_logged_at_warning(monkeypatch, caplog):
    async def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(sendermap_adapter, "map_domain", boom)
    with caplog.at_level(logging.WARNING, logger="sendermap_adapter"):
        assert sendermap_adapter.map_senders("example.test", 1) is None
    assert "Sender map for example.test failed" in caplog.text
    assert "exceeded its" not in caplog.text


def test_wildcard_is_found_when_it_is_not_the_first_name(monkeypatch):
    from datetime import datetime, timedelta

    from test_ct_active_cert_validity_window import _cert, _run
    now = datetime.utcnow()
    cert = _cert("1", "example.com", now - timedelta(days=10), now + timedelta(days=80))
    cert["name_value"] = "example.com\n*.example.com"
    raw = _run([cert], monkeypatch)
    assert [w["common_name"] for w in raw["wildcards"]] == ["*.example.com"]


@pytest.mark.parametrize("spf", ["v=spf1 mx -all", "v=spf1 ip4:203.0.113.99 -all", "v=spf1 -all"])
@pytest.mark.parametrize("tags", ["", "; aspf=s; adkim=s"])
def test_scope_marker_only_on_a_card_that_is_still_a_pass(audit, spf, tags):
    from test_dmarc_grades import RUA, _card, _run
    result = _run(audit, f"v=DMARC1; p=none; {RUA}{tags}", scope="deliverability", spf=spf)
    card = _card(result)
    if card["status"] != "pass":
        assert card["graded_for_scope"] is None
        headline = result["executive_summary"].get("headline") or ""
        assert "mailbox providers ask bulk senders for" not in headline
