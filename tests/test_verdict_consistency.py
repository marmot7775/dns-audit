"""Verdicts that contradicted the record or each other (review of Docs 43 to 70).

Each case runs a declared zone through run_full_audit and checks the card,
the health verdict, the readiness tile, the plan and the resilience section
say the same thing about the same record.
"""
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
from conftest import FakeZone
from test_dmarc_grades import DOMAIN, RUA, _card, _run

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _health(result):
    return _card(result)["tag_breakdown"]["health"]


def _dmarc_rows(result):
    return [i for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"]


# ---------------------------------------------------------------
# A broken record at a subdomain does not stop inheritance
# ---------------------------------------------------------------

def test_malformed_subdomain_record_still_inherits_the_parent_policy(audit):
    org, sub = "acmedoc.com", "mail.acmedoc.com"
    zone = FakeZone({
        sub: {"MX": [(10, f"mx1.{org}")], "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.10"]},
        org: {"NS": [f"ns1.{org}", f"ns2.{org}"], "SOA": ["x"]},
        f"mx1.{org}": {"A": ["203.0.113.11"]},
        f"_dmarc.{sub}": {"TXT": ["v=dmarc1; p=none"]},
        f"_dmarc.{org}": {"TXT": [f"v=DMARC1; p=reject; sp=reject; rua=mailto:d@{org}"]},
    })
    result = audit(zone, sub, scope="dmarc")
    card = _card(result)
    assert card["status"] == "fail"
    assert card["pill_label"] == "Malformed"
    assert "inherited reject from acmedoc.com" in card["verdict"]
    assert card["record"] == "v=dmarc1; p=none"
    assert result["executive_summary"]["spoofing_protection"]["label"] != "None"
    assert result["resilience"]["level"] != "none"


# ---------------------------------------------------------------
# sp or np weaker than p is never "Ready"
# ---------------------------------------------------------------

@pytest.mark.parametrize("dmarc, row", [
    (f"v=DMARC1; p=quarantine; sp=none; {RUA}", "Bring the subdomain policy up to p=quarantine"),
    (f"v=DMARC1; p=reject; sp=quarantine; {RUA}", "Bring the subdomain policy up to p=reject"),
    (f"v=DMARC1; p=reject; np=none; {RUA}", "Set np=reject to match the domain's policy"),
    (f"v=DMARC1; p=quarantine; np=none; {RUA}", "Set np=quarantine to match the domain's policy"),
    (f"v=DMARC1; p=reject; np=quarantine; {RUA}", "Set np=reject to match the domain's policy"),
])
def test_weaker_subdomain_policies_warn_everywhere(audit, dmarc, row):
    result = _run(audit, dmarc)
    card = _card(result)
    assert card["status"] == "warn"
    assert _health(result)["status"] in ("attention", "misconfigured")
    assert result["executive_summary"]["dmarcbis_readiness"]["label"] != "Ready"
    assert card["tag_breakdown"]["migration"]["status"] != "ready"
    assert row in [i["action"] for i in _dmarc_rows(result)]


# ---------------------------------------------------------------
# Advisories that do not lower enforcement leave the record Ready
# ---------------------------------------------------------------

def test_failure_reporting_without_fo_does_not_hold_back_ready(audit):
    # The paypal.com shape.
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}; ruf=mailto:f@{DOMAIN}")
    assert _health(result)["status"] == "ready"
    assert result["executive_summary"]["dmarcbis_readiness"]["label"] == "Ready"
    assert "Underutilized failure reporting" not in [i["action"] for i in _dmarc_rows(result)]


def test_test_mode_row_is_an_instruction(audit):
    result = _run(audit, f"v=DMARC1; p=reject; t=y; {RUA}")
    assert _health(result)["status"] == "attention"
    rows = {i["action"]: i["impact"] for i in _dmarc_rows(result)}
    assert "Remove t=y so p=reject applies in full" in rows
    assert rows["Remove t=y so p=reject applies in full"]
    assert "Test mode weakens reject" not in rows


def test_attention_keeps_the_removed_tags_row(audit):
    result = _run(audit, f"v=DMARC1; p=reject; t=y; pct=50; {RUA}")
    actions = [i["action"] for i in _dmarc_rows(result)]
    assert any(a.startswith("Remove the tag RFC 9989 retired: pct") for a in actions), actions


# ---------------------------------------------------------------
# The strict panel grades the way the card does
# ---------------------------------------------------------------

@pytest.mark.parametrize("dmarc", [
    f"v=DMARC1; p=rejectt; {RUA}",
    f"v=DMARC1; p=reject; adkim=x; {RUA}",
    f"v=DMARC1; p=reject; fo=2; {RUA}",
    f"v=DMARC1; p=reject; t=maybe; {RUA}",
    f"v=DMARC1; p=reject; rua=MAILTO:d@{DOMAIN}",
])
def test_strict_panel_has_no_structural_errors_when_the_card_does_not_fail(audit, dmarc):
    card = _card(_run(audit, dmarc))
    assert card["status"] != "fail"
    assert card["strict_validation"]["has_structural_errors"] is False
    assert card["strict_validation"]["fail_count"] == 0


def test_invalid_sp_without_rua_still_fails_both(audit):
    card = _card(_run(audit, "v=DMARC1; p=reject; sp=bogus"))
    assert card["status"] == "fail"
    assert card["strict_validation"]["has_structural_errors"] is True


# ---------------------------------------------------------------
# A lookup that did not complete is not an absence
# ---------------------------------------------------------------

def test_mx_timeout_is_not_no_mail(audit):
    import dns.resolver
    from test_dmarc_grades import _zone
    zone = _zone(f"v=DMARC1; p=none; {RUA}", spf="some-other-txt")
    zone.fail(DOMAIN, "MX", dns.resolver.LifetimeTimeout(timeout=1.0, errors={}))
    result = audit(zone, DOMAIN, dkim_selector="s1")
    assert result["resilience"]["level"] != "not_applicable"
    assert "does not send or receive mail" not in result["resilience"]["summary"]


# ---------------------------------------------------------------
# SPF with no space after v=spf1 is published, not missing
# ---------------------------------------------------------------

def test_spf_without_space_after_version_is_malformed_not_missing(audit):
    card = _card(_run(audit, f"v=DMARC1; p=reject; {RUA}",
                      spf="v=spf1ip4:192.0.2.0/24 -all"), "SPF")
    assert card["status"] == "fail"
    assert card["pill_label"] == "Malformed"
    assert card["record"] == "v=spf1ip4:192.0.2.0/24 -all"
    assert "No SPF record" not in card["verdict"]


# ---------------------------------------------------------------
# A domain that sends no mail is not told to add rua
# ---------------------------------------------------------------

def test_null_mx_record_builder_adds_no_rua(audit):
    zone = FakeZone({
        DOMAIN: {"MX": [(0, ".")], "TXT": ["v=spf1 -all"], "A": ["203.0.113.10"],
                 "NS": [f"ns1.{DOMAIN}"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=quarantine"]},
    })
    tb = _card(audit(zone, DOMAIN))["tag_breakdown"]
    rb = tb["record_builder"]
    assert "rua=" not in (rb.get("recommended_record") or "")
    assert not any(c.get("tag") == "rua" for c in rb.get("changes", []))
    mig = tb["migration"]
    if mig.get("status") == "migration":
        assert "rua=" not in mig["target_record"]
        assert not any("rua" in s.get("tags_changed", []) for s in mig["steps"])


# ---------------------------------------------------------------
# MTA-STS policy served with a charset Python does not know
# ---------------------------------------------------------------

def test_mta_sts_policy_with_unknown_charset_is_read():
    import conftest
    from test_dmarc_grades import _zone
    policy = ("version: STSv1\nmode: enforce\nmx: mx1.doc44.test\nmx: mx2.doc44.test\n"
              "max_age: 604800\n")

    class Binary(conftest.FakeHttpResponse):
        encoding = "binary"   # Content-Type: text/plain; charset=binary

    zone = _zone(f"v=DMARC1; p=reject; {RUA}",
                 extra={f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20260101"]},
                        f"mta-sts.{DOMAIN}": {"A": ["203.0.113.20"]}})
    # fake_dns patches the fetch itself, so this patch goes inside it.
    with conftest.fake_dns(zone, mta_sts_policy=policy):
        with patch("checks_extra._safe_fetch", lambda url, *a, **k: Binary(policy)):
            result = audit_engine.run_full_audit(DOMAIN, scope="transport")
    card = _card(result, "MTA-STS")
    assert card["status"] == "pass", (card["status"], card.get("verdict"))
