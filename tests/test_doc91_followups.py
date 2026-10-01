"""Follow-ups to Doc 91 from CodeRabbit's second review of PR #125.

- A report destination whose MX lookup timed out is "unknown", not "no MX":
  only NoAnswer or NXDOMAIN shows "No MX record found".
- A TLS-RPT mailto: with an empty local part or host is malformed, not just
  one with no @ at all.
- The report chain summary says when an authorization lookup did not finish,
  instead of folding it into "no authorization failures".
"""
import os
import sys

import dns.exception
import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns  # noqa: E402
import audit_engine  # noqa: E402
from checks_extra import _validate_tls_rpt_record  # noqa: E402

DOMAIN = "rc.test"
RECEIVER = "reports.example"


def _dests(zone):
    raw = {"record": f"v=DMARC1; p=none; rua=mailto:d@{RECEIVER}",
           "rua": f"mailto:d@{RECEIVER}", "policy": "none"}
    with fake_dns(zone):
        rc = audit_engine._check_report_authorization(DOMAIN, raw)
    return rc["report_destinations"]


def test_mx_timeout_is_unknown_and_no_answer_is_false():
    zone = FakeZone({f"{DOMAIN}._report._dmarc.{RECEIVER}": {"TXT": ["v=DMARC1"]},
                     RECEIVER: {"A": ["203.0.113.5"]}})
    zone.fail(RECEIVER, "MX", dns.exception.Timeout())
    assert _dests(zone)[0]["has_mx"] is None

    zone = FakeZone({f"{DOMAIN}._report._dmarc.{RECEIVER}": {"TXT": ["v=DMARC1"]},
                     RECEIVER: {"A": ["203.0.113.5"]}})
    zone.fail(RECEIVER, "MX", dns.resolver.NoAnswer())
    assert _dests(zone)[0]["has_mx"] is False


def test_tls_rpt_mailto_needs_a_local_part_and_a_host():
    for bad in ("mailto:@x.test", "mailto:tls@", "mailto:", "mailto:a@b@c.test"):
        _, issues = _validate_tls_rpt_record(f"v=TLSRPTv1; rua={bad}", "x.test")
        assert any("Invalid email in rua" in i["issue"] for i in issues), bad
    _, issues = _validate_tls_rpt_record("v=TLSRPTv1; rua=mailto:tls@x.test", "x.test")
    assert not any("Invalid email" in i["issue"] for i in issues)


def test_report_chain_names_unconfirmed_authorization():
    src = open(os.path.join(os.path.dirname(audit_engine.__file__), "static", "app.js"),
               encoding="utf-8").read()
    start = src.index("function _reportChainSummary(rc)")
    body = src[start:src.index("\n}\n", start)]
    assert "authorization_check_failed" in body and "not confirmed" in body
