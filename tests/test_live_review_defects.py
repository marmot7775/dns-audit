"""Defects found by running live audits on 2026-09-23 (gmail.com, paypal.com,
example.com, dns-audit.com).

1. MTA-STS warned about a spare policy line and never checked the direction
   that breaks delivery: an MX host no policy line covers.
2. Duplicate TLS-RPT records showed "Should be exactly one." with no subject,
   and the plan told the domain to configure the record it already had.
3. "<svg>" vanished from BIMI advice because the fix is rendered as HTML.
4. An SPF record ending in redirect= was called neutral.
5. The TTL wait advice rounded down, so "allow that long" undershot.
6. The DMARC Evaluation panel said DKIM was not configured when the DKIM card
   said it could not tell.
7. The web page and the PDF printed their own clock, not the audit time.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checks_extra
import pdf_report
from result_transformer import (
    _build_spf_deep_analysis,
    _humanize_seconds,
    build_security_roadmap,
    format_ttl,
    transform_tls_rpt,
)
from spf_execution_engine import build_dmarc_evaluation

POLICY = "version: STSv1\nmode: enforce\n{mx}max_age: 604800\n"


def _policy_issues(mx_lines, mx_hosts):
    text = POLICY.format(mx="".join(f"mx: {m}\n" for m in mx_lines))
    records = [f"10 {h}." for h in mx_hosts]
    with patch.object(checks_extra, "_lookup_records", return_value=records):
        _, issues = checks_extra._validate_mta_sts_policy(text, "mail.test")
    return issues


def test_a_spare_policy_line_is_info_not_a_warning():
    issues = _policy_issues(
        ["gmail-smtp-in.l.google.com", "*.gmail-smtp-in.l.google.com", "smtp.google.com"],
        ["gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com"])
    assert [i["severity"] for i in issues] == ["info"], issues
    assert "smtp.google.com" in issues[0]["plain_english"]


def test_an_mx_host_no_policy_line_covers_is_a_warning():
    issues = _policy_issues(["mx1.mail.test"], ["mx1.mail.test", "mx2.mail.test"])
    warnings = [i for i in issues if i["severity"] == "warning"]
    assert len(warnings) == 1, issues
    assert "mx2.mail.test" in warnings[0]["plain_english"]
    assert "mx1.mail.test" not in warnings[0]["issue"]


def test_a_wildcard_covers_one_label_only():
    issues = _policy_issues(["*.mail.test"], ["a.b.mail.test"])
    assert any(i["severity"] == "warning" for i in issues), issues


def _duplicate_tls_rpt_card():
    raw = {"status": "error", "record": "v=TLSRPTv1; rua=mailto:a@mail.test",
           "records_found": 2, "report_destinations": ["mailto:a@mail.test"],
           "issues": [checks_extra._make_issue(
               "error", "Multiple TLS-RPT records (2)",
               "2 TLS-RPT records are published at _smtp._tls.mail.test.", "",
               "Delete all but one TLS-RPT record.")]}
    return transform_tls_rpt(raw, "mail.test")


def test_duplicate_tls_rpt_card_names_the_problem():
    card = _duplicate_tls_rpt_card()
    assert card["status"] == "fail"
    assert "2 TLS-RPT records" in card["verdict"]
    assert any("_smtp._tls.mail.test" in d["text"] for d in card["details"])


def test_duplicate_tls_rpt_row_says_fix_not_configure():
    checks = [{"name": "MX", "status": "pass", "configured": True},
              _duplicate_tls_rpt_card()]
    rows = [i for i in build_security_roadmap(checks)["items"] if i["protocol"] == "TLS-RPT"]
    assert len(rows) == 1, rows
    assert "Configure" not in rows[0]["action"]
    assert "Delete all but one" in rows[0]["action"]


def test_bimi_fix_text_keeps_the_svg_element_name():
    with open(checks_extra.__file__, encoding="utf-8") as f:
        src = f.read()
    assert "root <svg> element" not in src
    assert src.count("root &lt;svg&gt; element") == 3
    assert "root <svg> element" in pdf_report._strip_html(
        "Set fixed pixel dimensions on the root &lt;svg&gt; element.")


def test_redirect_without_all_is_not_called_neutral():
    deep = _build_spf_deep_analysis({"record": "v=spf1 redirect=_spf.google.com",
                                     "lookup_count": 4})
    assert "neutral" not in deep["all_explanation"].lower()
    assert "_spf.google.com" in deep["all_explanation"]
    assert deep["all_severity"] == "info"


def test_ttl_wait_rounds_up():
    assert _humanize_seconds(299) == "5m"
    assert _humanize_seconds(101) == "2m"
    assert _humanize_seconds(3601) == "1h1m"
    assert format_ttl(3601)["detail"] == "Changes propagate within 2 hours."


def test_dmarc_eval_says_not_confirmed_when_dkim_is_unsettled():
    ev = build_dmarc_evaluation({"record": "v=DMARC1; p=reject", "policy": "reject"},
                                {"record": "v=spf1 mx ~all", "lookup_count": 1},
                                {"found_selectors": []}, None, dkim_confirmed=False)
    assert ev["dkim_result"] == "not confirmed"
    assert ev["dmarc_result"] == "configured"  # SPF still gives a path


def test_pdf_prints_the_audit_time_not_its_own_clock():
    assert pdf_report._audit_time({"audited_at": "2026-09-23T01:30:00Z"}) == (
        "September 23, 2026 at 01:30 UTC")


def test_migration_raises_a_weaker_sp_before_calling_np_inherited():
    from result_transformer import _build_migration_path
    m = _build_migration_path({"v": "DMARC1", "p": "none", "sp": "quarantine",
                               "rua": "mailto:a@x.test"}, "none", "partial", "x.test")
    actions = [s["action"] for s in m["steps"]]
    sp_i = next(i for i, a in enumerate(actions) if "sp=quarantine to sp=reject" in a)
    np_i = next(i for i, a in enumerate(actions) if "np=reject" in a)
    assert sp_i < np_i, actions
    # Each step's record changes only what its title names.
    assert "sp=reject" in m["steps"][sp_i]["record_after"]
    assert "np=reject" not in m["steps"][sp_i]["record_after"]
    assert "sp=reject; np=reject" in m["steps"][np_i]["record_after"]
