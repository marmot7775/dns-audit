"""Doc 66: five places where two parts of one report said different things.

  - the RFC 9989 strict panel passed pct while the plan beside it carried a
    row to remove the tag, and the spec comparison counted no difference
  - a plan row with no "Why it matters" and "See the card" for an action
  - the ruf note printed twice on the DMARC card, three lines apart
  - "Only 1 slots remain." and "1 DNS lookups"
  - a null MX domain told it had the best chance of reaching inboxes
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import spf_recursive  # noqa: E402
from result_transformer import (  # noqa: E402
    _build_spec_comparison,
    build_executive_summary,
    build_security_roadmap,
    transform_ct,
)

DOMAIN = "doc66.test"
RUA = f"rua=mailto:d@{DOMAIN}"


def _codes(validation, status=None):
    return [c["code"] for c in validation["checks"]
            if status is None or c["status"] == status]


# ---------------------------------------------------------------
# 1. The validator and the card agree about the removed tags
# ---------------------------------------------------------------

@pytest.mark.parametrize("tag,value,code", [
    ("pct", "100", "PCT_REMOVED"),
    ("rf", "afrf", "RF_REMOVED"),
    ("ri", "3600", "RI_REMOVED"),
])
def test_a_removed_tag_is_a_warning_under_rfc_9989_and_a_pass_under_7489(tag, value, code):
    record = f"v=DMARC1; p=reject; {tag}={value}; {RUA}"
    strict = audit_engine._validate_dmarc_strict(record)
    legacy = audit_engine._validate_dmarc_legacy(record)

    row = next(c for c in strict["checks"] if c["code"] == code)
    assert row["status"] == "warn"
    assert row["category"] == "tag_values"
    assert row["message"] == (
        f"{tag} is removed in RFC 9989 (§C.5.2). Receivers on RFC 9989 ignore it."
    )
    assert "PCT_VALID" not in _codes(strict)

    # RFC 7489 defines all three, so the legacy validator is right to be quiet.
    assert legacy["fail_count"] == 0
    assert code not in _codes(legacy)
    assert not any(c["status"] == "warn" and tag in c["message"]
                   for c in legacy["checks"])


def test_the_summary_says_with_warnings_and_the_spec_comparison_counts_them():
    record = f"v=DMARC1; p=reject; pct=100; rf=afrf; ri=3600; {RUA}"
    strict = audit_engine._validate_dmarc_strict(record)
    legacy = audit_engine._validate_dmarc_legacy(record)

    assert strict["fail_count"] == 0
    assert strict["summary"] == "This record passes strict validation with warnings."

    comparison = _build_spec_comparison(strict, legacy)
    codes = {i["code"] for i in comparison["dmarcbis_only_items"]}
    assert {"PCT_REMOVED", "RF_REMOVED", "RI_REMOVED"} <= codes
    assert comparison["dmarcbis_only_count"] >= 3


@pytest.mark.parametrize("value", ["abc", "150"])
def test_a_malformed_pct_still_fails_and_does_not_also_get_the_removal_warning(value):
    strict = audit_engine._validate_dmarc_strict(f"v=DMARC1; p=reject; pct={value}; {RUA}")

    assert "PCT_INVALID" in _codes(strict, "fail")
    assert "PCT_REMOVED" not in _codes(strict)


def test_leading_zeros_keep_their_own_row():
    strict = audit_engine._validate_dmarc_strict(f"v=DMARC1; p=reject; pct=050; {RUA}")

    assert "PCT_LEADING_ZEROS" in _codes(strict, "warn")
    assert "PCT_REMOVED" not in _codes(strict)


# ---------------------------------------------------------------
# 2. A plan row says why it is there and what to do
# ---------------------------------------------------------------

def _fallback_card(details, status="warn", verdict="58 active certs from 8 issuers",
                   name="Certificate Transparency"):
    return {"name": name, "status": status, "verdict": verdict,
            "details": details, "fix": None, "fix_records": None}


def test_a_card_with_no_fix_text_takes_its_first_bad_detail_and_its_verdict():
    card = _fallback_card([
        {"type": "good", "text": "58 active certs from 8 issuers"},
        {"type": "info", "text": "10 wildcard certificates found"},
        {"type": "warning", "text": "16 active certificates will expire soon. "
                                    "Ensure auto-renewal is working."},
        {"type": "warning", "text": "Expiring in 30 days: support.enterprise.test"},
    ])
    item = next(i for i in build_security_roadmap([card])["items"]
                if i["protocol"] == "Certificate Transparency")

    assert item["action"] == ("16 active certificates will expire soon. "
                              "Ensure auto-renewal is working.")
    assert item["impact"] == "58 active certs from 8 issuers"
    assert "Review the" not in item["action"]


def test_a_card_with_no_fix_and_no_bad_detail_gets_no_row_at_all():
    card = _fallback_card([
        {"type": "good", "text": "58 active certs from 8 issuers"},
        {"type": "info", "text": "10 wildcard certificates found"},
    ])
    items = build_security_roadmap([card])["items"]

    assert not [i for i in items if i["protocol"] == "Certificate Transparency"]


# One certificate, active, inside the 30-day window, so the check raises its
# own expiring-soon finding and the card also lists the certificate itself.
CT_ZONE = {
    DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
             "A": ["203.0.113.10"]},
    f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; {RUA}"]},
    f"mail.{DOMAIN}": {"A": ["203.0.113.10"]},
}


def _ct_certs():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    return [{
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": f"www.{DOMAIN}",
        "name_value": f"www.{DOMAIN}",
        "not_before": (now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S"),
        "not_after": (now + timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%S"),
        "id": 1,
    }]


def test_the_ct_row_says_where_certificates_are_renewed(audit):
    result = audit(CT_ZONE, DOMAIN, scope="complete", ct_certs=_ct_certs())
    item = next(i for i in result["security_roadmap"]["items"]
                if i["protocol"] == "Certificate Transparency")

    assert item["what_note"] == (
        "Certificates are renewed with the certificate authority or the host "
        "that issued them, not in DNS."
    )
    assert item["action"] == ("1 active certificate will expire soon. "
                              "Ensure auto-renewal is working.")
    assert item["impact"] == "1 active cert from 1 issuer"


def test_the_ct_card_puts_its_own_findings_above_the_individual_certificates(audit):
    result = audit(CT_ZONE, DOMAIN, scope="complete", ct_certs=_ct_certs())
    card = next(c for c in result["checks"] if c["name"] == "Certificate Transparency")
    warnings = [d["text"] for d in card["details"] if d["type"] == "warning"]

    assert warnings[0].startswith("1 active certificate will expire soon.")
    assert any(w.startswith("Expiring in ") for w in warnings)


# ---------------------------------------------------------------
# 3. The ruf note is printed once
# ---------------------------------------------------------------

def test_the_dmarc_details_list_contains_exactly_one_ruf_line(audit):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "TXT": ["v=spf1 mx -all"]},
        f"_dmarc.{DOMAIN}": {"TXT": [
            f"v=DMARC1; p=reject; {RUA}; ruf=mailto:f@{DOMAIN}; fo=1"
        ]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.10"]},
    }
    card = next(c for c in audit(zone, DOMAIN, scope="email_full")["checks"]
                if c["name"] == "DMARC")
    ruf_lines = [d["text"] for d in card["details"] if "(ruf)" in d["text"]]

    assert len(ruf_lines) == 1, ruf_lines
    assert ruf_lines[0] == (
        "Forensic reporting (ruf) is configured. Most mailbox providers do not "
        "send failure reports because of PII concerns."
    )


# ---------------------------------------------------------------
# 4. The singulars
# ---------------------------------------------------------------

def _spf_zone(includes):
    zone = {DOMAIN: {"TXT": [
        "v=spf1 " + " ".join(f"include:i{n}.test" for n in range(includes)) + " -all"
    ]}}
    for n in range(includes):
        zone[f"i{n}.test"] = {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]}
    return zone


def test_nine_lookups_reads_only_one_slot_remains(audit_zone):
    result = audit_zone(_spf_zone(9), lambda: spf_recursive.count_spf_lookups(DOMAIN))
    blob = " ".join([result["summary"]] + [i["plain_english"] for i in result["issues"]])

    assert result["total_lookups"] == 9
    assert "Only 1 slot remains." in blob
    assert "1 slots remain" not in blob


def test_one_lookup_reads_one_dns_lookup(audit_zone):
    result = audit_zone(_spf_zone(1), lambda: spf_recursive.count_spf_lookups(DOMAIN))

    assert result["total_lookups"] == 1
    assert result["summary"] == "1 DNS lookup (well within the 10-lookup limit)."
    assert "1 DNS lookups" not in result["summary"]


def test_the_spf_card_at_one_lookup_is_singular_too(audit):
    zone = _spf_zone(1)
    zone[DOMAIN]["MX"] = [(10, f"mail.{DOMAIN}")]
    zone[f"mail.{DOMAIN}"] = {"A": ["203.0.113.10"]}
    card = next(c for c in audit(zone, DOMAIN, scope="email_full")["checks"]
                if c["name"] == "SPF")
    blob = " ".join(d["text"] for d in card["details"])

    assert "1 DNS lookup (well within the 10-lookup limit)" in blob
    assert "1 DNS lookups" not in blob


# ---------------------------------------------------------------
# 5. A no-mail domain is not told about inbox placement
# ---------------------------------------------------------------

NO_MAIL_LINE = ("This domain publishes a null MX, so it sends no mail. Its "
                "authentication records are configured to say so.")


def test_a_null_mx_domain_gets_the_no_mail_deliverability_line(audit):
    zone = {
        DOMAIN: {"MX": [(0, "")], "TXT": ["v=spf1 -all"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; {RUA}"]},
    }
    result = audit(zone, DOMAIN, scope="complete")

    assert result["defensive_dns"] is True
    summary = result["executive_summary"]["deliverability_summary"]
    assert summary == NO_MAIL_LINE
    assert "reaching inboxes" not in summary


def test_a_mail_sending_domain_keeps_the_ordinary_deliverability_line():
    checks = [
        {"name": "DMARC", "status": "pass", "configured": True, "pill_label": "Pass",
         "record": f"v=DMARC1; p=reject; {RUA}"},
        {"name": "SPF", "status": "pass", "configured": True, "pill_label": "Pass",
         "record": "v=spf1 mx -all"},
        {"name": "DKIM", "status": "pass", "configured": True, "pill_label": "Pass"},
    ]
    es = build_executive_summary(checks, build_security_roadmap(checks))

    assert "reaching inboxes" in es["deliverability_summary"]
    assert es["deliverability_summary"] != NO_MAIL_LINE
