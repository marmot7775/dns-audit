"""The vendor SPF suggestion must never push a record past 10 lookups.

Run against servicenow.com, mit.edu, ucl.ac.uk and unimelb.edu.au, each
already at 10 of 10 DNS lookups, the SPF card suggested a record with one
more include appended. RFC 7208 section 4.6.4 makes the 11th lookup a
PermError, so pasting the suggestion would have failed SPF for every message.

Two faults combined. The "is this vendor missing?" test was a substring
match on the top-level record only, so a vendor covered inside an include or
a redirect target looked missing: servicenow.com publishes only
"v=spf1 redirect=8sfr6god._spf._d.mim.ec", Mimecast's hosted SPF, and was
told to add include:_netblocks.mimecast.com. Then the builder appended the
include without counting what it would cost, and appended it after the
redirect= modifier.

Now a vendor counts as present when its include (or its hosted SPF zone)
appears anywhere in the resolved tree, an include is only suggested when the
record still fits in 10 lookups with it, and a redirect= record gets no
appended suggestion at all.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import VENDOR_SPF_INCLUDES, _build_suggested_spf  # noqa: E402

GOOGLE_MX = [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]
MIMECAST_MX = [(10, "us-smtp-inbound-1.mimecast.com"), (10, "us-smtp-inbound-2.mimecast.com")]

# _spf.google.com costs 4 lookups: its own include plus three nested ones.
GOOGLE_SPF = {
    "_spf.google.com": {"TXT": [
        "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com "
        "include:_netblocks3.google.com ~all"]},
    "_netblocks.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"]},
    "_netblocks2.google.com": {"TXT": ["v=spf1 ip6:2001:4860:4000::/36 ~all"]},
    "_netblocks3.google.com": {"TXT": ["v=spf1 ip4:172.217.0.0/19 ~all"]},
}


def _zone(domain, spf, mx, extra=None, a_hosts=0):
    zone = {
        domain: {"TXT": [spf], "MX": mx, "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
    }
    for i in range(a_hosts):
        zone[f"h{i}.{domain}"] = {"A": ["203.0.113.3"]}
    zone.update(extra or {})
    return zone


def _a_terms(domain, n):
    return " ".join(f"a:h{i}.{domain}" for i in range(n))


def _spf_card(result):
    return next(c for c in result["checks"] if c["name"] == "SPF")


def test_builder_never_appends_after_redirect():
    # The exact servicenow.com record.
    record = "v=spf1 redirect=8sfr6god._spf._d.mim.ec"
    assert _build_suggested_spf(record, [VENDOR_SPF_INCLUDES["Mimecast"]]) is None
    assert _build_suggested_spf(
        "v=spf1 include:one.test redirect=_spf.vsp.test",
        [VENDOR_SPF_INCLUDES["Google Workspace"]],
    ) is None


def test_hosted_spf_behind_redirect_covers_the_vendor(audit):
    """servicenow.com shape: redirect to a mim.ec record at 10 lookups."""
    domain = "sn.test"
    hosted = "8sfr6god._spf._d.mim.ec"
    extra = {
        hosted: {"TXT": [
            f"v=spf1 exists:%{{ir}}.spf.mail.{domain} ip4:207.211.31.0/25 "
            f"{_a_terms(domain, 7)} include:8sfr6god1._spf._d.mim.ec ~all"]},
        "8sfr6god1._spf._d.mim.ec": {"TXT": ["v=spf1 ip4:72.32.217.0/24 ~all"]},
    }
    result = audit(_zone(domain, f"v=spf1 redirect={hosted}", MIMECAST_MX, extra, 7),
                   domain, scope="email_full")
    card = _spf_card(result)
    assert result["checks"] and card["spf_deep"]["lookup_count"] == 10
    fix = card.get("fix") or ""
    assert "Suggested SPF record" not in fix, fix
    assert "_netblocks.mimecast.com" not in fix, fix


def test_vendor_nested_inside_an_include_is_not_missing(audit):
    domain = "nested.test"
    extra = {"_spf.nested.test": {"TXT": ["v=spf1 include:_spf.google.com ~all"]}}
    extra.update(GOOGLE_SPF)
    result = audit(_zone(domain, "v=spf1 include:_spf.nested.test -all", GOOGLE_MX, extra),
                   domain, scope="email_full")
    fix = _spf_card(result).get("fix") or ""
    assert "Suggested SPF record" not in fix, fix
    assert "Detected services" not in fix, fix


def test_record_at_ten_lookups_gets_no_suggestion(audit):
    """mit.edu, ucl.ac.uk, unimelb.edu.au shape: 10/10, vendor not listed."""
    domain = "full.test"
    result = audit(
        _zone(domain, f"v=spf1 {_a_terms(domain, 10)} -all", GOOGLE_MX, GOOGLE_SPF, 10),
        domain, scope="email_full")
    fix = _spf_card(result).get("fix") or ""
    assert "Suggested SPF record" not in fix, fix
    assert "Google Workspace is not authorized" in fix, fix
    assert "no lookup budget left" in fix, fix
    assert "14 DNS lookups" in fix, fix
    assert "/articles/spf-lookups" in fix, fix


def test_budget_counts_the_whole_include_tree(audit):
    """7 lookups plus _spf.google.com (4) is 11: no suggestion. A record
    with 6 fits at exactly 10, so it still gets one."""
    domain = "seven.test"
    result = audit(
        _zone(domain, f"v=spf1 {_a_terms(domain, 7)} -all", GOOGLE_MX, GOOGLE_SPF, 7),
        domain, scope="email_full")
    fix = _spf_card(result).get("fix") or ""
    assert "Suggested SPF record" not in fix, fix
    assert "11 DNS lookups" in fix, fix

    domain = "six.test"
    result = audit(
        _zone(domain, f"v=spf1 {_a_terms(domain, 6)} -all", GOOGLE_MX, GOOGLE_SPF, 6),
        domain, scope="email_full")
    fix = _spf_card(result).get("fix") or ""
    assert "Suggested SPF record" in fix, fix
    assert f"{_a_terms(domain, 6)} include:_spf.google.com -all" in fix, fix


def test_redirect_record_with_headroom_points_at_the_target(audit):
    domain = "redir.test"
    extra = {"_spf.redir.test": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]}}
    extra.update(GOOGLE_SPF)
    result = audit(_zone(domain, "v=spf1 redirect=_spf.redir.test", GOOGLE_MX, extra),
                   domain, scope="email_full")
    fix = _spf_card(result).get("fix") or ""
    assert "Suggested SPF record" not in fix, fix
    assert "<strong>_spf.redir.test</strong> with redirect=" in fix, fix
