"""A dangling MX host the domain does not own gets a fix the domain can make.

tartinebakery.com lists an MX at
xo5kn3...mx-verification.google.com, which is NXDOMAIN. The MX card told
the operator to "Add A/AAAA records" for it, which only Google could do.
The record is a leftover from Google Workspace domain verification and the
fix is to delete it. A host inside the audited domain keeps the old advice,
since there adding the addresses is the operator's own change.
"""
import mx_check

DOMAIN = "bakery.example"
GOOGLE_LEFTOVER = "xo5kn3eebwfgmpnctns6pcp4njalxuanntrmbzysuvb7as5dvyba.mx-verification.google.com"


def _issue(audit_zone, mx_host):
    zone = {
        DOMAIN: {"MX": [(1, "aspmx.l.google.com."), (15, mx_host + ".")]},
        "aspmx.l.google.com": {"A": ["192.0.2.1"]},
    }
    result = audit_zone(zone, lambda: mx_check.check_mx(DOMAIN))
    hits = [i for i in result["issues"] if mx_host in i["issue"]]
    assert len(hits) == 1, result["issues"]
    return hits[0]


def test_google_verification_leftover_says_remove_it(audit_zone):
    issue = _issue(audit_zone, GOOGLE_LEFTOVER)
    assert issue["fix"] == (
        f"Remove the MX record pointing at {GOOGLE_LEFTOVER}; it does not resolve."
    )
    assert "Google's leftover setup verification record" in issue["plain_english"]
    assert "Add A/AAAA" not in repr(issue)


def test_other_external_host_says_remove_it(audit_zone):
    host = "mx.gone-provider.example"
    issue = _issue(audit_zone, host)
    assert issue["fix"] == f"Remove the MX record pointing at {host}; it does not resolve."
    assert "gone-provider.example" in issue["plain_english"]
    assert "Google" not in issue["plain_english"]


def test_host_inside_the_domain_keeps_add_records(audit_zone):
    host = f"mail.{DOMAIN}"
    issue = _issue(audit_zone, host)
    assert issue["fix"] == f"Add A/AAAA records for '{host}'."


def test_mx_card_fix_carries_the_new_advice(audit):
    zone = {
        DOMAIN: {
            "MX": [(1, "aspmx.l.google.com."), (15, GOOGLE_LEFTOVER + ".")],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
        },
        "aspmx.l.google.com": {"A": ["192.0.2.1"]},
    }
    result = audit(zone, DOMAIN, scope="email_full")
    card = next(c for c in result["checks"] if c["name"] == "MX Records")
    assert "Remove the MX record pointing at" in (card.get("fix") or "")
    assert "Add A/AAAA" not in repr(card)


def test_a_sibling_under_the_same_registrable_domain_is_outside():
    """shop.example.com cannot assume it controls mail.other.example.com."""
    from mx_check import _dangling_mx_issue
    issue = _dangling_mx_issue("shop.example.com", "mail.other.example.com")
    assert "Remove the MX record" in issue["fix"], issue
    issue = _dangling_mx_issue("shop.example.com", "mx.shop.example.com")
    assert "Add A/AAAA records" in issue["fix"], issue
