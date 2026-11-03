"""A CAA set with no issue property does not restrict the bare domain.

RFC 8659 section 4: with no issue property any CA may issue for the name,
and issuewild governs wildcards only. The card passed "Certificate
issuance restricted" for an iodef-only or issuewild-only set.
"""
import pytest

DOMAIN = "t.test"


def _caa(audit, caa):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
                 "CAA": caa},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
    }
    result = audit(zone, DOMAIN)
    return next(c for c in result["checks"] if c["name"] == "CAA")


def test_iodef_only_names_no_issuer(audit):
    card = _caa(audit, [(0, "iodef", f"mailto:a@{DOMAIN}")])
    assert card["status"] == "warn", card["verdict"]
    assert card["verdict"] == "No issuer named: any CA may issue"
    assert card["fix"] and "issue" in card["fix"]


@pytest.mark.parametrize("value", [";", "letsencrypt.org"])
def test_issuewild_only_restricts_wildcards_only(audit, value):
    card = _caa(audit, [(0, "issuewild", value)])
    assert card["status"] == "warn", card["verdict"]
    assert card["verdict"] == "Only wildcard certificates restricted"


@pytest.mark.parametrize("value,verdict", [
    ("letsencrypt.org", "Restricted to letsencrypt.org"),
    (";", "Certificate issuance restricted"),
])
def test_an_issue_property_still_passes(audit, value, verdict):
    card = _caa(audit, [(0, "issue", value)])
    assert card["status"] == "pass", card["details"]
    assert card["verdict"] == verdict
