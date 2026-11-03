"""A named selector whose TXT record has no p= is a broken key, not a miss.

RFC 6376 section 3.6.1 makes p= required. The card said "Checked 1
selector, no public key found" and told the user to re-run with the
selector entered, which they had done.
"""
import pytest

DOMAIN = "t.test"


def _dkim(audit, rec):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
                 "TXT": ["v=spf1 ip4:192.0.2.1 -all"]},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
        f"sel._domainkey.{DOMAIN}": {"TXT": [rec]},
    }
    result = audit(zone, DOMAIN, dkim_selector="sel")
    return next(c for c in result["checks"] if c["name"] == "DKIM")


def _texts(card):
    return " | ".join(d.get("text", "") for d in card["details"])


@pytest.mark.parametrize("rec", ["v=DKIM1; k=rsa", "k=rsa; n=x"])
def test_dkim_record_without_p_tag_fails_and_says_so(audit, rec):
    card = _dkim(audit, rec)
    assert card["status"] == "fail", card["verdict"]
    assert "p=" in card["verdict"]
    assert "has no p= tag" in _texts(card)
    assert rec in _texts(card)
    assert "Re-run the audit" not in _texts(card)


def test_a_txt_that_is_not_dkim_is_named_for_what_it_is(audit):
    card = _dkim(audit, "hello world")
    assert card["status"] == "fail"
    assert "not DKIM" in card["verdict"]
    assert "is not a DKIM key record" in _texts(card)
    assert "hello world" in _texts(card)
    assert "Re-run the audit" not in _texts(card)


def test_an_empty_p_is_still_retired(audit):
    card = _dkim(audit, "v=DKIM1; k=rsa; p=")
    assert card["pill_label"] == "Retired"
