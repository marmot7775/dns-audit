"""The DMARC card names only the no-mail records the domain publishes.

A domain is treated as defensive on two signals, and null SPF plus
p=reject is enough, so a domain with a real MX can be one. The card said
"(null MX, null SPF)" for it, which the MX card on the same page
contradicted.
"""
DOMAIN = "t.test"


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def test_null_spf_with_a_real_mx_does_not_claim_null_mx(audit):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}"), (20, f"mail2.{DOMAIN}")],
                 "TXT": ["v=spf1 -all"], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
        f"mail2.{DOMAIN}": {"A": ["192.0.2.2"]},
        f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject"]},
    }
    card = _dmarc(audit(zone, DOMAIN))
    assert "null MX" not in card["explanation"], card["explanation"]
    assert "null SPF" in card["explanation"]
    assert "no legitimate mail" not in card["explanation"]


def test_null_mx_and_null_spf_still_named_together(audit):
    zone = {
        DOMAIN: {"MX": [(0, ".")], "TXT": ["v=spf1 -all"],
                 "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=reject"]},
    }
    card = _dmarc(audit(zone, DOMAIN))
    assert "(null MX, null SPF)" in card["explanation"], card["explanation"]
