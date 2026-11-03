"""t=y lowers the applied policy one level (RFC 9989 section 4.7).

p=reject with t=y is applied as quarantine by RFC 9989 receivers, and
p=quarantine with t=y as none. The DMARC card already warned; the card's
verdict and explanation, the summary headline and the Spoofing Protection
tile read the published p= alone and said "rejected", "protected" and
"Full" beside it.
"""
import pytest

DOMAIN = "t.test"


def _zone(dmarc):
    return {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
                 "TXT": ["v=spf1 ip4:192.0.2.1 -all"]},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
        f"_dmarc.{DOMAIN}": {"TXT": [dmarc]},
    }


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def test_reject_with_testing_flag_is_not_called_protected(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; t=y; rua=mailto:a@{DOMAIN}"), DOMAIN)
    es = result["executive_summary"]
    assert es["headline"] != "Your domain is protected against spoofing."
    assert es["headline_state"] == "warn"
    assert "t=y" in es["headline"] and "spam" in es["headline"], es["headline"]
    assert es["spoofing_protection"]["label"] != "Full"
    assert es["spoofing_protection"]["color"] != "green"
    assert "refuse mail that fails" not in es["verdict"], es["verdict"]
    card = _dmarc(result)
    assert card["status"] == "warn"
    assert "t=y" in card["verdict"] and "quarantine" in card["verdict"], card["verdict"]
    assert "t=y is set" in card["explanation"]
    assert "p=quarantine" in card["explanation"]


def test_quarantine_with_testing_flag_names_no_action(audit):
    result = audit(_zone(f"v=DMARC1; p=quarantine; t=y; rua=mailto:a@{DOMAIN}"), DOMAIN)
    es = result["executive_summary"]
    assert "t=y" in es["headline"], es["headline"]
    card = _dmarc(result)
    assert "t=y" in card["verdict"] and "no action" in card["verdict"], card["verdict"]


@pytest.mark.parametrize("t", ["", "; t=n"])
def test_reject_without_testing_flag_still_reads_protected(audit, t):
    result = audit(_zone(f"v=DMARC1; p=reject{t}; rua=mailto:a@{DOMAIN}"), DOMAIN)
    es = result["executive_summary"]
    assert es["headline"] == "Your domain is protected against spoofing."
    assert es["spoofing_protection"]["label"] == "Full"
    assert _dmarc(result)["verdict"] == "p=reject (authentication failures are rejected)"
