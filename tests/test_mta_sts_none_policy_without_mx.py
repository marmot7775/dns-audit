"""RFC 8461 section 3.2: mx is required "except when mode is none".

Section 8.3 recommends exactly the minimal none policy to withdraw MTA-STS:
version, mode: none and a small max_age. It was failed for having no mx
lines, and the fix text told the operator to undo the opt-out.
"""
import pytest

DOMAIN = "t.test"
ZONE = {
    DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
    f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
    f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=1"]},
    f"mta-sts.{DOMAIN}": {"A": ["192.0.2.9"]},
}


def _card(audit, policy):
    result = audit(ZONE, DOMAIN, mta_sts_policy=policy)
    return next(c for c in result["checks"] if c["name"] == "MTA-STS")


@pytest.mark.parametrize("policy", [
    f"version: STSv1\nmode: none\nmx: mail.{DOMAIN}\nmax_age: 86400\n",
    "version: STSv1\nmode: none\nmax_age: 86400\n",
])
def test_mode_none_reads_turned_off_with_or_without_mx(audit, policy):
    card = _card(audit, policy)
    assert (card["status"], card["pill_label"]) == ("absent", "Turned off"), card["details"]


@pytest.mark.parametrize("mode", ["testing", "enforce"])
def test_testing_and_enforce_still_need_mx(audit, mode):
    card = _card(audit, f"version: STSv1\nmode: {mode}\nmax_age: 86400\n")
    assert card["status"] == "fail"
    assert any("at least one MX hostname pattern" in d.get("text", "")
               for d in card["details"]), card["details"]
