"""A null MX in any shape but the lone "0 ." (RFC 7505 section 3).

A null MX beside other MX records, or at a preference other than 0, read
as a dangling MX with a blank host name and advice to add addresses for it.
"""
DOMAIN = "t.test"


def _mx(audit, mx):
    zone = {
        DOMAIN: {"NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"], "TXT": ["v=spf1 -all"], "MX": mx},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
    }
    result = audit(zone, DOMAIN)
    return next(c for c in result["checks"] if c["name"] == "MX Records")


def _texts(card):
    return [d.get("text", "") for d in card["details"]]


def _no_blank_host(card):
    for t in _texts(card):
        assert "Priority 0:  " not in t and "Priority 10:  " not in t, t
        assert "''" not in t, t


def test_null_mx_next_to_other_mx_records(audit):
    card = _mx(audit, [(0, "."), (10, f"mail.{DOMAIN}")])
    assert card["status"] == "fail"
    assert card["verdict"] == "Null MX published next to other MX records"
    assert any("must be the only MX record" in t for t in _texts(card)), _texts(card)
    _no_blank_host(card)


def test_null_mx_at_a_nonzero_preference(audit):
    card = _mx(audit, [(10, ".")])
    assert card["status"] == "fail"
    assert "Single MX host" not in card["verdict"]
    assert any("should use preference 0" in t for t in _texts(card)), _texts(card)
    _no_blank_host(card)


def test_the_lone_null_mx_is_still_no_mail_by_design(audit):
    from result_transformer import PILL_NULL_MX
    card = _mx(audit, [(0, ".")])
    assert (card["status"], card["pill_label"]) == ("pass", PILL_NULL_MX)
