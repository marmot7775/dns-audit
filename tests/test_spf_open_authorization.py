"""SPF terms that authorize every sender, wherever they sit in the chain.

RFC 7208 section 5.2: an include matches when the included record evaluates
to pass, and +all (or bare all) always does. A domain whose own record ends
in -all but includes or redirects to a +all record authorizes the whole
internet, and DMARC passes on that aligned SPF pass. The same holds for a
term whose range is every address: ip4:0.0.0.0/0, ip6:::/0, a/0, mx/0.

Section 5.1: terms after the first "all" are never evaluated, so a sender
appended after it is not authorized and must not be listed as if it were.
"""
import pytest

DOMAIN = "t.test"


def _zone(spf, extra=None):
    zone = {
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
                 "TXT": [spf], "A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]},
        f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:a@{DOMAIN}"]},
    }
    zone.update(extra or {})
    return zone


def _spf(result):
    return next(c for c in result["checks"] if c["name"] == "SPF")


def _texts(card):
    return [d.get("text", "") for d in card.get("details", [])]


@pytest.mark.parametrize("spf,extra,culprit", [
    ("v=spf1 include:i0.test -all", {"i0.test": {"TXT": ["v=spf1 +all"]}}, "i0.test"),
    ("v=spf1 include:i0.test -all", {"i0.test": {"TXT": ["v=spf1 all"]}}, "i0.test"),
    ("v=spf1 redirect=i0.test", {"i0.test": {"TXT": ["v=spf1 +all"]}}, "i0.test"),
    ("v=spf1 include:i0.test -all", {"i0.test": {"TXT": ["v=spf1 ip4:0.0.0.0/0 -all"]}}, "i0.test"),
    ("v=spf1 include:i0.test -all",
     {"i0.test": {"TXT": ["v=spf1 include:i1.test -all"]},
      "i1.test": {"TXT": ["v=spf1 +all"]}}, "i1.test"),
])
def test_include_or_redirect_to_an_open_record_fails_the_card(audit, spf, extra, culprit):
    result = audit(_zone(spf, extra), DOMAIN)
    card = _spf(result)
    assert card["status"] == "fail", card["verdict"]
    assert card["verdict"] == "Authorizes the entire internet to send as you"
    assert any(culprit in t for t in _texts(card)), _texts(card)
    # The closing -all does not keep anyone out, so the card must not say so.
    assert not any("servers not listed are not authorized" in t for t in _texts(card))
    assert result["executive_summary"]["headline"] != "Your domain is protected against spoofing."
    assert result["executive_summary"]["spoofing_protection"]["label"] != "Full"


def test_negative_include_of_an_open_record_does_not_authorize_anyone(audit):
    # -include: of a +all record makes everyone fail, which is not an opening.
    result = audit(_zone("v=spf1 ip4:192.0.2.1 -include:i0.test -all",
                         {"i0.test": {"TXT": ["v=spf1 +all"]}}), DOMAIN)
    assert _spf(result)["verdict"] != "Authorizes the entire internet to send as you"


def test_include_ending_in_minus_all_is_not_an_opening(audit):
    result = audit(_zone("v=spf1 include:i0.test -all",
                         {"i0.test": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all +all"]}}), DOMAIN)
    card = _spf(result)
    assert card["status"] == "pass", (card["verdict"], _texts(card))


@pytest.mark.parametrize("spf", [
    "v=spf1 ip4:0.0.0.0/0 -all",
    "v=spf1 ip6:::/0 -all",
    "v=spf1 a/0 -all",
    "v=spf1 mx/0 -all",
    "v=spf1 a//0 -all",
])
def test_a_range_of_every_address_fails_like_plus_all(audit, spf):
    card = _spf(audit(_zone(spf), DOMAIN))
    assert card["status"] == "fail", (spf, card["status"])
    assert card["verdict"] == "Authorizes the entire internet to send as you"
    assert not any("servers not listed are not authorized" in t for t in _texts(card))


@pytest.mark.parametrize("spf", [
    "v=spf1 ip4:0.0.0.0/1 -all",
    "v=spf1 ip4:10.0.0.0/8 -all",
    "v=spf1 ip6:2000::/3 -all",
    "v=spf1 a/4 -all",
])
def test_a_very_wide_range_is_a_warning_not_a_pass(audit, spf):
    card = _spf(audit(_zone(spf), DOMAIN))
    assert card["status"] == "warn", (spf, card["status"])


@pytest.mark.parametrize("spf", [
    "v=spf1 ip4:192.0.2.0/24 -all",
    "v=spf1 ip4:10.0.0.0/16 -all",
    "v=spf1 -ip4:0.0.0.0/0 ip4:192.0.2.1 -all",
])
def test_ordinary_or_negative_ranges_still_pass(audit, spf):
    card = _spf(audit(_zone(spf), DOMAIN))
    assert card["status"] == "pass", (spf, card["status"], _texts(card))


@pytest.mark.parametrize("spf,ignored", [
    ("v=spf1 -all ip4:192.0.2.1", "ip4:192.0.2.1"),
    ("v=spf1 ip4:192.0.2.1 ~all -all", "-all"),
    ("v=spf1 -all include:i0.test", "include:i0.test"),
])
def test_terms_after_all_are_flagged_and_not_counted(audit, spf, ignored):
    card = _spf(audit(_zone(spf, {"i0.test": {"TXT": ["v=spf1 ip4:198.51.100.1 -all"]}}), DOMAIN))
    assert card["status"] == "warn", (spf, card["status"])
    texts = _texts(card)
    assert any("ignored" in t and ignored in t for t in texts), texts
    if spf.startswith("v=spf1 -all"):
        assert not any(t.startswith("Direct IP authorization") for t in texts), texts
        assert not any("include mechanism" in t for t in texts), texts


def test_the_first_all_decides_the_result(audit):
    # ~all comes first, so the record softfails; the later -all is never read.
    card = _spf(audit(_zone("v=spf1 ip4:192.0.2.1 ~all -all"), DOMAIN))
    assert any(t.startswith("~all (softfail)") for t in _texts(card)), _texts(card)


def test_exp_modifier_after_all_is_not_flagged(audit):
    card = _spf(audit(_zone("v=spf1 ip4:192.0.2.1 -all exp=explain.t.test"), DOMAIN))
    assert card["status"] == "pass", _texts(card)
