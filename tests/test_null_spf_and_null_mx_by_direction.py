"""Null SPF and null MX each waive one direction of mail, not both.

parkviewdental.com publishes v=spf1 -all and an MX that resolves. Null SPF
was read as "non-mail domain", so MTA-STS, TLS-RPT, BIMI and DKIM all said
"Not applicable (non-mail domain)" while DANE, which keys on MX hosts, said
"Optional, not set up". The domain receives mail, so the inbound
protections apply to it.

SPF (RFC 7208) says who may send as the domain: null SPF means it sends
nothing. Null MX (RFC 7505) means it accepts nothing. The inbound cards
(MTA-STS, TLS-RPT, DANE) follow MX; the outbound cards (DKIM, BIMI) follow
SPF. The defensive_dns flag behind the results banner keeps its meaning,
but it no longer waives inbound cards on a domain whose MX works.
"""
import pytest

from result_transformer import PILL_NOT_APPLICABLE

INBOUND = ("MTA-STS", "TLS-RPT", "DANE")
OUTBOUND = ("DKIM", "BIMI")


def _zone(domain, mx, spf, dmarc=None):
    zone = {domain: {"MX": [mx], "TXT": [spf], "NS": ["ns1.example.net."]}}
    if mx[1] != ".":
        zone[mx[1].rstrip(".")] = {"A": ["192.0.2.25"]}
    if dmarc:
        zone[f"_dmarc.{domain}"] = {"TXT": [dmarc]}
    return zone


def _cards(result):
    return {c["name"]: c for c in result["checks"]}


def _not_applicable(card):
    return card.get("pill_label") == PILL_NOT_APPLICABLE


def _assert_applicable(cards, names):
    for name in names:
        assert not _not_applicable(cards[name]), (
            f"{name} must apply here; got {cards[name].get('verdict')!r}"
        )


def _assert_not_applicable(cards, names):
    for name in names:
        assert _not_applicable(cards[name]), (
            f"{name} must not apply here; got {cards[name].get('pill_label')!r} "
            f"{cards[name].get('verdict')!r}"
        )


@pytest.mark.parametrize("dmarc", [None, "v=DMARC1; p=reject"])
def test_null_spf_with_a_working_mx_keeps_inbound_cards(audit, dmarc):
    domain = "receive-only.example"
    result = audit(_zone(domain, (10, f"mx.{domain}."), "v=spf1 -all", dmarc), domain)
    cards = _cards(result)

    _assert_applicable(cards, INBOUND)
    _assert_not_applicable(cards, OUTBOUND)
    # DANE and MTA-STS answer the same question about the same MX hosts, so
    # they must agree on whether it applies.
    assert cards["DANE"]["pill_label"] == cards["MTA-STS"]["pill_label"]
    # The banner flag is unchanged: null SPF plus p=reject is still a
    # declared defensive setup.
    assert result["defensive_dns"] is bool(dmarc)


def test_null_mx_with_a_sending_spf_keeps_outbound_cards(audit):
    domain = "send-only.example"
    result = audit(
        _zone(domain, (0, "."), "v=spf1 ip4:192.0.2.10 -all",
              "v=DMARC1; p=reject"),
        domain,
    )
    cards = _cards(result)

    _assert_not_applicable(cards, INBOUND)
    _assert_applicable(cards, OUTBOUND)
    assert result["defensive_dns"] is True


def test_null_mx_and_null_spf_waive_both_directions(audit):
    domain = "parked.example"
    result = audit(
        _zone(domain, (0, "."), "v=spf1 -all", "v=DMARC1; p=reject"), domain,
    )
    cards = _cards(result)

    _assert_not_applicable(cards, INBOUND + OUTBOUND)
    assert result["defensive_dns"] is True
