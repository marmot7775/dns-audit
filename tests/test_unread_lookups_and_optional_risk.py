"""Lookups that did not complete, reported as findings, and an optional
protocol named as the biggest risk.

A failed lookup is not a finding (docs/decisions/2026-09-02):
- A SERVFAIL on a nameserver's address read as "does not resolve (lame
  delegation)", a red Nameservers card and a plan row to remove it.
- DANE said "no TLSA records found" when every TLSA query had failed.
- "MTA-STS configured without TLS-RPT" fired when the TLS-RPT lookup
  failed, and "BIMI without DMARC enforcement" when the DMARC lookup did.

An optional protocol that is not set up is never a warning (CLAUDE.md), but
the executive summary picked "Configure MTA-STS" as the biggest risk of a
clean domain, which PDF page 1 printed with a green tick.
"""
from anomaly_detector import detect_anomalies
from conftest import FakeZone

D = "clean.example"
RUA = f"rua=mailto:dmarc@{D}"


def _records():
    return {
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "MX": [(10, f"mx1.{D}")],
            "TXT": ["v=spf1 mx -all"]},
        f"ns1.{D}": {"A": ["192.0.2.1"]},
        f"ns2.{D}": {"A": ["198.51.100.1"]},
        f"mx1.{D}": {"A": ["203.0.113.11"]},
        f"_dmarc.{D}": {"TXT": [f"v=DMARC1; p=reject; sp=reject; np=reject; {RUA}"]},
    }


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def test_a_failed_nameserver_address_lookup_is_not_lame_delegation(audit):
    zone = FakeZone(_records()).fail(f"ns1.{D}", "A").fail(f"ns1.{D}", "AAAA")
    card = _card(audit(zone, D, scope="complete"), "Nameservers")
    texts = " ".join(d["text"] for d in card["details"])
    assert "lame delegation" not in texts, texts
    assert card["status"] != "fail"


def test_a_nameserver_with_no_address_is_still_lame(audit):
    zone = FakeZone(_records())
    zone._records.pop((f"ns1.{D}", "A"))
    card = _card(audit(zone, D, scope="complete"), "Nameservers")
    assert card["status"] == "fail"
    assert any("lame delegation" in d["text"] for d in card["details"])


def test_dane_is_unavailable_when_every_tlsa_query_failed(audit):
    zone = FakeZone(_records()).fail(f"_25._tcp.mx1.{D}", "TLSA")
    card = _card(audit(zone, D, scope="complete"), "DANE")
    assert card["status"] == "unavailable", (card["status"], card.get("verdict"))


def test_dane_with_no_tlsa_is_still_absent(audit):
    card = _card(audit(FakeZone(_records()), D, scope="complete"), "DANE")
    assert card["status"] == "absent"


def test_an_unread_tls_rpt_does_not_raise_the_mta_sts_anomaly():
    raw = {"mta_sts": {"txt_record": "v=STSv1; id=1"},
           "tls_rpt": {"status": "unavailable", "record": None}}
    assert not [a for a in detect_anomalies(raw, has_mx=True)
                if "TLS-RPT" in a["title"]]
    raw["tls_rpt"] = {"record": None}
    assert [a for a in detect_anomalies(raw, has_mx=True) if "TLS-RPT" in a["title"]]


def test_an_unread_dmarc_does_not_raise_the_bimi_anomaly():
    raw = {"bimi": {"record": "v=BIMI1; l=https://example.com/l.svg"},
           "dmarc": {"status": "unavailable", "record": None, "policy": None}}
    assert not [a for a in detect_anomalies(raw, has_mx=True) if "BIMI" in a["title"]]
    raw["dmarc"] = {"record": "v=DMARC1; p=none", "policy": "none"}
    assert [a for a in detect_anomalies(raw, has_mx=True) if "BIMI" in a["title"]]


def test_an_optional_protocol_is_not_the_biggest_risk(audit):
    result = audit(FakeZone(_records()), D, scope="complete")
    es = result["executive_summary"]
    assert "MTA-STS" not in es["biggest_risk"], es["biggest_risk"]
    assert "DANE" not in es["biggest_risk"]
    assert es["biggest_risk_severity"] == "none", es
