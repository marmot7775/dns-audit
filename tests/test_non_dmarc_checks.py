"""Doc 45: the non-DMARC checks follow their RFCs.

Every case runs a declared zone through run_full_audit and asserts on the
transformed card, the roadmap or the resilience block. DANE validation is
read from the AD flag of each TLSA answer, which FakeZone cannot model, so
item 3 also has a unit test with a fake TLSA answer.
"""
import base64
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import patch

import dns.flags
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import pdf_report
from conftest import FakeZone, fake_dns
from dns_tools import is_spf_record
from result_transformer import transform_dane

D = "doc45.test"
RUA = f"rua=mailto:d@{D}"
ENFORCING = f"v=DMARC1; p=reject; {RUA}"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dkim_public_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


_DKIM_P = _dkim_public_key()
_TWO_MX = [(10, f"mx1.{D}"), (20, f"mx2.{D}")]


def _zone(spf="v=spf1 mx -all", dmarc=ENFORCING, mx=_TWO_MX, dkim=True, extra=None):
    records = {
        D: {"A": ["203.0.113.10"], "NS": [f"ns1.{D}", f"ns2.{D}"]},
        f"ns1.{D}": {"A": ["203.0.113.53"]},
        f"ns2.{D}": {"A": ["198.51.100.53"]},
    }
    if spf:
        records[D]["TXT"] = [spf]
    if mx is not None:
        records[D]["MX"] = mx
        for i, (_, host) in enumerate(mx):
            records.setdefault(host, {"A": [f"203.0.113.{20 + i}"]})
    if dmarc:
        records[f"_dmarc.{D}"] = {"TXT": [dmarc]}
    if dkim:
        records[f"s1._domainkey.{D}"] = {"TXT": ["v=DKIM1; k=rsa; p=" + _DKIM_P]}
    records.update(extra or {})
    return FakeZone(records)


def _run(audit, zone, selector="s1", **kwargs):
    return audit(zone, D, dkim_selector=selector, **kwargs)


def _card(result, name):
    return {c["name"]: c for c in result["checks"]}[name]


def _rows(card, pattern):
    return [d["text"] for d in card["details"] if re.search(pattern, d["text"], re.I)]


# ---------------------------------------------------------------
# Item 1: RFC 7208 section 6 modifiers and the section 4.5 version
# ---------------------------------------------------------------

def test_registered_modifiers_do_not_fail_the_card(audit):
    card = _card(_run(audit, _zone(spf="v=spf1 mx -all ra=postmaster rp=10 rr=all")), "SPF")

    assert card["status"] == "pass", card["details"]
    assert not [d for d in card["details"] if d["type"] == "error"]


def test_an_unknown_modifier_is_information(audit):
    card = _card(_run(audit, _zone(spf="v=spf1 mx -all foo=bar")), "SPF")

    assert card["status"] == "pass"
    rows = [d for d in card["details"] if "RFC 7208 section 6" in d["text"] or "'foo'" in d["text"]]
    assert rows and all(d["type"] == "info" for d in rows), card["details"]


@pytest.mark.parametrize("record,is_spf", [
    ("v=spf1", True), ("v=spf1 -all", True), ("V=SPF1 mx -all", True),
    ("v=spf10 -all", False), ("v=spf1-all", False), ("v=spf2.0/pra -all", False),
])
def test_the_version_section_ends_at_a_space_or_the_end(record, is_spf):
    assert is_spf_record(record) is is_spf


def test_v_spf10_is_not_an_spf_record(audit):
    card = _card(_run(audit, _zone(spf="v=spf10 mx -all")), "SPF")

    assert card["pill_label"] == "Missing", (card["status"], card["pill_label"])


# ---------------------------------------------------------------
# Item 2: each SPF finding once
# ---------------------------------------------------------------

def _includes(n):
    spf = "v=spf1 " + " ".join(f"include:i{k}.{D}" for k in range(n)) + " -all"
    extra = {f"i{k}.{D}": {"TXT": ["v=spf1 -all"]} for k in range(n)}
    return spf, extra


def test_ptr_is_reported_once(audit):
    card = _card(_run(audit, _zone(spf="v=spf1 ptr mx -all")), "SPF")

    assert len(_rows(card, r"\bptr\b")) == 1, card["details"]


@pytest.mark.parametrize("n,severity", [(10, "warning"), (11, "error")], ids=["at-10", "over-10"])
def test_the_lookup_limit_is_reported_once(audit, n, severity):
    spf, extra = _includes(n)
    card = _card(_run(audit, _zone(spf=spf, extra=extra)), "SPF")
    rows = [d for d in card["details"] if re.search(r"lookup", d["text"], re.I)]

    assert len(rows) == 1, [d["text"] for d in rows]
    assert rows[0]["type"] == severity


# ---------------------------------------------------------------
# Item 3: DANE judged on the MX host's zone
# ---------------------------------------------------------------

class _Tlsa:
    usage, selector, mtype = 3, 1, 1
    cert = bytes.fromhex("ab" * 32)


def _dane(ad, domain_signed):
    answer = [_Tlsa()]
    response = SimpleNamespace(flags=dns.flags.AD if ad else 0)
    answers = type("_Answer", (list,), {"response": response})(answer)
    resolver = SimpleNamespace(resolve=lambda name, rdtype: answers)
    raw_results = {
        "mx": {"status": "ok", "mx_details": [
            {"hostname": "mx.provider.test", "resolved": True, "provider": ""}]},
        "dnssec": {"has_dnssec": domain_signed, "has_ds": domain_signed, "chain_valid": None},
    }
    with fake_dns(FakeZone({})), \
            patch.object(audit_engine, "_get_dnssec_resolver", return_value=resolver):
        raw = audit_engine._raw_check_dane("hosted.test", raw_results)
    return raw, transform_dane(raw, "hosted.test")


def test_unsigned_domain_on_a_signed_provider_is_protected():
    raw, card = _dane(ad=True, domain_signed=False)
    text = " ".join(d["text"] for d in card["details"])

    assert raw["tlsa_records"][0]["validated"] is True
    assert card["status"] == "pass", card["details"]
    assert card["verdict"] == "DANE-protected (1/1 MX hosts)"
    assert "validates under DNSSEC" in text
    assert "ignore" not in card["explanation"]


def test_signed_domain_on_an_unsigned_mx_zone_is_not_called_valid():
    raw, card = _dane(ad=False, domain_signed=True)
    text = " ".join(d["text"] for d in card["details"])

    assert raw["tlsa_records"][0]["validated"] is False
    assert card["status"] == "warn"
    assert card["verdict"] == "TLSA present but not DNSSEC validated"
    assert "chain of trust is valid" not in text
    assert "not DNSSEC validated" in text


def test_a_mixed_mx_list_is_not_called_provider_hosted(audit):
    zone = _zone(mx=[(10, f"mail.{D}"), (20, "aspmx.l.google.com")])
    card = _card(_run(audit, zone), "DANE")

    assert "Google" not in card["verdict"], card["verdict"]
    assert not _rows(card, "not under this domain's control")


def test_an_all_google_mx_list_still_gets_the_provider_card(audit):
    zone = _zone(mx=[(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")])
    card = _card(_run(audit, zone), "DANE")

    assert card["verdict"] == "DANE is not available on Google Workspace"
    assert card["pill_label"] == "Not applicable"


# ---------------------------------------------------------------
# Item 4: no MX, no transport advice
# ---------------------------------------------------------------

NO_MX_VERDICT = "No MX records, so there is no inbound mail to protect"


def test_a_domain_with_no_mx_gets_no_transport_rows(audit):
    result = _run(audit, _zone(spf=None, mx=[], dkim=False), selector=None)

    for name in ("MTA-STS", "TLS-RPT", "DANE"):
        card = _card(result, name)
        assert (card["status"], card["pill_label"], card["verdict"]) == (
            "absent", "Not applicable", NO_MX_VERDICT), (name, card["pill_label"], card["verdict"])
    protocols = {i["protocol"] for i in result["security_roadmap"]["items"]}
    assert not protocols & {"MTA-STS", "TLS-RPT", "DANE"}, protocols
    assert "encryption" not in result["executive_summary"]["biggest_risk"]


# ---------------------------------------------------------------
# Item 5: CAA tags match regardless of case
# ---------------------------------------------------------------

def test_caa_tags_match_regardless_of_case(audit):
    zone = _zone().add(D, "CAA", [(0, "ISSUE", "letsencrypt.org")])
    with fake_dns(zone):
        raw = audit_engine._raw_check_caa(D)
    card = _card(_run(audit, zone), "CAA")

    assert raw["has_issue"] is True
    assert raw["authorized_cas"] == ["letsencrypt.org"], raw["authorized_cas"]
    assert _rows(card, "letsencrypt.org"), card["details"]


# ---------------------------------------------------------------
# Item 6: parse errors are findings, not "Not checked"
# ---------------------------------------------------------------

_BIMI = {f"default._bimi.{D}": {"TXT": [f"v=BIMI1; l=https://bimi.{D}/logo.svg"]}}
_ENTITY_SVG = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
    '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [\n'
    '  <!ENTITY ns_graphs "http://ns.adobe.com/Graphs/1.0/">\n]>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">'
    '<title>x</title></svg>'
)


def test_a_logo_with_xml_entities_is_a_finding(audit):
    result = _run(audit, _zone(extra=_BIMI), bimi_logo=_ENTITY_SVG)
    card = _card(result, "BIMI")

    assert card["status"] != "unavailable", card
    assert _rows(card, "entity declarations"), card["details"]


def test_an_unparseable_bimi_logo_uri_is_a_finding(audit):
    extra = {f"default._bimi.{D}": {"TXT": ["v=BIMI1; l=https://[bad/logo.svg"]}}
    card = _card(_run(audit, _zone(extra=extra)), "BIMI")

    assert card["status"] != "unavailable" and card.get("pill_label") != "Error", card


def test_an_unparseable_tls_rpt_uri_is_a_finding(audit):
    extra = {f"_smtp._tls.{D}": {"TXT": ["v=TLSRPTv1; rua=https://[bad"]}}
    card = _card(_run(audit, _zone(extra=extra)), "TLS-RPT")

    assert card["status"] == "fail" and card.get("pill_label") != "Error", card


# ---------------------------------------------------------------
# Item 7: unknown fields ignored, first duplicate kept
# ---------------------------------------------------------------

_STS = {f"_mta-sts.{D}": {"TXT": ["v=STSv1; id=20260913"]}}


def _policy(*lines):
    return "\n".join(("version: STSv1",) + lines + (f"mx: mx1.{D}", f"mx: mx2.{D}",
                                                    "max_age: 604800")) + "\n"


def test_an_unknown_mta_sts_field_is_ignored(audit):
    card = _card(_run(audit, _zone(extra=_STS),
                      mta_sts_policy=_policy("mode: enforce", "foo: bar")), "MTA-STS")

    assert card["status"] == "pass", card["details"]


def test_a_duplicate_mta_sts_field_keeps_the_first_value(audit):
    card = _card(_run(audit, _zone(extra=_STS),
                      mta_sts_policy=_policy("mode: enforce", "mode: testing")), "MTA-STS")

    assert card["verdict"] == "Inbound email must use encryption", card["verdict"]
    assert card["status"] == "warn"


def test_an_unknown_tls_rpt_tag_is_ignored(audit):
    extra = {f"_smtp._tls.{D}": {"TXT": [f"v=TLSRPTv1; rua=mailto:t@{D}; foo=bar"]}}
    card = _card(_run(audit, _zone(extra=extra)), "TLS-RPT")

    assert card["status"] == "pass", card["details"]


# ---------------------------------------------------------------
# Item 8: a long DMARC record renders as a PDF
# ---------------------------------------------------------------

def test_a_dmarc_record_with_25_rua_addresses_renders(audit):
    rua = ",".join(f"mailto:reports-{k}@{D}" for k in range(25))
    result = _run(audit, _zone(dmarc=f"v=DMARC1; p=reject; rua={rua}"))

    assert pdf_report.generate_pdf(result)[:5] == b"%PDF-"


# ---------------------------------------------------------------
# Item 9: DKIM counts what it tested; a revoked key is no path
# ---------------------------------------------------------------

def test_a_found_supplied_selector_counts_as_tested(audit):
    card = _card(_run(audit, _zone()), "DKIM")

    assert _rows(card, r"^Tested 1 selector$"), card["details"]


def test_a_revoked_key_is_not_a_working_dkim_path(audit):
    zone = _zone(dkim=False, extra={f"s1._domainkey.{D}": {"TXT": ["v=DKIM1; k=rsa; p="]}})
    result = _run(audit, zone)

    assert result["dmarc_eval"]["dkim_result"] == "none", result["dmarc_eval"]


# ---------------------------------------------------------------
# Item 10: the MX card agrees with itself and RFC 5321
# ---------------------------------------------------------------

def test_no_mx_warning_describes_the_implicit_mx(audit):
    card = _card(_run(audit, _zone(mx=[])), "MX Records")
    text = " ".join(d["text"] for d in card["details"])

    assert "RFC 5321 section 5.1" in text, card["details"]
    assert "Most modern mail servers" not in text


def test_single_mx_explanation_does_not_contradict_the_detail(audit):
    card = _card(_run(audit, _zone(mx=[(10, f"mail.{D}")])), "MX Records")

    assert "fail until it recovers" not in card["explanation"]
    assert _rows(card, "queues at the sending server"), card["details"]


# ---------------------------------------------------------------
# Item 11: the resilience block agrees with the cards
# ---------------------------------------------------------------

def test_no_mail_spf_is_amber_in_the_resilience_block(audit):
    result = _run(audit, _zone(spf=None, mx=[], dkim=False), selector=None)

    assert _card(result, "SPF")["pill_label"] == "No mail"
    assert result["resilience"]["mechanisms"]["spf"]["status"] == "no_mail"
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        assert "info.status === 'no_mail' ? 'warn'" in f.read().replace("\n                    || ", " || ")


def test_inconclusive_dkim_does_not_lower_the_level(audit):
    result = _run(audit, _zone(dkim=False), selector=None)
    res = result["resilience"]

    assert res["mechanisms"]["dkim"]["status"] == "inconclusive"
    assert res["level"] == "high", res["summary"]
