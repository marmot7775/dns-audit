"""Doc 99, report copy part 1: each false or misleading statement, through a
mocked run_full_audit, before and after.

Each test names its doc item. The old wording is asserted absent and the new
wording present in what the audit returns, which is what the page and the
PDF render.
"""
import base64
import io
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pdf_report  # noqa: E402
from conftest import FakeZone  # noqa: E402

D = "copy99.test"


def _key(bits=2048, extra=""):
    if bits >= 1024:
        pub = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    else:
        # cryptography will not generate a key this small; a modulus of the
        # right length is all the size check reads.
        pub = rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 1).public_key()
    spki = pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return f"v=DKIM1; {extra}k=rsa; p=" + base64.b64encode(spki).decode("ascii")


KEY = _key()


def _zone(dmarc=f"v=DMARC1; p=reject; rua=mailto:d@{D}", spf="v=spf1 mx -all",
          mx=True, dkim=KEY, extra=None):
    apex = {"A": ["203.0.113.10"], "NS": [f"ns1.{D}", f"ns2.{D}"]}
    if mx:
        apex["MX"] = [(10, f"mx.{D}")]
    if spf is not None:
        apex["TXT"] = spf if isinstance(spf, list) else [spf]
    records = {
        D: apex,
        f"mx.{D}": {"A": ["203.0.113.11"]},
        f"ns1.{D}": {"A": ["203.0.113.53"]},
        f"ns2.{D}": {"A": ["198.51.100.53"]},
    }
    if dmarc is not None:
        records[f"_dmarc.{D}"] = {"TXT": [dmarc]}
    if dkim is not None:
        records[f"selector1._domainkey.{D}"] = {"TXT": [dkim]}
    records.update(extra or {})
    return FakeZone(records)


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def _text(obj):
    return json.dumps(obj)


# ---------------------------------------------------------------
# Part C
# ---------------------------------------------------------------

def test_c3_ready_verdict_says_fails_authentication(audit):
    es = audit(_zone(), D)["executive_summary"]
    assert "pretends" not in es["verdict"]
    assert es["verdict"].startswith("Receiving mail servers are asked to refuse mail that "
                                    "fails authentication for this domain")


def test_c2_and_c4_name_what_to_do(audit):
    text = _text(audit(_zone(), D))
    assert "The plan" not in text and "the plan below" not in text.lower()


# ---------------------------------------------------------------
# Part D
# ---------------------------------------------------------------

D1 = ("This record has no p= tag. Because it has a report address, receiving mail "
      "servers treat it as p=none. Add p= so the record states its policy.")


def test_d1_missing_p_with_rua_is_advisory_and_not_split(audit):
    result = audit(_zone(dmarc=f"v=DMARC1; rua=mailto:d@{D}"), D)
    card = _card(result, "DMARC")
    text = _text(result)
    assert "ignore the record" not in text and "interop hazard" not in text
    assert "Receiver behavior is split" not in text
    warning = next(w for w in card["tag_breakdown"]["config_warnings"]
                   if w["title"] == "Missing p= tag")
    assert warning["level"] == "advisory"
    assert warning["text"] == D1
    assert card["tag_breakdown"]["health"]["status"] != "misconfigured"
    row = next(i for i in result["security_roadmap"]["items"]
               if i["action"] == "Add a p= tag to the DMARC record")
    assert row["impact"] == D1


def test_d2_no_record_and_p_none_do_not_say_pretends(audit):
    none = audit(_zone(dmarc=f"v=DMARC1; p=none; rua=mailto:d@{D}"), D)
    missing = audit(_zone(dmarc=None), D)
    assert none["executive_summary"]["verdict"] == (
        "Your DMARC policy is p=none, which asks receiving mail servers to take no action "
        "on mail that fails authentication. Each server decides on its own.")
    assert missing["executive_summary"]["verdict"] == (
        "Your domain has no DMARC record, so receiving mail servers get no instruction for "
        "mail that fails authentication.")
    heads = [i.get("plain_head") for i in missing["security_roadmap"]["items"]]
    assert ("Receiving mail servers have no instruction for mail that fails your "
            "authentication checks.") in heads
    assert "pretend" not in _text(none) + _text(missing)


def test_d3_subdomain_row_names_sp(audit):
    result = audit(_zone(dmarc=f"v=DMARC1; p=reject; sp=none; rua=mailto:d@{D}"), D)
    actions = [i["action"] for i in result["security_roadmap"]["items"]]
    assert "Raise the subdomain policy to sp=reject" in actions
    assert not any(a.startswith("Bring the subdomain policy") for a in actions)


def test_d4_reporting_is_not_a_spoofing_route(audit):
    result = audit(_zone(dmarc="v=DMARC1; p=reject; rua=mailto:agg@unrelated-vendor.test"), D)
    surface = _card(result, "DMARC")["attack_surface"]
    assert "spoofed through" not in _text(surface)
    assert surface["overall"]["summary"] == "Some of your DMARC reports are not delivered."


def test_d4_partial_only_does_not_say_exposed(audit):
    result = audit(_zone(dmarc=f"v=DMARC1; p=quarantine; rua=mailto:d@{D}"), D)
    surface = _card(result, "DMARC")["attack_surface"]
    assert surface["overall"]["summary"] == "Some routes are only partly covered."


def test_d5_three_documents(audit):
    text = _text(audit(_zone(), D))
    assert "splits the specification" not in text
    assert ("DMARC is now three documents: RFC 9989 for the core, RFC 9990 for aggregate "
            "reports, and RFC 9991 for failure reports.") in text


def test_d6_unusable_key_does_not_say_a_key_is_published(audit):
    card = _card(audit(_zone(dkim=_key(extra="h=sha1; ")), D), "DKIM")
    assert card["status"] != "pass"
    assert "A DKIM key is published" not in _text(card)
    good = _card(audit(_zone(), D), "DKIM")
    assert good["status"] == "pass"
    assert good["deliverability"].startswith("A DKIM key is published.")


def test_d7_unanchored_zone_gets_no_protection_claim(audit):
    zone = _zone()
    zone.add(D, "DNSKEY", [13])
    card = _card(audit(zone, D), "DNSSEC")
    assert card["status"] in ("warn", "fail"), card["status"]
    assert "cache poisoning" not in card["explanation"]
    assert card["explanation"].startswith("The zone is signed, but resolvers cannot verify "
                                          "it yet, so it gets none of DNSSEC's protection.")


def test_d8_google_validates_by_default():
    import result_transformer
    with open(result_transformer.__file__, encoding="utf-8") as f:
        assert "in DNSSEC mode" not in f.read()


def test_d9_a_key_under_1024_bits_fails_now(audit):
    card = _card(audit(_zone(dkim=_key(512)), D), "DKIM")
    text = _text(card)
    assert "can be factored" not in text
    assert ("Under 1024 bits. Receiving servers must reject signatures from keys this small "
            "(RFC 8301), so this key fails now. Replace it with a 2048-bit key.") in text
    assert "still verifies today" not in text


def _spf_with(n):
    spf = "v=spf1 " + " ".join(f"include:i{i}.{D}" for i in range(n)) + " -all"
    extra = {f"i{i}.{D}": {"TXT": ["v=spf1 ip4:192.0.2.1 -all"]} for i in range(n)}
    return spf, extra


def test_d10_over_the_limit_names_lookups_not_length(audit):
    spf, extra = _spf_with(11)
    result = audit(_zone(spf=spf, extra=extra), D)
    heads = [i.get("plain_head") or "" for i in result["security_roadmap"]["items"]]
    assert not any("too long" in h for h in heads)
    assert any(h.startswith("Your approved sender list needs more DNS lookups than receiving "
                            "servers allow, so some or all of your mail fails this check.")
               for h in heads)


def test_d11_at_ten_lookups_nothing_fails_yet(audit):
    spf, extra = _spf_with(10)
    card = _card(audit(_zone(spf=spf, extra=extra), D), "SPF")
    text = _text(card)
    for old in ("will break SPF for all", "Any addition will cause a PermError",
                "cannot satisfy DMARC alignment", "some or all of your mail fails"):
        assert old not in text, old
    assert ("Your SPF record is at the 10 lookup limit. One more include, a, mx, or exists "
            "will push it over, and receiving servers will return an error instead of a "
            "pass.") in text


def test_d12_no_mx_does_not_mean_no_mail_sent(audit):
    card = _card(audit(_zone(spf=None, mx=False), D), "SPF")
    assert "does not send or receive email" not in card["explanation"]
    assert card["explanation"].startswith(
        "No SPF record found. This domain has no MX records, so it does not receive email. "
        "If it sends none either, publish")


def test_d13_mta_sts_enforce_verdict(audit):
    zone = _zone(extra={f"_mta-sts.{D}": {"TXT": ["v=STSv1; id=20260101000000Z"]}})
    policy = f"version: STSv1\nmode: enforce\nmx: mx.{D}\nmax_age: 604800\n"
    card = _card(audit(zone, D, mta_sts_policy=policy), "MTA-STS")
    assert card["verdict"] == "Enforced: senders that support MTA-STS must use encryption"


def test_d14_tls_rpt_reports_arrive_after(audit):
    card = _card(audit(_zone(), D), "TLS-RPT")
    assert "before they affect delivery" not in card["explanation"]
    assert "you don't hear about encryption failures when other servers deliver to you. " \
           "Senders that support it send a daily report." in card["explanation"]


def test_d15_a_permerror_is_not_always_a_lookup_overflow(audit):
    two = ["v=spf1 mx -all", "v=spf1 a -all"]
    with_dkim = _text(audit(_zone(spf=two), D))
    assert "Fix the SPF error shown on the SPF check to restore the second way to pass DMARC." \
        in with_dkim
    assert "reducing it to 10 or fewer DNS lookups" not in with_dkim


def test_d16_a_missing_ct_result_is_an_incomplete_check(audit):
    # The engine's issue text is replaced by the unavailable card before a
    # visitor sees it, so the card is checked for the gap and the engine
    # source for the corrected sentence.
    card = _card(audit(_zone(), D), "Certificate Transparency")
    assert card["status"] == "unavailable"
    assert "does not affect the audit results" not in _text(card)
    import audit_engine
    with open(audit_engine.__file__, encoding="utf-8") as f:
        src = f.read()
    assert "This does not affect the audit results." not in src
    assert src.count("The certificate log service (crt.sh) didn't respond, so this check is ") == 2


def test_d17_and_d18_pdf_names(audit):
    result = json.loads(json.dumps(audit(_zone(dmarc=f"v=DMARC1; p=none; rua=mailto:d@{D}"), D),
                                   default=str))
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)
    assert "Protocol Coverage figure on the cover" not in text
    assert "Migration path" not in text and "migration steps" not in text
    assert "Path to enforcement" in text


def test_a_record_taller_than_a_page_does_not_break_the_pdf(audit):
    """github.com publishes enough DKIM selectors that its key list, in one
    table cell, was taller than a page: the PDF endpoint returned 500."""
    result = json.loads(json.dumps(audit(_zone(), D), default=str))
    card = _card(result, "DKIM")
    card["record"] = "\n".join(f"sel{i}._domainkey: {KEY}" for i in range(12))
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    text = " ".join((p.extract_text() or "") for p in reader.pages)
    assert "sel0._domainkey" in text and "sel11._domainkey" in text
