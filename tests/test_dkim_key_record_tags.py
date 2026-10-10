"""DKIM key records the card passed although receivers cannot use them (Doc 94).

Each check reads dkim_formatter.parse_dkim_tags, the one parser for a key
record, which keeps tag order and repeats. The governing text, quoted from
RFC 6376 (rfc-editor.org/rfc/rfc6376.txt):

1. v= other than DKIM1. Section 3.6.1: "If specified, this tag MUST be set
   to "DKIM1" (without the quotes). [...] Records beginning with a "v=" tag
   with any other value MUST be discarded. Note that Verifiers must do a
   string comparison on this value; for example, "DKIM1" is not the same as
   "DKIM1.0"." Card fail, critical row.

2. v= not first. Section 3.6.1: "This tag MUST be the first tag in the
   record." Verifiers differ on what they do with such a record. Card warn,
   medium row.

3. k= other than rsa or ed25519 (ed25519 is RFC 8463). Section 3.6.1:
   "Unrecognized key types MUST be ignored." Section 6.1.2 step 8: "If the
   public-key data is not suitable for use with the algorithm and key types
   defined by the "a=" and "k=" tags in the DKIM-Signature header field, the
   Verifier MUST immediately return PERMFAIL (inappropriate key algorithm)."
   A key nobody can use fails every signature. Card fail, critical row.

4. s= listing neither email nor *. Section 3.6.1: "Verifiers for a given
   service type MUST ignore this record if the appropriate type is not
   listed." A mail verifier ignores the record, so the selector has no key
   for mail. Card fail, critical row.

5. A repeated tag. Section 3.2: "Tags with duplicate names MUST NOT occur
   within a single tag-list; if a tag name does occur more than once, the
   entire tag-list is invalid." Card fail, critical row.

Both discovery paths, the selector sweep and a selector entered by hand,
must grade the same record the same way.
"""
import base64
import io
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pypdf import PdfReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
from conftest import FakeZone
from dkim_formatter import dkim_record_problems, parse_dkim_tags
from result_transformer import build_security_roadmap, transform_dkim

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
P = base64.b64encode(_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)).decode("ascii")
ED25519_P = base64.b64encode(bytes(range(32))).decode("ascii")

CLEAN = f"v=DKIM1; k=rsa; p={P}"


def _card(record, selector="s1"):
    raw = {"configured": True, "status": "pass", "discovery_method": "blind_loop",
           "tested_count": 86, "issues": [],
           "found_selectors": [{"selector": selector, "record": record, "vendor": None}]}
    return transform_dkim(raw, "keys.test")


def _dkim_rows(card):
    return [i for i in build_security_roadmap([card])["items"] if i["protocol"] == "DKIM"]


def _texts(card):
    return " ".join(d["text"] for d in card["details"])


def _key_row(card):
    [key] = card["dkim_deep"]["keys"]
    return key


# ---------------------------------------------------------------
# The parser
# ---------------------------------------------------------------

def test_parser_keeps_order_and_repeats():
    assert parse_dkim_tags("k=rsa; v=DKIM1; k=rsa ;p=AB CD;") == [
        ("k", "rsa"), ("v", "DKIM1"), ("k", "rsa"), ("p", "AB CD")]


# ---------------------------------------------------------------
# The five conditions
# ---------------------------------------------------------------

@pytest.mark.parametrize("version", ["DKIM2", "DKIM1.0", "dkim1"])
def test_wrong_version_fails_with_a_critical_row(version):
    card = _card(f"v={version}; k=rsa; p={P}")
    assert card["status"] == "fail"
    assert f"v={version}" in _texts(card)
    assert "v=DKIM1" in card["fix"]
    [row] = [r for r in _dkim_rows(card) if "v=DKIM1" in r["action"]]
    assert row["priority"] == "critical"
    assert _key_row(card)["rating"] == "red"


def test_version_not_first_is_amber_with_a_medium_row():
    card = _card(f"k=rsa; v=DKIM1; p={P}")
    assert card["status"] == "warn"
    assert "some receivers will reject the key" in _texts(card)
    [row] = [r for r in _dkim_rows(card) if "front" in r["action"]]
    assert row["priority"] == "medium"
    assert "Some receivers will reject it" in row["plain_head"]


@pytest.mark.parametrize("key_type", ["dsa", "ecdsa", "rsa2048"])
def test_unknown_key_type_fails_with_a_critical_row(key_type):
    card = _card(f"v=DKIM1; k={key_type}; p={P}")
    assert card["status"] == "fail"
    assert f"k={key_type} is not a key type receivers know" in _texts(card)
    [row] = [r for r in _dkim_rows(card) if "k=rsa or k=ed25519" in r["action"]]
    assert row["priority"] == "critical"
    key = _key_row(card)
    assert key["rating"] == "red" and key["key_type"] == key_type


@pytest.mark.parametrize("service", ["tlsrpt", "web:other"])
def test_service_type_without_email_fails_with_a_critical_row(service):
    card = _card(f"v=DKIM1; k=rsa; s={service}; p={P}")
    assert card["status"] == "fail"
    assert f"s={service} limits the key to services other than email" in _texts(card)
    assert "s=email" in card["fix"]
    [row] = [r for r in _dkim_rows(card) if "Allow email" in r["action"]]
    assert row["priority"] == "critical"


def test_repeated_tag_fails_with_a_critical_row():
    card = _card(f"v=DKIM1; k=rsa; k=rsa; p={P}")
    assert card["status"] == "fail"
    assert "the k= tag appears more than once" in _texts(card)
    [row] = [r for r in _dkim_rows(card) if "repeated tag" in r["action"]]
    assert row["priority"] == "critical"
    assert _key_row(card)["rotation_status"] == "Replace"
    assert card["dkim_deep"]["has_unusable"]


# ---------------------------------------------------------------
# Records that must still pass
# ---------------------------------------------------------------

def test_dkim_record_with_no_problem_tags_passes():
    card = _card(CLEAN)
    assert card["status"] == "pass"
    assert _dkim_rows(card) == []
    assert _key_row(card)["rating"] == "green"
    assert not card["dkim_deep"]["has_unusable"]
    assert not any(v for v in dkim_record_problems(CLEAN).values())


def test_record_without_a_version_tag_passes():
    # v= is RECOMMENDED, not required; its default is DKIM1.
    assert _card(f"k=rsa; p={P}")["status"] == "pass"


@pytest.mark.parametrize("service", ["email", "*", "email:other", "*:other"])
def test_service_types_that_include_email_pass(service):
    assert _card(f"v=DKIM1; k=rsa; s={service}; p={P}")["status"] == "pass"


def test_valid_ed25519_key_passes():
    card = _card(f"v=DKIM1; k=ed25519; p={ED25519_P}")
    assert card["status"] == "pass"
    assert "256-bit Ed25519 key" in _texts(card)


def test_test_mode_and_a_repeated_tag_are_both_reported():
    card = _card(f"v=DKIM1; k=rsa; t=y; p={P}; t=y")
    assert card["status"] == "fail"
    texts = _texts(card)
    assert "the t= tag appears more than once" in texts
    assert "test mode is on (t=y)" in texts
    actions = [r["action"] for r in _dkim_rows(card)]
    assert any("repeated tag" in a for a in actions)
    assert any("test mode" in a for a in actions)


# ---------------------------------------------------------------
# Both discovery paths
# ---------------------------------------------------------------

DOMAIN = "example.com"
SELECTOR = "google"

PATH_RECORDS = {
    "clean": CLEAN,
    "bad version": f"v=DKIM2; k=rsa; p={P}",
    "version not first": f"k=rsa; v=DKIM1; p={P}",
    "unknown key type": f"v=DKIM1; k=dsa; p={P}",
    "no email service": f"v=DKIM1; k=rsa; s=tlsrpt; p={P}",
    "repeated tag": f"v=DKIM1; k=rsa; k=rsa; p={P}",
}


def _zone(record):
    return FakeZone({
        DOMAIN: {
            "TXT": ["v=spf1 include:_spf.google.com -all"],
            "MX": [(10, "aspmx.l.google.com")],
        },
        "aspmx.l.google.com": {"A": ["203.0.113.10"]},
        "_spf.google.com": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"{SELECTOR}._domainkey.{DOMAIN}": {"TXT": [record]},
    })


def _graded(result):
    card = next(c for c in result["checks"] if c["name"] == "DKIM")
    own = [d["text"] for d in card["details"] if d["text"].startswith(f"{SELECTOR}:")]
    rows = sorted((i["priority"], i["action"]) for i in result["security_roadmap"]["items"]
                  if i["protocol"] == "DKIM")
    return card["status"], own, card["fix"], rows


@pytest.mark.parametrize("label", sorted(PATH_RECORDS))
def test_sweep_and_manual_selector_grade_alike(audit, label):
    record = PATH_RECORDS[label]
    swept = _graded(audit(_zone(record), DOMAIN, scope="dmarc"))
    manual = _graded(audit(_zone(record), DOMAIN, scope="dmarc", dkim_selector=SELECTOR))
    assert swept == manual
    assert swept[0] == {"clean": "pass", "version not first": "warn"}.get(label, "fail")


def test_pdf_carries_the_row_and_the_key_table_verdict(audit):
    result = audit(_zone(PATH_RECORDS["bad version"]), DOMAIN, scope="dmarc",
                   dkim_selector=SELECTOR)
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in
                    PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages)
    assert f"Set v=DKIM1 on DKIM key {SELECTOR}" in text
    assert "names a version receivers do not accept" in text
    assert "Wrong version." in text


def test_wrong_version_out_of_place_still_fails():
    # Section 6.1.2 step 5: "the Verifier MUST ignore keys with a version
    # code ("v=" tag) that they do not implement", wherever the tag sits.
    card = _card(f"k=rsa; v=DKIM2; p={P}")
    assert card["status"] == "fail"
    assert "v=DKIM2" in _texts(card)
