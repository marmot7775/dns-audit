"""Regression test for Ed25519 DKIM keys being called weak.

The remediation planner that first showed this was removed in Doc 49 (no
reader); the card below is where the key is graded now.

Bug 18: _has_weak_dkim_keys compared every key against `bits <= 1024`, an RSA
modulus threshold. An Ed25519 key is 256 bits, so it matched, and the plan
told the user "your selectors use 1024-bit RSA keys, rotate to 2048-bit"
while the DKIM card in the same report rated that selector pass, 256-bit
Ed25519, green. The comparison now happens only after the key type says RSA.

The mixed case is covered too: skipping Ed25519 must not suppress a genuinely
weak RSA key sitting alongside it.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from dkim_formatter import analyze_dkim_key_strength
from result_transformer import transform_dkim

DOMAIN = "example.com"


def _ed25519_record():
    spki = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=ed25519; p=" + base64.b64encode(spki).decode("ascii")


def _rsa_record(bits):
    spki = rsa.generate_private_key(
        public_exponent=65537, key_size=bits
    ).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode("ascii")


ED25519 = _ed25519_record()
RSA_1024 = _rsa_record(1024)


def _selector(name, record):
    """The shape both discovery paths emit after the bug 17 normalization."""
    analysis = analyze_dkim_key_strength(record)
    return {
        "selector": name,
        "record": record,
        "key_type": analysis["key_type"],
        "key_bits": analysis["key_bits"],
        "vendor": None,
    }


def _raw(*selectors):
    return {"domain": DOMAIN, "found_selectors": list(selectors), "tested_count": 12}


def _card_text(card):
    return " ".join(d.get("text", "") for d in card.get("details", []))


def test_ed25519_selector_produces_no_weak_key_step():
    raw = _raw(_selector("ed", ED25519))
    card = transform_dkim(raw, DOMAIN, has_mx=True)

    # What the card tells the user.
    assert card["status"] == "pass"
    assert "256-bit Ed25519 key" in _card_text(card)
    assert card["dkim_deep"]["keys"][0]["rating"] == "green"


def test_ed25519_alongside_a_weak_rsa_key_still_flags_the_rsa_key():
    raw = _raw(_selector("ed", ED25519), _selector("old", RSA_1024))
    card = transform_dkim(raw, DOMAIN, has_mx=True)

    text = _card_text(card)
    assert "256-bit Ed25519 key" in text
    assert "1024-bit RSA key" in text and "upgrade recommended" in text
    assert card["status"] == "warn"
