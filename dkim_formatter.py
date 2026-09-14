"""
DKIM key strength analysis.

analyze_dkim_key_strength() is the only public function; audit_engine,
result_transformer and spf_intelligence use it to grade a selector's key.
"""

from typing import Dict, Optional, Tuple
import base64
import re

# RFC 8463 section 3: the Ed25519 public key is 32 raw bytes. Some generators
# publish the 44-byte DER SubjectPublicKeyInfo wrapper around it instead.
ED25519_RAW_LEN = 32
ED25519_SPKI_LEN = 44

# The SPKI wrapper is a fixed 12-byte header, so it is checked rather than
# assumed from the length. Any 32 bytes is a well-formed raw Ed25519 point and
# there is nothing further to verify without curve arithmetic, but 44 bytes is
# a structured encoding, and accepting the length alone graded 44 bytes of
# zeroes as a healthy 256-bit key. That is the same defect this branch was
# hardened for once already: a length, like a k= tag, is a claim about what
# follows.
#
#   30 2a                 SEQUENCE, 42 bytes
#      30 05              SEQUENCE, 5 bytes (AlgorithmIdentifier)
#         06 03 2b 65 70  OID 1.3.101.112, id-Ed25519 (RFC 8410 section 3)
#      03 21 00           BIT STRING, 33 bytes, 0 unused
#         <32 key bytes>
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _decode_rsa_key_bits(b64_data: str) -> Optional[int]:
    """Decode an RSA SubjectPublicKeyInfo DER blob and return the modulus bit length.

    Every declared ASN.1 length is checked against the bytes actually
    present. A DER length header is a claim, not a guarantee: a TXT value
    truncated by a DNS provider still carries the original header, so
    trusting mod_len alone reports a 60-character fragment of a 2048-bit key
    as a healthy 2048-bit key while every signature it made fails.
    """
    try:
        raw = base64.b64decode(b64_data)
    except Exception:
        return None

    try:
        if raw[0] != 0x30:
            return None
        idx = 1
        idx, _ = _asn1_length(raw, idx)

        # Skip algorithm identifier SEQUENCE
        if raw[idx] != 0x30:
            return None
        idx += 1
        idx, algo_len = _asn1_length(raw, idx)
        if idx + algo_len > len(raw):
            return None
        idx += algo_len

        # BIT STRING
        if raw[idx] != 0x03:
            return None
        idx += 1
        idx, bs_len = _asn1_length(raw, idx)
        if idx + bs_len > len(raw):
            return None
        idx += 1  # skip unused-bits byte

        # Inner SEQUENCE
        if raw[idx] != 0x30:
            return None
        idx += 1
        idx, seq_len = _asn1_length(raw, idx)
        if idx + seq_len > len(raw):
            return None

        # First INTEGER = modulus
        if raw[idx] != 0x02:
            return None
        idx += 1
        idx, mod_len = _asn1_length(raw, idx)
        if idx + mod_len > len(raw):
            return None

        # Leading zero byte for positive integers
        if raw[idx] == 0x00:
            mod_len -= 1

        if mod_len <= 0:
            return None

        return mod_len * 8
    except (IndexError, ValueError):
        return None


def _asn1_length(data: bytes, idx: int) -> Tuple[int, int]:
    if idx >= len(data):
        raise ValueError("Truncated ASN.1 data")
    b = data[idx]
    if b < 0x80:
        return idx + 1, b
    num_bytes = b & 0x7F
    if idx + 1 + num_bytes > len(data):
        raise ValueError("Truncated ASN.1 length")
    length = int.from_bytes(data[idx + 1: idx + 1 + num_bytes], "big")
    return idx + 1 + num_bytes, length


def _tag_value(dkim_record: str, tag: str) -> Optional[str]:
    """Return a tag's value lowercased, or None when the tag is absent.

    A substring test for "k=ed25519" also matched the string appearing inside
    some other tag's value, e.g. a note tag. Tags are split on ';' and then on
    the first '=', per RFC 6376 section 3.2.
    """
    for part in dkim_record.split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip().lower() == tag:
            return value.strip().lower()
    return None


def _extract_p_tag(dkim_record: str) -> Optional[str]:
    """Return the p= value with all whitespace stripped, or None if absent.

    Split on ';' per RFC 6376 section 3.2. Section 3.6.1 permits folding
    whitespace inside the base64 and long keys are routinely published folded,
    so a regex that stops at the first space silently truncates a valid key and
    it fails to decode.
    """
    for part in dkim_record.split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip() == "p":
            return re.sub(r"\s+", "", value)
    return None


def _is_ed25519(sel: dict, key_analysis: dict) -> bool:
    """Key type from the normalized field, falling back to the k= tag."""
    key_type = sel.get("key_type") or key_analysis.get("key_type") or ""
    if "ed25519" in str(key_type).lower():
        return True
    # Selector dicts assembled elsewhere may carry only the raw record.
    return "k=ed25519" in str(sel.get("record") or "").lower().replace(" ", "")


def analyze_dkim_key_strength(dkim_record: str) -> Dict:
    """
    Analyze DKIM key strength and return security assessment.

    Returns:
        dict with key_type, key_bits, status, warning, reason

    'reason' qualifies a status of 'invalid', which covers three distinct
    conditions: 'no_key' (no p= tag at all), 'revoked' (an empty p=, which is
    the only one that actually means revocation) and 'undecodable' (a p= that
    will not parse as a public key). Callers select their explanation on this
    rather than assuming a revocation.
    """
    result = {
        'key_type': 'Unknown',
        'key_bits': 0,
        'status': 'unknown',
        'warning': None,
        'reason': None
    }

    # Extract public key data first (may be empty). Per RFC 6376 §3.6.1, an
    # empty p= means the key is REVOKED -- this must be checked before the
    # Ed25519 shortcut below, which otherwise returns 'strong' without ever
    # looking at whether the key was revoked.
    key_data = _extract_p_tag(dkim_record)
    if key_data is None:
        result['status'] = 'invalid'
        result['reason'] = 'no_key'
        result['warning'] = 'No public key found'
        return result

    if not key_data:
        result['status'] = 'invalid'
        result['reason'] = 'revoked'
        result['warning'] = 'Empty public key (p=): this key is revoked'
        return result

    # Check Ed25519 (all records have a non-empty p= at this point).
    #
    # The key data is decoded, not assumed. Returning 256 bits on the presence
    # of the k= tag alone graded four bytes of junk as a healthy key, which is
    # the same defect the RSA path was fixed for: a DER length header, or here a
    # k= tag, is a claim about what follows, not a guarantee. RFC 8463 section 3
    # publishes the Ed25519 public key as the 32 raw bytes; some generators
    # publish the 44-byte SPKI wrapper instead, so both are accepted, the
    # wrapper on its actual header rather than on its length.
    if _tag_value(dkim_record, 'k') == 'ed25519':
        result['key_type'] = 'Ed25519'
        try:
            raw_bytes = base64.b64decode(key_data, validate=False)
        except Exception:
            raw_bytes = b''
        if len(raw_bytes) == ED25519_RAW_LEN or (
            len(raw_bytes) == ED25519_SPKI_LEN
            and raw_bytes.startswith(ED25519_SPKI_PREFIX)
        ):
            result['key_bits'] = 256
            result['status'] = 'strong'
            return result
        # A record that says ed25519 but carries RSA key data is a type
        # mismatch, not an odd size.
        rsa_bits = _decode_rsa_key_bits(key_data)
        result['status'] = 'invalid'
        result['reason'] = 'undecodable'
        if rsa_bits:
            result['warning'] = (
                f'Record says k=ed25519 but the key data is a {rsa_bits}-bit RSA key'
            )
        elif len(raw_bytes) == ED25519_SPKI_LEN:
            result['warning'] = (
                'Not a valid Ed25519 public key: 44 bytes, but not the DER '
                'SubjectPublicKeyInfo wrapper for id-Ed25519'
            )
        else:
            result['warning'] = (
                f'Not a valid Ed25519 public key ({len(raw_bytes)} bytes, '
                f'expected {ED25519_RAW_LEN} raw or {ED25519_SPKI_LEN} SPKI)'
            )
        return result

    # RSA (default key type per RFC 6376)
    result['key_type'] = 'RSA'

    # Decode the DER SubjectPublicKeyInfo to get the real modulus bit
    # length. Guessing from base64 string length is unreliable: a real
    # 1024-bit key's SPKI is 216 base64 chars, not ~172.
    key_bits = _decode_rsa_key_bits(key_data)
    if key_bits is None:
        result['status'] = 'invalid'
        result['reason'] = 'undecodable'
        result['warning'] = 'Could not decode RSA public key'
        return result

    result['key_bits'] = key_bits
    if key_bits < 2048:
        result['status'] = 'weak'
        result['warning'] = f'{key_bits}-bit RSA key, upgrade to 2048-bit'
    else:
        result['status'] = 'strong'

    return result
