"""DKIM key settings that change what a receiver does with a signature.

t=y (RFC 6376 section 3.6.1) lets receivers treat the mail as unsigned.
h= without sha256 limits the key to SHA-1, which RFC 8301 forbids
receivers to accept. Both showed in the key table and graded nothing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import build_security_roadmap, transform_dkim
from test_dkim_discovery_starvation import DKIM_RECORD

P = DKIM_RECORD.split("p=", 1)[1]


def _card(record):
    raw = {"configured": True, "status": "pass", "discovery_method": "blind_loop",
           "tested_count": 86, "issues": [],
           "found_selectors": [{"selector": "s1", "record": record, "vendor": None}]}
    return transform_dkim(raw, "keys.test")


def _items(card):
    return build_security_roadmap([card])["items"]


def test_dkim_key_without_test_mode_or_sha1_passes():
    card = _card(DKIM_RECORD)
    assert card["status"] == "pass"
    assert card["dkim_test_mode"] == [] and card["dkim_sha1_only"] == []


def test_test_mode_is_amber_with_a_medium_row():
    card = _card(f"v=DKIM1; k=rsa; t=y; p={P}")
    assert card["status"] == "warn"
    assert any("t=y" in d["text"] for d in card["details"])
    assert "t=y" in card["fix"]
    [row] = [i for i in _items(card) if "test mode" in i["action"]]
    assert row["priority"] == "medium"


def test_test_mode_among_other_flags():
    assert _card(f"v=DKIM1; k=rsa; t=s:y; p={P}")["status"] == "warn"
    assert _card(f"v=DKIM1; k=rsa; t=s; p={P}")["status"] == "pass"


def test_sha1_only_fails_with_a_critical_row():
    card = _card(f"v=DKIM1; h=sha1; k=rsa; p={P}")
    assert card["status"] == "fail"
    assert "h=sha256" in card["fix"]
    [row] = [i for i in _items(card) if "SHA-256" in i["action"]]
    assert row["priority"] == "critical"


def test_sha256_in_the_list_is_fine():
    assert _card(f"v=DKIM1; h=sha1:sha256; k=rsa; p={P}")["status"] == "pass"
    assert _card(f"v=DKIM1; h=sha256; k=rsa; p={P}")["status"] == "pass"
