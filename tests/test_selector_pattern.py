"""The DKIM selector rule follows RFC 6376 section 3.1.

    selector = sub-domain *( "." sub-domain )

"Periods are allowed in selectors and are component separators", with
"march2005.reykjavik" as the RFC's own example. The rule allowed one label
only, so a dotted selector was refused with a 400 that cited RFC 6376 for
the opposite of what it says.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SELECTOR_PATTERN  # noqa: E402


@pytest.mark.parametrize("selector", [
    "s1", "google", "selector1", "k-2", "20230601", "march2005.reykjavik",
    "a.b.c", "x" * 63, ".".join(["y" * 63] * 3),
])
def test_valid_selectors_pass(selector):
    assert SELECTOR_PATTERN.match(selector)


@pytest.mark.parametrize("selector", [
    "", "a..b", ".a", "a.", "a_b", "a b", "<x>", "s1\n", "x" * 64,
    ".".join(["y" * 63] * 4),  # 255 characters, over the 253 a name allows
])
def test_invalid_selectors_fail(selector):
    assert not SELECTOR_PATTERN.match(selector)


def test_server_refusal_names_the_real_rule():
    import server
    client = TestClient(server.app)
    resp = client.get("/api/audit/example.com/pdf", params={"selector": "a_b"})
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "periods between parts" in detail
    assert "alphanumeric and hyphens only" not in detail


def test_a_dotted_selector_finds_its_key(audit):
    from test_dkim_key_record_tags import CLEAN
    zone = {
        "example.com": {"TXT": ["v=spf1 -all"], "MX": [(10, "mx.example.com")]},
        "mx.example.com": {"A": ["203.0.113.10"]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]},
        "march2005.reykjavik._domainkey.example.com": {"TXT": [CLEAN]},
    }
    result = audit(zone, "example.com", scope="dmarc", dkim_selector="march2005.reykjavik")
    dkim = next(c for c in result["checks"] if c["name"] == "DKIM")
    assert dkim["status"] == "pass", dkim["details"]
    assert any(d["text"].startswith("march2005.reykjavik:") for d in dkim["details"])
