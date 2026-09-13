"""Doc 43 item 3: a check that raises must not put its exception text in the
API response.

The errors list used to carry f"{label}: {str(e)}", and str(e) has carried
server filesystem paths before. The response is cached for five minutes, so
one leak is served to everyone who audits the domain in that window. Every
check is made to raise an exception whose message holds a fake path, and the
whole result, serialized the way the API sends it, must not contain it.
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import audit_engine

DOMAIN = "leak.test"
FAKE_PATH = "/home/deployuser/app/secret_module.py"

# The module-level function each check runs, and the fixed string the doc
# names for the four sites it fixed (None where the doc named none).
CHECKS = [
    ("dmarc_tree_walk", "Tree Walk: check failed"),
    ("_raw_check_dmarc", "DMARC: check failed"),
    ("check_mx", "MX: check failed"),
    ("_raw_check_spf", "SPF: check failed"),
    ("check_mta_sts", None),
    ("check_tls_rpt", None),
    ("check_bimi", None),
    ("_raw_check_dnssec", None),
    ("_raw_check_caa", None),
    ("_raw_check_nameservers", None),
    ("_raw_check_dane", None),
    ("smart_dkim_check", None),
    ("_raw_check_ct", None),
]


def _zone():
    return FakeZone({
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 mx -all"],
            "A": ["203.0.113.50"],
            "NS": [f"ns1.{DOMAIN}"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.51"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
    })


@pytest.mark.parametrize("func_name,expected_error", CHECKS, ids=[c[0] for c in CHECKS])
def test_exception_text_never_reaches_the_result(monkeypatch, func_name, expected_error):
    calls = []

    def _raise(*args, **kwargs):
        calls.append(1)
        raise RuntimeError(f"could not open {FAKE_PATH}")

    monkeypatch.setattr(audit_engine, func_name, _raise)
    with fake_dns(_zone()):
        result = audit_engine.run_full_audit(DOMAIN, scope="complete")

    assert calls, f"{func_name} was never called, so this case proves nothing"
    serialized = json.dumps(result, default=str)
    assert FAKE_PATH not in serialized and "secret_module" not in serialized, (
        f"exception text from {func_name} reached the API response"
    )
    for entry in result.get("errors") or []:
        assert re.fullmatch(r"[\w .-]+: (check failed|timed out)", entry), (
            f"errors entry is not a fixed string: {entry!r}"
        )
    if expected_error:
        assert expected_error in (result.get("errors") or [])
