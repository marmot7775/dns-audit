"""Certificate Transparency falls back to Cert Spotter (2026-10-25).

crt.sh often times out. When it does not answer, the check asks SSLMate's
Cert Spotter for the same certificates, dedupes them by certificate, and
the card names the source. Only when both fail is the card Not checked.
"""
import os
import sys
from unittest.mock import patch

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine
import result_transformer

D = "doc44.test"

SPOTTER = [
    {"cert_sha256": "aa", "dns_names": [f"*.{D}", D],
     "issuer": {"name": "C=US, O=Google Trust Services, CN=WE1"},
     "not_before": "2026-08-07T13:51:05Z", "not_after": "2099-11-05T14:49:30Z"},
    {"cert_sha256": "aa", "dns_names": [f"*.{D}", D],
     "issuer": {"name": "C=US, O=Google Trust Services, CN=WE1"},
     "not_before": "2026-08-07T13:51:05Z", "not_after": "2099-11-05T14:49:30Z"},
    {"cert_sha256": "bb", "dns_names": [f"mail.{D}"],
     "issuer": {"name": "C=US, O=Let's Encrypt, CN=R11"},
     "not_before": "2026-09-01T00:00:00Z", "not_after": "2099-12-01T00:00:00Z"},
]


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.content = b"x"
        self.text = "x"

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(str(self.status_code))


@pytest.fixture(autouse=True)
def _no_cache():
    audit_engine._ct_cache.clear()
    audit_engine._ct_timeout_cache.clear()
    yield
    audit_engine._ct_cache.clear()
    audit_engine._ct_timeout_cache.clear()


def _get(crt, spotter):
    def get(url, *a, **kw):
        if "crt.sh" in url:
            if isinstance(crt, Exception):
                raise crt
            return crt
        if "certspotter" in url:
            if isinstance(spotter, Exception):
                raise spotter
            return spotter
        raise requests.exceptions.ConnectionError("no network")
    return get


def _raw(crt, spotter):
    with patch("requests.get", _get(crt, spotter)):
        return audit_engine._raw_check_ct_uncached(D, {})


def test_a_crt_sh_timeout_falls_back_to_cert_spotter():
    raw = _raw(requests.exceptions.Timeout(), _Resp(200, SPOTTER))
    assert raw["source"] == "Cert Spotter"
    # Two rows for one certificate count once.
    assert raw["total_certs"] == 2
    card = result_transformer.transform_ct(raw, D)
    assert card["status"] == "pass"
    assert "Source: Cert Spotter." in card["explanation"]


def test_crt_sh_answering_is_named_as_the_source():
    rows = [{"serial_number": "1", "issuer_name": "CN=R11", "common_name": D, "name_value": D,
             "not_before": "2026-09-01T00:00:00", "not_after": "2099-12-01T00:00:00"}]
    raw = _raw(_Resp(200, rows), requests.exceptions.ConnectionError())
    assert raw["source"] == "crt.sh"
    assert "Source: crt.sh." in result_transformer.transform_ct(raw, D)["explanation"]


@pytest.mark.parametrize("spotter", [_Resp(429, {}), requests.exceptions.Timeout(), _Resp(200, {"no": "list"})])
def test_both_failing_is_not_checked(spotter):
    raw = _raw(requests.exceptions.Timeout(), spotter)
    card = result_transformer.transform_ct(raw, D)
    assert card["status"] == "unavailable"
    assert "Cert Spotter" in card["explanation"]


def test_the_card_no_longer_claims_every_certificate():
    raw = _raw(requests.exceptions.Timeout(), _Resp(200, SPOTTER))
    text = result_transformer.transform_ct(raw, D)["explanation"]
    assert "record of all certificates" not in text
    assert "except names hidden behind a wildcard" in text
    assert "private certificate authority never appear" in text
