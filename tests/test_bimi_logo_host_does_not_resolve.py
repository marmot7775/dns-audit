"""A BIMI logo host with no address is not a private IP.

The cloud bug hunt that found the MTA-STS case (cloudflare.com) noted the
same shape in the BIMI logo fetch: _safe_fetch raises HostResolutionError,
a ValueError, for a name that does not resolve, and check_bimi read every
ValueError as "BIMI logo URL resolves to a private/reserved IP" with a fix
to point the URL at a public server. The logo simply cannot be fetched.

The resolution failure is simulated at socket.getaddrinfo, under the real
_safe_fetch, so nothing leaves the machine.
"""
import os
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns  # noqa: E402
import checks_extra  # noqa: E402

DOMAIN = "logo.test"
LOGO_HOST = "brand.logo.test"
REAL_SAFE_FETCH = checks_extra._safe_fetch


def _zone():
    return FakeZone({
        DOMAIN: {"MX": [(10, f"mx.{DOMAIN}")], "A": ["203.0.113.80"]},
        f"mx.{DOMAIN}": {"A": ["203.0.113.81"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"default._bimi.{DOMAIN}": {"TXT": [f"v=BIMI1; l=https://{LOGO_HOST}/logo.svg"]},
    })


def _run(errno):
    def _raise(*args, **kwargs):
        raise socket.gaierror(errno, "Name or service not known")
    with fake_dns(_zone()), \
            patch.object(checks_extra, "_safe_fetch", REAL_SAFE_FETCH), \
            patch("checks_extra.socket.getaddrinfo", _raise):
        return checks_extra.check_bimi(DOMAIN)


def test_unresolvable_logo_host_says_so():
    titles = [i["issue"] for i in _run(socket.EAI_NONAME)["issues"]]
    assert f"Logo host {LOGO_HOST} does not resolve" in titles, titles
    assert not any("private" in t for t in titles), titles


def test_an_unfinished_lookup_is_not_called_missing():
    titles = [i["issue"] for i in _run(socket.EAI_AGAIN)["issues"]]
    assert f"Could not resolve {LOGO_HOST}" in titles, titles
    assert not any("does not resolve" in t or "private" in t for t in titles), titles
