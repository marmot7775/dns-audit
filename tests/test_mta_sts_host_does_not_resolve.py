"""An MTA-STS policy host with no address is a failure, not a private IP.

cloudflare.com publishes _mta-sts TXT but mta-sts.cloudflare.com has no A or
AAAA record. _resolve_and_validate raised the same ValueError for a name that
does not resolve as for one that resolves to a private address, and
check_mta_sts read every ValueError as the second case: a warning that the
host "resolves to a private/reserved IP" with a fix to point it at a public
one. Senders cannot fetch the policy at all (RFC 8461 section 3.3), so
MTA-STS does not work, the same outcome a 404 already grades as a failure.

The resolution failure is simulated at socket.getaddrinfo, under the real
_safe_fetch, so nothing leaves the machine.
"""
import os
import socket
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeHttpResponse, FakeZone, fake_dns
import checks_extra
from checks_extra import HostResolutionError, _resolve_and_validate
from result_transformer import transform_mta_sts

DOMAIN = "cloudflare.test"
REAL_SAFE_FETCH = checks_extra._safe_fetch


def _zone():
    return FakeZone({
        DOMAIN: {"MX": [(10, f"mx.{DOMAIN}")], "A": ["203.0.113.80"]},
        f"mx.{DOMAIN}": {"A": ["203.0.113.81"]},
        f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20260901"]},
    })


def _gai(errno):
    def _raise(*args, **kwargs):
        raise socket.gaierror(errno, "Name or service not known")
    return _raise


def _run_check(getaddrinfo):
    # fake_dns stubs _safe_fetch; put the real one back so the lookup runs.
    with fake_dns(_zone()), \
            patch.object(checks_extra, "_safe_fetch", REAL_SAFE_FETCH), \
            patch("checks_extra.socket.getaddrinfo", getaddrinfo):
        return checks_extra.check_mta_sts(DOMAIN)


def test_unresolvable_host_is_a_failure_with_an_accurate_fix():
    raw = _run_check(_gai(socket.EAI_NONAME))

    assert raw["status"] == "error"
    titles = [i["issue"] for i in raw["issues"]]
    assert f"mta-sts.{DOMAIN} does not resolve" in titles, titles
    assert not any("private" in t for t in titles), titles

    card = transform_mta_sts(raw, DOMAIN)
    assert card["status"] == "fail"
    text = " ".join(d["text"] for d in card["details"])
    assert f"mta-sts.{DOMAIN} does not resolve, so senders cannot fetch the policy." in text
    assert card["fix"] == (
        f"Publish an A or AAAA record for mta-sts.{DOMAIN} pointing at the "
        "server that serves /.well-known/mta-sts.txt."
    )
    assert "public IP" not in card["fix"]


def test_coverage_counts_it_the_same_as_a_missing_policy_file():
    """A 404 is the existing failure for "the policy cannot be fetched".
    The unresolvable host must score no better on protocol coverage."""
    unresolvable = transform_mta_sts(_run_check(_gai(socket.EAI_NONAME)), DOMAIN)
    with fake_dns(_zone()), patch.object(
            checks_extra, "_safe_fetch",
            return_value=FakeHttpResponse("not found", status_code=404)):
        missing_file = transform_mta_sts(checks_extra.check_mta_sts(DOMAIN), DOMAIN)

    assert missing_file["status"] == unresolvable["status"] == "fail"
    assert unresolvable["configured"] == missing_file["configured"]


def test_private_address_keeps_its_own_finding():
    def _private(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]

    raw = _run_check(_private)
    titles = [i["issue"] for i in raw["issues"]]
    assert titles == ["MTA-STS host resolves to a private/reserved IP"]
    assert raw["status"] == "warning"


def test_a_lookup_that_did_not_complete_is_not_called_missing():
    raw = _run_check(_gai(socket.EAI_AGAIN))
    titles = [i["issue"] for i in raw["issues"]]
    assert titles == [f"Could not resolve mta-sts.{DOMAIN}"]
    assert raw["status"] == "warning"
    assert not any("does not resolve" in t for t in titles)


@pytest.mark.parametrize("errno, transient", [
    (socket.EAI_NONAME, False),
    (socket.EAI_AGAIN, True),
])
def test_resolve_and_validate_says_which_failure_it_was(errno, transient):
    with patch("checks_extra.socket.getaddrinfo", side_effect=_gai(errno)):
        with pytest.raises(HostResolutionError) as exc:
            _resolve_and_validate("mta-sts.example.test")
    assert exc.value.transient is transient


def test_blocked_address_is_not_a_resolution_error():
    def _private(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 443))]

    with patch("checks_extra.socket.getaddrinfo", side_effect=_private):
        with pytest.raises(ValueError) as exc:
            _resolve_and_validate("mta-sts.example.test")
    assert not isinstance(exc.value, HostResolutionError)
