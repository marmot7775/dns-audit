"""The shared TLS context is built once and keeps verification intact."""

import ssl
import threading
from unittest import mock

import pytest

import http_tls
from checks_extra import _PinnedHostSSLAdapter


@pytest.fixture(autouse=True)
def _fresh_contexts():
    saved = dict(http_tls._contexts)
    http_tls._contexts.clear()
    yield
    http_tls._contexts.clear()
    http_tls._contexts.update(saved)


def test_context_built_once_per_name():
    with mock.patch("ssl.create_default_context",
                    wraps=ssl.create_default_context) as build:
        a = http_tls.shared_context()
        b = http_tls.shared_context()
        for _ in range(3):
            http_tls.session().close()
    assert a is b
    assert build.call_count == 1


def test_context_built_once_across_threads():
    seen = []
    with mock.patch("ssl.create_default_context",
                    wraps=ssl.create_default_context) as build:
        threads = [threading.Thread(target=lambda: seen.append(http_tls.shared_context()))
                   for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert build.call_count == 1
    assert all(c is seen[0] for c in seen)


def test_default_context_verifies():
    ctx = http_tls.shared_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.cert_store_stats()["x509_ca"] > 0


def test_pinned_and_default_are_different_objects():
    assert http_tls.shared_context("pinned") is not http_tls.shared_context()


def test_adapter_pool_uses_shared_context():
    adapter = http_tls.SharedContextAdapter()
    assert adapter.poolmanager.connection_pool_kw["ssl_context"] is http_tls.shared_context()
    pinned = _PinnedHostSSLAdapter()
    assert pinned.poolmanager.connection_pool_kw["ssl_context"] is http_tls.shared_context("pinned")


def test_cert_verify_does_not_hand_urllib3_a_bundle_path():
    adapter = http_tls.SharedContextAdapter()
    conn = mock.Mock()
    adapter.cert_verify(conn, "https://example.com/", True, None)
    assert conn.cert_reqs == "CERT_REQUIRED"
    assert conn.ca_certs is None
    assert conn.ca_cert_dir is None


def test_cert_verify_falls_through_for_custom_bundle():
    adapter = http_tls.SharedContextAdapter()
    conn = mock.Mock()
    with mock.patch.object(http_tls.HTTPAdapter, "cert_verify") as base:
        adapter.cert_verify(conn, "https://example.com/", "/tmp/ca.pem", None)
    base.assert_called_once()


def test_pinned_adapter_requires_host_header():
    pinned = _PinnedHostSSLAdapter()
    request = mock.Mock()
    request.headers = {"User-Agent": "x"}
    with pytest.raises(ValueError):
        pinned.send(request)


def test_default_context_not_mutated_by_pinned_use():
    """urllib3 turns check_hostname off on a context used with assert_hostname.
    The pinned adapter must do that to its own context, not the default one."""
    default = http_tls.shared_context()
    pinned = http_tls.shared_context("pinned")
    pinned.check_hostname = False
    assert default.check_hostname is True
