import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
import dns.exception

import server as server_module

client = TestClient(server_module.app)


def test_health_failure_does_not_leak_resolver_detail(monkeypatch):
    sensitive_detail = "SERVFAIL from resolver 10.0.0.53 port 53"

    def _boom(*args, **kwargs):
        raise dns.exception.DNSException(sensitive_detail)

    monkeypatch.setattr(server_module.dns.resolver, "resolve", _boom)
    monkeypatch.setitem(server_module._health_cache, "expires", 0.0)

    class _BoomResolver:
        lifetime = None

        def resolve(self, *args, **kwargs):
            _boom()

    monkeypatch.setattr(server_module, "get_uncached_resolver", lambda timeout: _BoomResolver())
    monkeypatch.setitem(server_module._negative_probe_cache, "expires", 0.0)

    response = client.get("/api/health")

    assert response.status_code == 500
    body = response.json()
    # The negative probe reports the exception class name, never its message.
    assert body == {
        "status": "error",
        "negative_lookups": "failing",
        "negative_lookups_error": "DNSException",
        "version": server_module.BUILD_SHA,
    }
    assert sensitive_detail not in response.text
