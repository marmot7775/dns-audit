"""
Sentry error reports carry a stack trace, not the visitor.

The privacy page says the client IP is never written anywhere. Sentry is
the one place that could quietly break that: its SDK attaches request
headers, stack frame locals and log breadcrumbs to every event, and its
default scrubbing misses CF-Connecting-IP, User-Agent, and this code's own
client_ip locals and "ip=" log lines.

The end-to-end test runs in a subprocess because the FastAPI integration
wraps route handlers when the routes are registered, so Sentry has to be
initialised before server.py builds its app, and a fresh interpreter keeps
that patching out of every other test. A stub transport collects the
events instead of sending them.
"""
import json
import os
import subprocess
import sys
import textwrap

import sentry_sdk

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import server as server_module

REPO = os.path.join(os.path.dirname(__file__), "..")

VISITOR_IP = "203.0.113.77"
VISITOR_UA = "Mozilla/5.0 (X11; Linux x86_64) SentryProbe/9.9"

_SCRIPT = textwrap.dedent(f"""
    import json, sys
    import sentry_sdk
    from sentry_sdk.transport import Transport

    events = []

    class Capture(Transport):
        def capture_envelope(self, envelope):
            for item in envelope.items:
                if item.type == "event":
                    events.append(item.payload.json)

    _real_init = sentry_sdk.init
    sentry_sdk.init = lambda *a, **kw: _real_init(*a, transport=Capture, **kw)

    import server
    from fastapi.testclient import TestClient

    def boom(*args, **kwargs):
        raise RuntimeError("engine exploded")

    server.TRUSTED_PROXY_IPS.add("testclient")
    server._preflight_dns_check = lambda domain: None
    server.run_full_audit = boom

    client = TestClient(server.app)
    r = client.get(
        "/api/audit",
        params={{"domain": "example.com"}},
        headers={{
            "X-Real-IP": "{VISITOR_IP}",
            "CF-Connecting-IP": "{VISITOR_IP}",
            "True-Client-IP": "{VISITOR_IP}",
            "User-Agent": "{VISITOR_UA}",
            "Referer": "https://forum.example.net/private/thread/42",
            "Cookie": "session=abc",
        }},
    )
    sentry_sdk.flush()
    json.dump({{"status": r.status_code, "events": events}}, sys.stdout)
""")


def _run_with_sentry(tmp_path):
    env = dict(os.environ)
    env["SENTRY_DSN"] = "https://publickey@sentry.invalid/1"
    env["LOG_DIR"] = str(tmp_path)
    out = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def test_no_dsn_means_no_sentry(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert server_module._init_sentry() is False
    assert not sentry_sdk.get_client().is_active()


def test_error_event_carries_no_visitor_data(tmp_path):
    result = _run_with_sentry(tmp_path)
    events = result["events"]
    assert events, "the failed audit should have produced a Sentry event"

    event = events[0]
    blob = json.dumps(event)

    # The event is still useful: the exception, the route, the domain.
    assert "engine exploded" in blob
    assert "example.com" in blob

    # And it holds nothing about who asked.
    assert VISITOR_IP not in blob
    assert "SentryProbe" not in blob
    assert "forum.example.net" not in blob
    assert "session=abc" not in blob
    assert "user" not in event
    request = event.get("request", {})
    assert set(request) <= {"method", "url", "query_string"}
    assert not any(
        crumb.get("category") == "dns-auditor"
        for crumb in event.get("breadcrumbs", {}).get("values", [])
    ), "INFO log lines carry the client IP and must not become breadcrumbs"


def test_before_send_keeps_only_method_url_query():
    event = {
        "request": {
            "method": "GET",
            "url": "https://dns-audit.com/api/audit",
            "query_string": "domain=example.com",
            "headers": {"CF-Connecting-IP": VISITOR_IP, "User-Agent": VISITOR_UA},
            "cookies": {"a": "b"},
            "env": {"REMOTE_ADDR": VISITOR_IP},
        },
        "user": {"ip_address": VISITOR_IP},
    }
    out = server_module._sentry_before_send(event, {})
    assert out["request"] == {
        "method": "GET",
        "url": "https://dns-audit.com/api/audit",
        "query_string": "domain=example.com",
    }
    assert "user" not in out
