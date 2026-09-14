"""Doc 43 item 4: every endpoint that runs an audit gives it a deadline.

/api/audit already passed deadline= into run_full_audit. The SSE stream and
the PDF endpoint did not, so a slow domain requested as a PDF held a
concurrency slot past Cloudflare's 100 second origin timeout, and the stream
only noticed its own cutoff at the audit's next progress callback.
"""
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server as server_module


@pytest.fixture
def calls(monkeypatch):
    recorded = []

    def _fake_audit(domain, dkim_selector=None, scope=None, progress_callback=None,
                    deadline=None):
        recorded.append({"deadline": deadline, "now": time.monotonic()})
        return {"domain": domain, "checks": [], "vendors": []}

    monkeypatch.setattr(server_module, "run_full_audit", _fake_audit)
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda domain: None)
    monkeypatch.setattr(server_module, "_check_rate_limit", lambda ip: True)
    monkeypatch.setattr(server_module, "_active_audits", 0)
    monkeypatch.setattr(server_module, "generate_pdf", lambda data: b"%PDF-1.4 test")
    return recorded


def _assert_deadline(recorded):
    assert len(recorded) == 1, "the handler did not run the audit"
    deadline, now = recorded[0]["deadline"], recorded[0]["now"]
    assert deadline is not None, "run_full_audit was called without a deadline"
    assert now < deadline <= now + server_module.AUDIT_WALL_CLOCK_BUDGET


def test_stream_passes_a_deadline(calls):
    with TestClient(server_module.app) as client:
        resp = client.get("/api/audit/stream",
                          params={"domain": f"deadline-sse-{time.time_ns()}.example.com"})
    assert resp.status_code == 200
    _assert_deadline(calls)


def test_pdf_passes_a_deadline(calls):
    with TestClient(server_module.app) as client:
        resp = client.get(f"/api/audit/deadline-pdf-{time.time_ns()}.example.com/pdf")
    assert resp.status_code == 200
    _assert_deadline(calls)
