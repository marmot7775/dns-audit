"""
Every audit request writes one log line, including the ones that run no audit.

A PDF download, a cached repeat inside five minutes, a request that joined an
audit already running, and a domain refused before the checks start used to
write nothing, so the usage report never saw a typo and undercounted repeat
domains. Each now writes a line in the existing format: a PDF run says
source "pdf", a refusal says status "refused" with the preflight code, and an
answer that ran no audit says cached: true. The cached flag is present only
when true, so a reader counting audits run keeps its meaning by skipping it.

None of these lines may carry more than an audit line does: no IP, no raw
user agent, no referer path.
"""
import asyncio
import json
import logging
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import server as server_module  # noqa: E402

AUDIT_FIELDS = {"ts", "domain", "scope", "duration_s", "checks", "ua", "bot",
                "source", "status", "vid"}
# Every key an audit line may ever hold. A new path writing anything outside
# this set is a privacy change, not a logging fix.
ALLOWED = AUDIT_FIELDS | {"error", "ref", "aprf", "cached"}
IP = "198.51.100.23"


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.entries = []

    def emit(self, record):
        try:
            self.entries.append(json.loads(record.getMessage()))
        except ValueError:
            pass


@pytest.fixture
def entries(monkeypatch):
    handler = _Capture()
    server_module.audit_logger.addHandler(handler)
    monkeypatch.setattr(server_module, "RATE_LIMIT_MAX", 10_000)
    monkeypatch.setattr(server_module, "_cache", {})
    monkeypatch.setattr(server_module, "_active_audits", 0)
    server_module._rate_limits.clear()
    try:
        yield handler.entries
    finally:
        server_module.audit_logger.removeHandler(handler)


def _ok_audit(domain, dkim_selector=None, scope=None, progress_callback=None, deadline=None):
    return {
        "domain": domain,
        "checks": [{"id": "dmarc"}, {"id": "spf"}],
        "vendors": [],
        "draft_standards": [{"name": "APRF", "aprf_state": "none"}],
    }


def _refuse(code):
    return lambda d: {"domain": d, "checks": [], "error": code, "error_message": "x"}


def _client():
    # A real client address in the scope, so a leak would be visible.
    return TestClient(server_module.app, client=(IP, 50000))


def _assert_same_shape(entry):
    assert AUDIT_FIELDS <= set(entry), entry
    assert set(entry) <= ALLOWED, "a new path logged a field audits never did: %r" % entry
    assert IP not in json.dumps(entry), "the client IP reached the log"


# ------------------------------------------------------------------
# refused domains
# ------------------------------------------------------------------

@pytest.mark.parametrize("code", ["domain_not_found", "dns_broken", "timeout"])
def test_a_refused_domain_on_the_web_form_logs_refused_and_the_code(monkeypatch, entries, code):
    monkeypatch.setattr(server_module, "_preflight_dns_check", _refuse(code))

    body = _client().get("/api/audit", params={"domain": "refused-web.example.com"}).json()

    assert body["error"] == code
    assert "_refused" not in body, "the internal marker reached the client"
    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["source"], entry["status"], entry["error"], entry["checks"]) == ("web", "refused", code, 0)
    assert "cached" not in entry


def test_a_refused_domain_on_the_stream_logs_refused(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", _refuse("domain_not_found"))

    _client().get("/api/audit/stream", params={"domain": "refused-sse.example.com"})

    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["source"], entry["status"], entry["error"]) == ("sse", "refused", "domain_not_found")


def test_a_refused_domain_on_the_pdf_endpoint_logs_refused(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", _refuse("domain_not_found"))

    resp = _client().get("/api/audit/refused-pdf.example.com/pdf")

    assert resp.status_code == 400
    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["source"], entry["status"], entry["error"]) == ("pdf", "refused", "domain_not_found")


# ------------------------------------------------------------------
# PDF runs
# ------------------------------------------------------------------

def test_a_pdf_that_runs_its_own_audit_logs_source_pdf(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    monkeypatch.setattr(server_module, "generate_pdf", lambda data, **k: b"%PDF-1.4")

    resp = _client().get("/api/audit/pdf-run.example.com/pdf")

    assert resp.status_code == 200
    assert len(entries) == 1
    entry = entries[0]
    _assert_same_shape(entry)
    assert (entry["source"], entry["status"], entry["checks"]) == ("pdf", "ok", 2)
    assert entry["aprf"] == "none"
    assert "cached" not in entry


def test_a_pdf_whose_audit_throws_logs_an_error(monkeypatch, entries):
    def _boom(*a, **k):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "run_full_audit", _boom)

    resp = _client().get("/api/audit/pdf-boom.example.com/pdf")

    assert resp.status_code == 500
    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["source"], entry["status"], entry["error"]) == ("pdf", "error", "server_error")


# ------------------------------------------------------------------
# cached repeats
# ------------------------------------------------------------------

@pytest.mark.parametrize("path,source", [("/api/audit", "web"), ("/api/audit/stream", "sse")])
def test_a_cached_repeat_logs_a_cached_line(monkeypatch, entries, path, source):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    client = _client()
    params = {"domain": f"cached-{source}.example.com"}

    client.get(path, params=params)
    client.get(path, params=params)

    assert len(entries) == 2
    first, repeat = entries
    assert "cached" not in first
    _assert_same_shape(repeat)
    assert repeat["cached"] is True
    assert (repeat["source"], repeat["status"], repeat["checks"]) == (source, "ok", 2)
    # An adoption count over aprf counts audits run, not answers served.
    assert "aprf" not in repeat


def test_a_pdf_from_a_cached_audit_logs_pdf_and_cached(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)
    monkeypatch.setattr(server_module, "generate_pdf", lambda data, **k: b"%PDF-1.4")
    client = _client()

    client.get("/api/audit", params={"domain": "cached-pdf.example.com"})
    assert client.get("/api/audit/cached-pdf.example.com/pdf").status_code == 200

    assert [e["source"] for e in entries] == ["web", "pdf"]
    _assert_same_shape(entries[1])
    assert entries[1]["cached"] is True


# ------------------------------------------------------------------
# requests that join an audit in flight
# ------------------------------------------------------------------

def _follower_of(payload):
    def _join(cache_key):
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(payload)
        return fut, False
    return _join


def test_a_request_that_joins_an_audit_in_flight_logs_a_cached_line(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_join_or_lead",
                        _follower_of(_ok_audit("joined.example.com")))

    resp = _client().get("/api/audit", params={"domain": "joined.example.com"})

    assert resp.json()["coalesced"] is True
    entry = entries[-1]
    _assert_same_shape(entry)
    assert entry["cached"] is True
    assert (entry["source"], entry["status"], entry["checks"]) == ("web", "ok", 2)


def test_a_request_that_joins_a_refused_audit_logs_refused(monkeypatch, entries):
    # "timeout" is also the audit's own wall-clock code, so only the leader's
    # marker can say this one was a preflight refusal.
    leader_payload = {**_refuse("timeout")("joined-refused.example.com"), "_refused": True}
    monkeypatch.setattr(server_module, "_join_or_lead", _follower_of(leader_payload))

    body = _client().get("/api/audit", params={"domain": "joined-refused.example.com"}).json()

    assert "_refused" not in body, "the internal marker reached the client"
    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["status"], entry["error"], entry["cached"]) == ("refused", "timeout", True)


def test_a_pdf_that_joins_an_audit_in_flight_logs_pdf_and_cached(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "_join_or_lead",
                        _follower_of(_ok_audit("joined-pdf.example.com")))
    monkeypatch.setattr(server_module, "generate_pdf", lambda data, **k: b"%PDF-1.4")

    assert _client().get("/api/audit/joined-pdf.example.com/pdf").status_code == 200

    entry = entries[-1]
    _assert_same_shape(entry)
    assert (entry["source"], entry["cached"]) == ("pdf", True)


# ------------------------------------------------------------------
# a fresh audit is unchanged
# ------------------------------------------------------------------

def test_a_fresh_audit_line_has_no_cached_field(monkeypatch, entries):
    monkeypatch.setattr(server_module, "_preflight_dns_check", lambda d: None)
    monkeypatch.setattr(server_module, "run_full_audit", _ok_audit)

    _client().get("/api/audit", params={"domain": "fresh.example.com"})

    assert len(entries) == 1
    assert "cached" not in entries[0]
    assert entries[0]["source"] == "web"
