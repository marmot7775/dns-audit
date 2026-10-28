"""
Usage notes from the sister tools (APRF Report Reader, Email Header Decoder).

Those pages do their work in the browser, so without a note their use was
invisible. A note lands in the audit log beside the audits. It must carry
counts and a result only, never report contents or header text, and a
malformed or oversized note must be refused rather than logged.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import logging

import pytest
from fastapi.testclient import TestClient

import server as server_module

APRF = {"tool": "aprf-reader", "reports": 40, "streams": 2, "warnings": 3, "skipped": 1, "copies": 0,
        "domains": ["Example.com", "*.news.example.com", "not a domain", "example.com"]}


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.entries = []

    def emit(self, record):
        self.entries.append(json.loads(record.getMessage()))


@pytest.fixture
def logged():
    h = _Capture()
    server_module.audit_logger.addHandler(h)
    server_module._usage_hits.clear()
    try:
        yield h.entries
    finally:
        server_module.audit_logger.removeHandler(h)


def _post(client, note, raw=None):
    # The pages send text/plain, which needs no CORS preflight
    return client.post("/api/usage", content=raw if raw is not None else json.dumps(note),
                       headers={"Content-Type": "text/plain", "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0",
                                "Referer": "https://aprf.dns-audit.com/some/path?q=1"})


def test_aprf_note_is_logged_with_counts_and_clean_domains(logged):
    r = _post(TestClient(server_module.app), APRF)
    assert r.status_code == 204
    (e,) = logged
    assert e["source"] == "tool" and e["tool"] == "aprf-reader"
    assert (e["reports"], e["streams"], e["warnings"], e["skipped"], e["copies"]) == (40, 2, 3, 1, 0)
    assert e["domains"] == ["example.com", "news.example.com"]  # lowercased, roll-up star dropped, junk and repeats out
    assert "ref" not in e  # the request's Referer is the tool page itself, so it is not used
    assert len(e["vid"]) == 12 and "Chrome" in e["ua"] and e["bot"] is False


def test_header_note_carries_the_result_only(logged):
    note = {"tool": "header-decoder", "status": "fail", "headers": "Received: from secret.internal", "from": "a@b.com"}
    assert _post(TestClient(server_module.app), note).status_code == 204
    (e,) = logged
    assert e["status"] == "fail" and "headers" not in e and "from" not in e
    assert "secret" not in json.dumps(e)


@pytest.mark.parametrize("note, raw", [
    ({"tool": "something-else"}, None),
    ({"tool": "header-decoder", "status": "maybe"}, None),
    ({**APRF, "reports": -1}, None),
    ({**APRF, "streams": "2"}, None),
    ({**APRF, "domains": "example.com"}, None),
    (None, "not json"),
    (None, json.dumps([APRF])),
    (None, json.dumps({**APRF, "pad": "x" * 5000})),
])
def test_bad_notes_are_refused_and_not_logged(logged, note, raw):
    assert _post(TestClient(server_module.app), note, raw).status_code == 400
    assert logged == []


def test_linking_host_comes_from_the_note(logged):
    client = TestClient(server_module.app)
    _post(client, {**APRF, "ref": "www.LinkedIn.com"})
    _post(client, {**APRF, "ref": "https://evil.example/path?x=1"})
    assert logged[0]["ref"] == "www.linkedin.com" and "ref" not in logged[1]


def test_sample_runs_are_marked(logged):
    _post(TestClient(server_module.app), {**APRF, "sample": True})
    assert logged[0]["sample"] is True


def test_hourly_limit_drops_notes_without_touching_audits(logged, monkeypatch):
    monkeypatch.setattr(server_module, "_USAGE_PER_HOUR", 3)
    client = TestClient(server_module.app)
    codes = [_post(client, APRF).status_code for _ in range(5)]
    assert codes == [204, 204, 204, 429, 429] and len(logged) == 3
    assert server_module._rate_limits.get("testclient") is None  # the audit limiter never saw them
