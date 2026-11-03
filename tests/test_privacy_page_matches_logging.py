"""The privacy page and README describe the log and the lookups the code makes.

The page once said every audit writes a log line, including PDF downloads,
when the code wrote none for a PDF download, a cached repeat inside five
minutes, or a domain refused before the checks start. Those paths now write
a line (source pdf, cached true, status refused), and the page says so.
It also once named only Cloudflare and Sentry as third parties, while every
audit sends the domain to public resolvers and to crt.sh or Cert Spotter.

These tests pin the text to the behaviour: change one and the other has to
change with it.
"""
import os
import re

import pytest
from fastapi.testclient import TestClient

from conftest import FakeZone, fake_dns

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = "t.test"
ZONE = {
    DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
             "TXT": ["v=spf1 ip4:192.0.2.1 -all"]},
    f"mail.{DOMAIN}": {"A": ["192.0.2.1"]},
    f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:a@{DOMAIN}"]},
}


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def _privacy_text():
    html = _read("static", "privacy.html")
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


@pytest.fixture
def logged(monkeypatch):
    import server
    calls = []
    monkeypatch.setattr(server, "RATE_LIMIT_MAX", 10_000)
    monkeypatch.setattr(server, "_cache", {})
    monkeypatch.setattr(server, "_log_audit",
                        lambda *a, **k: calls.append(
                            (k.get("source"), k.get("status", "ok"), bool(k.get("cached")))))
    return server, calls


def test_a_pdf_download_writes_a_pdf_line_and_the_page_says_so(logged, monkeypatch):
    server, calls = logged
    monkeypatch.setattr(server, "_preflight_dns_check", lambda d: None)
    with fake_dns(FakeZone(ZONE)):
        resp = TestClient(server.app).get(f"/api/audit/{DOMAIN}/pdf", params={"scope": "dmarc"})
    assert resp.status_code == 200, resp.text[:200]
    assert calls == [("pdf", "ok", False)]
    text = _privacy_text()
    assert "or a PDF download" in text
    assert "A PDF download is not logged" not in text


def test_a_cached_repeat_writes_a_cached_line_and_the_page_says_so(logged, monkeypatch):
    server, calls = logged
    monkeypatch.setattr(server, "_preflight_dns_check", lambda d: None)
    client = TestClient(server.app)
    with fake_dns(FakeZone(ZONE)):
        for _ in range(2):
            assert client.get("/api/audit", params={"domain": DOMAIN, "scope": "dmarc"}).status_code == 200
    assert calls == [("web", "ok", False), ("web", "ok", True)]
    text = _privacy_text()
    assert "within five minutes" in text
    assert "not logged again" not in text


@pytest.mark.parametrize("path", ["/api/audit", "/api/audit/stream"])
def test_a_refused_domain_writes_a_refused_line_and_the_page_says_so(logged, monkeypatch, path):
    server, calls = logged
    monkeypatch.setattr(server, "_preflight_dns_check", lambda d: {
        "domain": d, "checks": [], "error": "domain_not_found", "error_message": "x"})
    TestClient(server.app).get(path, params={"domain": "nx.test"})
    assert [c[1] for c in calls] == ["refused"]
    text = _privacy_text()
    assert "refused before the checks started" in text
    assert "is not logged either" not in text


def test_the_page_names_where_the_audited_domain_is_sent():
    import dns_tools
    text = _privacy_text()
    for name in ("crt.sh", "Cert Spotter", "Sentry"):
        assert name in text, name
    for ip in ("1.1.1.1", "8.8.8.8"):
        assert ip in dns_tools.AUDIT_UPSTREAMS
        assert ip in text, ip


def test_the_readme_outbound_line_names_the_resolvers_and_both_logs():
    readme = _read("README.md")
    line = next(ln for ln in readme.splitlines() if "Outbound traffic is DNS" in ln)
    for name in ("1.1.1.1", "8.8.8.8", "crt.sh", "Cert Spotter"):
        assert name in line, name
