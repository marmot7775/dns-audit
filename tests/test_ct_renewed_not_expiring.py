"""A certificate that has already been renewed is not expiring.

CT logs keep every certificate ever issued, so the one a renewal replaced
stays listed until it runs out. The CT card flagged it anyway, and with a
30-day window it flagged healthy ACME automation mid-cycle: four of five
domains audited on 2026-10-25 (example.com, redcross.org, uoregon.edu,
mailchimp.com) showed "Expiring" for certificates that had successors.

A certificate now counts as expiring only inside CT_EXPIRING_DAYS and only
when no certificate that expires later covers every one of its names.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import audit_engine
from test_ct_active_cert_validity_window import _FakeResponse, _iso


def _cert(serial, names, not_before, not_after):
    return {
        "serial_number": serial,
        "common_name": names[0],
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "name_value": "\n".join(names),
    }


def _run(certs, monkeypatch):
    monkeypatch.setattr("http_tls.get", lambda *a, **k: _FakeResponse(certs))
    return audit_engine._raw_check_ct_uncached("example.com", {})


def _expiring(result):
    return [c["common_name"] for c in result["expiring_soon"]]


NOW = datetime.now(timezone.utc)
OLD = (NOW - timedelta(days=85), NOW + timedelta(days=5))
NEW = (NOW - timedelta(days=25), NOW + timedelta(days=65))


def test_renewed_certificate_is_not_expiring(monkeypatch):
    result = _run([
        _cert(1, ["example.com", "www.example.com"], *OLD),
        _cert(2, ["example.com", "www.example.com"], *NEW),
    ], monkeypatch)
    assert _expiring(result) == []
    assert result["status"] == "ok"


def test_certificate_without_successor_is_expiring(monkeypatch):
    result = _run([_cert(1, ["example.com"], *OLD)], monkeypatch)
    assert _expiring(result) == ["example.com"]
    assert result["status"] == "warning"


def test_partial_successor_leaves_it_expiring(monkeypatch):
    # The renewal dropped www, so www still runs out in five days.
    result = _run([
        _cert(1, ["example.com", "www.example.com"], *OLD),
        _cert(2, ["example.com"], *NEW),
    ], monkeypatch)
    assert _expiring(result) == ["example.com"]


def test_names_split_across_two_successors_count_as_renewed(monkeypatch):
    result = _run([
        _cert(1, ["example.com", "www.example.com"], *OLD),
        _cert(2, ["example.com"], *NEW),
        _cert(3, ["www.example.com"], *NEW),
    ], monkeypatch)
    assert _expiring(result) == []


def test_wildcard_successor_covers_a_subdomain(monkeypatch):
    result = _run([
        _cert(1, ["app.example.com"], *OLD),
        _cert(2, ["*.example.com"], *NEW),
    ], monkeypatch)
    assert _expiring(result) == []


def test_wildcard_does_not_cover_the_apex_or_two_labels_down(monkeypatch):
    result = _run([
        _cert(1, ["example.com"], *OLD),
        _cert(2, ["a.b.example.com"], *OLD),
        _cert(3, ["*.example.com"], *NEW),
    ], monkeypatch)
    assert sorted(_expiring(result)) == ["a.b.example.com", "example.com"]


def test_scheduled_renewal_not_yet_valid_counts(monkeypatch):
    result = _run([
        _cert(1, ["example.com"], *OLD),
        _cert(2, ["example.com"], NOW + timedelta(days=1), NOW + timedelta(days=91)),
    ], monkeypatch)
    assert _expiring(result) == []


def test_successor_inside_the_window_is_itself_expiring(monkeypatch):
    # The 5-day cert has a successor; the 8-day successor has none.
    result = _run([
        _cert(1, ["example.com"], NOW - timedelta(days=80), NOW + timedelta(days=8)),
        _cert(2, ["example.com"], NOW - timedelta(days=85), NOW + timedelta(days=5)),
    ], monkeypatch)
    assert [c["days_left"] for c in result["expiring_soon"]] == [7]
    assert result["status"] == "warning"


def test_outside_the_window_is_not_expiring(monkeypatch):
    days = audit_engine.CT_EXPIRING_DAYS + 5
    result = _run([
        _cert(1, ["example.com"], NOW - timedelta(days=60), NOW + timedelta(days=days)),
    ], monkeypatch)
    assert _expiring(result) == []


def test_issue_text_names_the_window(monkeypatch):
    result = _run([_cert(1, ["example.com"], *OLD)], monkeypatch)
    text = result["issues"][0]["plain_english"]
    assert f"within {audit_engine.CT_EXPIRING_DAYS} days" in text
    assert "1 active certificate expires" in text


class _PagedResponse(_FakeResponse):
    """A Cert Spotter answer with a next page still to fetch."""

    links = {"next": {"url": "https://api.certspotter.com/v1/issuances?after=1"}}


def _cert_spotter_row(names, not_before, not_after):
    return {
        "cert_sha256": "ab" * 32,
        "dns_names": names,
        "issuer": {"name": "C=US, O=Let's Encrypt, CN=R3"},
        "not_before": _iso(not_before) + "Z",
        "not_after": _iso(not_after) + "Z",
    }


def _run_cert_spotter(response, monkeypatch):
    import requests

    def fake_get(url, *a, **k):
        if "crt.sh" in url:
            raise requests.exceptions.Timeout()
        return response

    monkeypatch.setattr("http_tls.get", fake_get)
    return audit_engine._raw_check_ct_uncached("example.com", {})


def test_partial_cert_spotter_page_makes_no_expiry_claim(monkeypatch):
    rows = [_cert_spotter_row(["old.example.com"], *OLD)]
    result = _run_cert_spotter(_PagedResponse(rows), monkeypatch)
    assert result["source"] == "Cert Spotter"
    assert result["partial"] is True
    assert result["active_certs"] == 1
    assert _expiring(result) == []
    assert result["status"] == "ok"


def test_complete_cert_spotter_answer_still_judges_expiry(monkeypatch):
    rows = [_cert_spotter_row(["old.example.com"], *OLD)]
    result = _run_cert_spotter(_FakeResponse(rows), monkeypatch)
    assert result["partial"] is False
    assert _expiring(result) == ["old.example.com"]


def test_partial_card_says_counts_are_a_floor():
    import result_transformer

    card = result_transformer.transform_ct({
        "total_certs": 100, "active_certs": 100, "partial": True,
        "source": "Cert Spotter", "status": "ok",
        "issuers": [{"name": "R3", "count": 100}],
    }, "example.com")
    assert card["status"] == "pass"
    assert card["pill_label"] == "100+ certs"
    assert card["verdict"].startswith("100+ active certs")
    assert any("expiry was not judged" in d["text"] for d in card["details"])


def test_null_common_name_falls_back_to_the_first_san(monkeypatch):
    # Let's Encrypt's newer profiles omit the CN; crt.sh sends null.
    cert = _cert(1, ["eugene.example.com", "www.eugene.example.com"], *OLD)
    cert["common_name"] = None
    cert["issuer_name"] = None
    result = _run([cert], monkeypatch)
    assert _expiring(result) == ["eugene.example.com"]
    assert result["issuers"] == [{"name": "Unknown", "count": 1}]
