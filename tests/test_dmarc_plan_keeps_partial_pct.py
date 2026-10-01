"""A suggested DMARC record keeps pct below 100 unless the row removes it.

new.org publishes p=quarantine; pct=5. Every proposed record dropped the
tags RFC 9989 retired, so the "purely optional" np row offered a record
without pct. Pasting it raises enforcement from 5% to all failing mail at
RFC 7489 receivers, which the card itself says still honor pct. Same on
illinois.gov (p=reject; sp=none; pct=75) with the sp row. Rows whose purpose
is something else keep pct as published and say so; the row that removes
the retired tags still drops it.
"""
from conftest import FakeZone
from result_transformer import _parse_record_tags


def _run(audit, domain, dmarc):
    zone = FakeZone({
        domain: {"NS": [f"ns1.{domain}", f"ns2.{domain}"], "MX": [(10, f"mx.{domain}")],
                 "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.5"]},
        f"mx.{domain}": {"A": ["203.0.113.6"]},
        f"_dmarc.{domain}": {"TXT": [dmarc]},
    })
    return audit(zone, domain, scope="dmarc")


def _rows(result):
    return {i["action"]: i for i in result["security_roadmap"]["items"]
            if i["protocol"] == "DMARC"}


def test_optional_np_row_keeps_pct_5(audit):
    rows = _rows(_run(audit, "new.test", "v=DMARC1; p=quarantine; pct=5; rua=mailto:d@new.test"))
    np_row = rows["Consider adding an explicit np= tag"]
    tags = _parse_record_tags(np_row["record"])
    assert tags["pct"] == "5", np_row["record"]
    assert tags["np"] == "quarantine"
    assert "pct=5" in np_row["host_note"]

    # The row whose job is removing the retired tags still removes pct.
    removal = rows["Remove the tag RFC 9989 retired: pct"]
    assert "pct" not in _parse_record_tags(removal["record"])
    assert not removal.get("host_note")


def test_sp_row_keeps_pct_75(audit):
    rows = _rows(_run(audit, "illinois.test",
                      "v=DMARC1; p=reject; sp=none; pct=75; rua=mailto:d@illinois.test"))
    sp_row = rows["Bring the subdomain policy up to p=reject"]
    tags = _parse_record_tags(sp_row["record"])
    assert tags["pct"] == "75" and tags["sp"] == "reject", sp_row["record"]
    assert "pct=75" in sp_row["host_note"]


def test_pct_100_is_still_dropped_without_a_note(audit):
    rows = _rows(_run(audit, "full.test", "v=DMARC1; p=reject; pct=100; rua=mailto:d@full.test"))
    np_row = rows["Consider adding an explicit np= tag"]
    assert "pct" not in _parse_record_tags(np_row["record"])
    assert not np_row.get("host_note")
