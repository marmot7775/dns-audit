"""An inherited subdomain is judged by the policy that applies to it (Doc 76).

mail.github.com has no DMARC record of its own; github.com publishes
p=quarantine; sp=reject. The DMARC card said "Effective policy: reject", while
the summary, the Attack Surface and the plan used the parent's p= as if it
were the subdomain's, and the plan offered the parent's record for publishing
at _dmarc.mail.github.com, where it would replace the inherited reject with
quarantine (RFC 7489 section 6.6.3: a record at the name itself is used and
the parent is never consulted).
"""

import io
import re

import dns.resolver
from pypdf import PdfReader

from conftest import FakeZone
import pdf_report

ORG = "inheritco.com"
SUB = f"mail.{ORG}"
RUA = f"rua=mailto:dmarc@{ORG}"


def _zone(parent_dmarc, sub_mx=True, sub_spf="v=spf1 mx -all", sub_dmarc=None):
    records = {
        ORG: {"NS": [f"ns1.{ORG}", f"ns2.{ORG}"], "MX": [(10, f"mx1.{ORG}")],
              "TXT": ["v=spf1 mx -all"]},
        f"mx1.{ORG}": {"A": ["203.0.113.11"]},
        f"_dmarc.{ORG}": {"TXT": [parent_dmarc]},
        SUB: {"A": ["203.0.113.10"]},
    }
    if sub_mx:
        records[SUB]["MX"] = [(10, f"mx1.{ORG}")]
    if sub_spf:
        records[SUB]["TXT"] = [sub_spf]
    if sub_dmarc:
        records[f"_dmarc.{SUB}"] = {"TXT": [sub_dmarc]}
    zone = FakeZone(records)
    # The subdomain exists: SOA gets NOERROR with no answer, the way a
    # name below a zone apex answers.
    zone.fail(SUB, "SOA", dns.resolver.NoAnswer())
    return zone


def _card(result, name="DMARC"):
    return next(c for c in result["checks"] if c["name"] == name)


def _dmarc_rows(result):
    return [i for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"]


def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages))


def _direct(result):
    return _card(result)["attack_surface"]["vectors"][0]


def _assert_no_subdomain_host(result, pdf):
    """Nothing offers a record for publishing at the subdomain's own name."""
    for row in _dmarc_rows(result):
        assert row.get("host") != f"_dmarc.{SUB}", row
    deploy = _card(result)["tag_breakdown"]["record_builder"]["deploy"]
    assert deploy["host"] != f"_dmarc.{SUB}"
    assert f"TXT record at _dmarc.{SUB}" not in pdf


def test_parent_quarantine_with_sp_reject_reads_as_reject_everywhere(audit):
    result = audit(_zone(f"v=DMARC1; p=quarantine; sp=reject; pct=100; {RUA}"), SUB)
    card = _card(result)
    assert card["effective_policy"] == "reject"
    assert card["inherited_from"] == ORG

    assert _direct(result)["status"] == "protected"
    assert "quarantine" not in card["attack_surface"]["attacker_path"]

    summary = result["executive_summary"]
    assert "partially blocks" not in summary["verdict"]
    assert summary["spoofing_protection"]["label"] == "Full"
    assert "pct" not in summary["biggest_risk"]

    # The parent's pct is not this name's problem: one short line.
    rows = _dmarc_rows(result)
    assert len(rows) == 1
    assert rows[0]["action"] == f"The policy is inherited from {ORG}, and changes are made there"
    assert not rows[0].get("record")

    deploy = card["tag_breakdown"]["record_builder"]["deploy"]
    assert deploy["host"] == f"_dmarc.{ORG}"
    assert deploy["inherited_policy"] == "reject"

    pdf = _pdf_text(result)
    _assert_no_subdomain_host(result, pdf)
    assert "partially blocks" not in pdf
    assert "Spoofed mail goes to spam" not in pdf
    assert f"inherited from {ORG}, and changes are made there" in pdf


def test_parent_reject_without_sp_reads_as_reject(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}"), SUB)
    assert _card(result)["effective_policy"] == "reject"
    assert _direct(result)["status"] == "protected"
    assert "partially blocks" not in result["executive_summary"]["verdict"]
    _assert_no_subdomain_host(result, _pdf_text(result))


def test_parent_sp_none_reads_as_none_and_the_fix_names_the_parent(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; sp=none; {RUA}"), SUB)
    assert _card(result)["effective_policy"] == "none"
    assert _direct(result)["status"] == "exposed"
    assert "blocked" not in result["executive_summary"]["verdict"]

    sp_row = next(r for r in _dmarc_rows(result)
                  if r["action"] == "Bring the subdomain policy up to p=reject")
    assert sp_row["host"] == f"_dmarc.{ORG}"
    assert "sp=reject" in sp_row["record"]
    assert f"at {ORG}, the organizational domain" in sp_row["host_note"]

    pdf = _pdf_text(result)
    _assert_no_subdomain_host(result, pdf)
    assert f"TXT record at _dmarc.{ORG}" in pdf


def test_subdomain_with_its_own_record_is_unchanged(audit):
    own = f"v=DMARC1; p=quarantine; pct=100; rua=mailto:d@{SUB}"
    result = audit(_zone(f"v=DMARC1; p=reject; sp=reject; {RUA}", sub_dmarc=own), SUB)
    card = _card(result)
    assert card["effective_policy"] == "quarantine"
    assert card["inherited_from"] is None
    assert _direct(result)["status"] == "partial"
    assert card["tag_breakdown"]["record_builder"]["deploy"]["host"] == f"_dmarc.{SUB}"
    rows = _dmarc_rows(result)
    assert rows and all("host" not in r for r in rows)
    assert f"TXT record at _dmarc.{SUB}" in _pdf_text(result)


def test_no_mx_inherited_subdomain_without_spf_gets_one_null_spf_row(audit):
    result = audit(_zone(f"v=DMARC1; p=quarantine; sp=reject; {RUA}",
                         sub_mx=False, sub_spf=None), SUB)
    assert not [a for a in result["anomalies"] if "without SPF" in a["title"]]
    spf_rows = [i for i in result["security_roadmap"]["items"] if i["protocol"] == "SPF"]
    assert len(spf_rows) == 1
    assert "v=spf1 -all" in spf_rows[0]["action"]


def test_strict_spf_alignment_parent_keeps_the_anomaly(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; aspf=s; {RUA}", sub_spf=None), SUB)
    anomaly = next(a for a in result["anomalies"] if "without SPF" in a["title"])
    assert "aspf=s" in anomaly["description"]
    assert "SPF alignment cannot pass" in anomaly["description"]


def test_relaxed_alignment_anomaly_does_not_claim_spf_can_never_pass(audit):
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}", sub_spf=None), SUB)
    anomaly = next(a for a in result["anomalies"] if "without SPF" in a["title"])
    assert "never pass" not in anomaly["description"]
    assert "relaxed alignment accepts" in anomaly["description"]
