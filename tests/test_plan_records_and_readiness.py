"""Proposed DMARC records drop retired tags, and readiness agrees with the plan (Doc 77).

Three findings from the Doc 75 review:
- the sp, weak-np and optional np plan rows built their records from the
  published record, so after "Remove the tags RFC 9989 retired: pct, ri"
  the next row's record put pct=100 and ri=86400 back;
- a missing rua on an enforcing policy was a critical warning, which made
  readiness "misconfigured" and proton.me read "Action needed" in red;
- readiness said an absent np left "potential gaps" to close while the plan
  said np was optional, although an enforcing fallback leaves no gap
  (RFC 9989 section 4.7: np, then sp, then p).
"""

import io
import pathlib
import re

from pypdf import PdfReader

from conftest import FakeZone
import pdf_report

D = "planrec.com"
ROOT = pathlib.Path(__file__).resolve().parent.parent
RETIRED = re.compile(r"(^|;)\s*(pct|rf|ri)\s*=", re.I)


def _audit(audit, dmarc):
    zone = FakeZone({
        D: {"NS": [f"ns1.{D}", f"ns2.{D}"], "MX": [(10, f"mx.{D}")],
            "TXT": ["v=spf1 mx -all"], "A": ["203.0.113.5"]},
        f"mx.{D}": {"A": ["203.0.113.6"]},
        f"_dmarc.{D}": {"TXT": [dmarc]},
    })
    return audit(zone, D, scope="dmarc")


def _card(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def _pdf_text(result):
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages))


def _proposed_records(result):
    """Every record the report proposes publishing, from the data both the
    page and the PDF render."""
    card = _card(result)
    tb = card["tag_breakdown"]
    out = [i["record"] for i in result["security_roadmap"]["items"] if i.get("record")]
    rb = tb["record_builder"]
    out.append(rb["recommended_record"])
    mig = tb["migration"]
    out += [s["record_after"] for s in mig.get("steps", []) if s.get("record_after")]
    if mig.get("target_record"):
        out.append(mig["target_record"])
    if card["dmarcbis_readiness"].get("suggested_record"):
        out.append(card["dmarcbis_readiness"]["suggested_record"])
    return out


def test_no_proposed_record_carries_a_retired_tag(audit):
    result = _audit(audit, f"v=DMARC1; p=reject; pct=100; ri=86400; rf=afrf; rua=mailto:d@{D}")
    records = _proposed_records(result)
    assert len(records) >= 4
    for rec in records:
        assert not RETIRED.search(rec), rec

    rows = [i["action"] for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"]
    assert "Remove the tags RFC 9989 retired: pct, rf, ri" in rows
    assert "Consider adding an explicit np= tag" in rows

    # Every record in the PDF's "What to do" rows.
    pdf = _pdf_text(result)
    plan_records = re.findall(r"TXT record at _dmarc\.\S+ (v=DMARC1.*?) This is the next edit", pdf)
    assert plan_records
    for rec in plan_records:
        assert not RETIRED.search(rec.replace(" ", "")), rec


def test_sp_and_np_rows_start_from_the_cleaned_record(audit):
    result = _audit(audit, f"v=DMARC1; p=reject; sp=none; np=none; pct=100; rua=mailto:d@{D}")
    rows = {i["action"]: i for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"}
    assert "pct" not in rows["Bring the subdomain policy up to p=reject"]["record"]
    assert "pct" not in rows["Set np=reject to match the domain's policy"]["record"]


def test_enforcing_policy_without_rua_is_amber_not_action_needed(audit):
    result = _audit(audit, "v=DMARC1; p=quarantine; fo=1; aspf=s; adkim=s")
    card = _card(result)
    assert result["executive_summary"]["dmarcbis_readiness"]["label"] != "Action needed"
    assert card["tag_breakdown"]["health"]["status"] != "misconfigured"
    assert card["status"] == "warn"
    assert any(d["type"] == "warning" and "rua" in d["text"] for d in card["details"])
    warning = next(w for w in card["tag_breakdown"]["config_warnings"]
                   if w["title"] == "No aggregate reporting")
    assert warning["level"] == "advisory"
    row = next(i for i in result["security_roadmap"]["items"]
               if i["action"] == "Add aggregate reporting (rua=)")
    assert row["priority"] == "high"


def test_enforcing_np_fallback_is_optional_not_a_gap(audit):
    result = _audit(audit, f"v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@{D}")
    card = _card(result)
    np_item = next(i for i in card["dmarcbis_readiness"]["checklist"] if i["label"].startswith("np"))
    texts = [np_item.get("recommendation") or ""] + [
        w["text"] for w in card["tag_breakdown"]["config_warnings"] if "np" in w.get("tags", [])]
    for text in texts:
        assert "gap" not in text.lower(), text
        assert "consider" not in text.lower(), text
    assert "optional" in np_item["recommendation"]
    assert "sp=reject" in np_item["recommendation"]
    row = next(i for i in result["security_roadmap"]["items"]
               if i["action"] == "Consider adding an explicit np= tag")
    assert "optional" in row["impact"].lower()


def test_p_none_readiness_still_suggests_np(audit):
    result = _audit(audit, f"v=DMARC1; p=none; rua=mailto:d@{D}")
    np_item = next(i for i in _card(result)["dmarcbis_readiness"]["checklist"]
                   if i["label"].startswith("np"))
    assert "consider np=" in np_item["recommendation"]


def test_the_retired_tag_set_is_written_once():
    pattern = re.compile(r"""[\(\[\{]\s*["']pct["']\s*,\s*["']rf["']\s*,\s*["']ri["']\s*[\)\]\}]""")
    hits = []
    for path in ROOT.glob("*.py"):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                hits.append(f"{path.name}:{n}")
    assert len(hits) == 1, hits
