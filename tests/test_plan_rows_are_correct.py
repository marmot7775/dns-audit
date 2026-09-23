"""Doc 64: the plan and the summary above it say true things.

Six corrections, each reproduced on the live site before it was fixed:

  - the deliverability all-clear called a configuration "properly set up"
    whenever the three lookups ran, warn cards included
  - sp= published weaker than p= produced no row, and the np= row told the
    reader subdomains already inherit the enforcing policy
  - the biggest risk printed the top item's impact alone, which for a
    fallback row is the card's verdict ("SPF record configured")
  - the RFC 9989 readiness rows printed a health label as an action
  - a no-mail domain with no rua kept a Warning pill with every detail on
    the card good or info
  - the Record Builder and the Migration Path proposed different records
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone  # noqa: E402
from result_transformer import (  # noqa: E402
    _build_migration_path,
    _build_record_builder,
    build_executive_summary,
    build_security_roadmap,
)

DOMAIN = "plan.test"


def _auth_cards(spf="pass", dkim="pass", dmarc="pass"):
    return [
        {"name": "DMARC", "status": dmarc, "configured": True, "pill_label": "Pass",
         "record": f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"},
        {"name": "SPF", "status": spf, "configured": True, "pill_label": "Pass",
         "record": "v=spf1 mx ~all"},
        {"name": "DKIM", "status": dkim, "configured": True, "pill_label": "Pass"},
    ]


# ---------------------------------------------------------------
# 1. The deliverability line
# ---------------------------------------------------------------

def test_a_warn_card_does_not_get_the_properly_set_up_sentence():
    checks = _auth_cards(spf="warn")
    es = build_executive_summary(checks, build_security_roadmap(checks))
    assert es["deliverability_summary"] == (
        "SPF, DKIM, and DMARC are all in place. The plan below has what to tighten.")
    assert "looks solid" not in es["deliverability_summary"]
    assert "properly set up" not in es["deliverability_summary"]


def test_three_passing_cards_keep_the_all_clear():
    checks = _auth_cards()
    es = build_executive_summary(checks, build_security_roadmap(checks))
    assert es["deliverability_summary"].startswith("Your configuration looks solid.")


# ---------------------------------------------------------------
# 2. sp= weaker than p=
# ---------------------------------------------------------------

def _dmarc_only(record):
    return [{"name": "DMARC", "status": "warn", "configured": True,
             "pill_label": "Warning", "record": record}]


def test_sp_none_under_p_reject_gets_a_high_row_and_no_np_row():
    rows = build_security_roadmap(_dmarc_only("v=DMARC1; p=reject; sp=none"))["items"]
    sp_rows = [i for i in rows if i["action"].startswith("Bring the subdomain policy")]

    assert len(sp_rows) == 1, rows
    assert sp_rows[0]["priority"] == "high"
    assert sp_rows[0]["action"] == "Bring the subdomain policy up to p=reject"
    assert sp_rows[0]["impact"].startswith("sp=none leaves every subdomain unprotected")
    assert not [i for i in rows if "np=" in i["action"]], (
        "the np= note claims subdomains inherit the enforcing policy, which "
        "is what sp=none stops")


def test_sp_quarantine_under_p_reject_does_not_call_subdomains_unprotected():
    rows = build_security_roadmap(_dmarc_only("v=DMARC1; p=reject; sp=quarantine"))["items"]
    row = next(i for i in rows if i["action"].startswith("Bring the subdomain policy"))

    assert row["priority"] == "high"
    assert "unprotected" not in row["impact"]
    assert "quarantined rather than rejected" in row["impact"]


def test_p_reject_with_no_sp_keeps_the_low_np_row():
    rows = build_security_roadmap(_dmarc_only("v=DMARC1; p=reject"))["items"]
    np_rows = [i for i in rows if "np=" in i["action"]]

    assert len(np_rows) == 1 and np_rows[0]["priority"] == "low"
    assert not [i for i in rows if i["action"].startswith("Bring the subdomain policy")]


def test_p_reject_with_sp_reject_gets_no_subdomain_policy_row():
    rows = build_security_roadmap(_dmarc_only("v=DMARC1; p=reject; sp=reject"))["items"]

    assert not [i for i in rows if i["action"].startswith("Bring the subdomain policy")]
    # np is still absent, so its low note keeps its own gate.
    assert [i["priority"] for i in rows if "np=" in i["action"]] == ["low"]


def test_p_reject_with_sp_and_np_set_gets_neither_row():
    rows = build_security_roadmap(
        _dmarc_only("v=DMARC1; p=reject; sp=reject; np=reject"))["items"]

    assert not [i for i in rows if "np=" in i["action"]]
    assert not [i for i in rows if i["action"].startswith("Bring the subdomain policy")]


# ---------------------------------------------------------------
# 3. The biggest risk
# ---------------------------------------------------------------

def test_the_biggest_risk_is_never_a_bare_card_verdict():
    # CAA is a card no roadmap rule words, so its row falls back to the
    # card's own fix text, and the verdict used to become the biggest risk.
    checks = _auth_cards() + [
        {"name": "CAA", "status": "fail", "configured": True,
         "verdict": "CAA records published", "fix": "Repair the <strong>CAA</strong> record."},
    ]
    es = build_executive_summary(checks, build_security_roadmap(checks))

    assert es["biggest_risk"] == "Repair the CAA record."
    assert es["biggest_risk_detail"] == ""
    assert "CAA records published" not in es["biggest_risk"]


def test_the_biggest_risk_leads_with_the_action_and_carries_the_impact():
    checks = _auth_cards(dkim="warn")
    checks[2]["dkim_deep"] = {"has_weak": True, "keys": [
        {"rating": "amber", "bits": 1024, "selector": "s1"}]}
    es = build_executive_summary(checks, build_security_roadmap(checks))

    assert es["biggest_risk"] == "Rotate the weak DKIM key to 2048-bit"
    assert es["biggest_risk_detail"].startswith("This key is below current recommendations")


def test_an_empty_roadmap_keeps_its_own_sentence_and_no_detail():
    checks = _auth_cards()
    checks[0]["record"] = f"v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:d@{DOMAIN}"
    roadmap = build_security_roadmap(checks)
    es = build_executive_summary(checks, roadmap)

    assert roadmap["items"] == []
    assert es["biggest_risk"].startswith("Nothing to fix.")
    assert es["biggest_risk_detail"] == ""


# ---------------------------------------------------------------
# 4. RFC 9989 readiness rows
# ---------------------------------------------------------------

@pytest.mark.parametrize("reasons, action, impact_start", [
    (["Removed tags: pct, ri"], "Remove the tags RFC 9989 retired: pct, ri",
     "Receivers on RFC 9989 ignore them, and pct never gave"),
    (["Removed tags: ri"], "Remove the tag RFC 9989 retired: ri",
     "Receivers on RFC 9989 ignore it."),
    (["Test mode weakens reject"], "Remove t=y so p=reject applies in full",
     "With t=y, RFC 9989 receivers apply quarantine"),
])
def test_a_readiness_row_reads_as_an_instruction(reasons, action, impact_start):
    # The removed-tags row reads the record, so the record carries the tags
    # the reason names, as a real one would.
    removed = [t.strip() for r in reasons if r.startswith("Removed tags:")
               for t in r.split(":", 1)[1].split(",")]
    extra = "".join(f"; {t}=1" for t in removed)
    card = {"name": "DMARC", "status": "warn", "configured": True,
            "record": f"v=DMARC1; p=reject; sp=reject; rua=mailto:d@plan.test{extra}",
            "tag_breakdown": {"health": {"status": "compatible", "reasons": reasons}}}
    rows = [i for i in build_security_roadmap([card])["items"] if i["priority"] == "medium"]

    assert [i["action"] for i in rows] == [action]
    assert rows[0]["impact"].startswith(impact_start)
    assert "not fully RFC 9989-ready" not in rows[0]["impact"]


def test_no_roadmap_row_starts_with_the_address_label():
    card = {"name": "DMARC", "status": "warn", "configured": True,
            "record": "v=DMARC1; p=reject; sp=reject; pct=50; rua=mailto:d@plan.test",
            "tag_breakdown": {"health": {"status": "compatible",
                                         "reasons": ["Removed tags: pct"]}}}
    for item in build_security_roadmap([card])["items"]:
        assert not item["action"].startswith("Address:"), item


# ---------------------------------------------------------------
# 5. A no-mail domain with no rua
# ---------------------------------------------------------------

def _no_mail_zone(record="v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"):
    return FakeZone({
        DOMAIN: {"MX": [(0, ".")], "TXT": ["v=spf1 -all"], "A": [],
                 "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": [record]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    })


def test_a_no_mail_domain_without_rua_passes_and_is_not_counted_as_a_warning(audit):
    result = audit(_no_mail_zone(), DOMAIN)
    card = next(c for c in result["checks"] if c["name"] == "DMARC")

    assert card["status"] == "pass", card["verdict"]
    assert card["pill_label"] != "Warning"
    assert [d["type"] for d in card["details"] if d["type"] in ("error", "warning")] == []
    assert sum(1 for c in result["checks"] if c["status"] == "warn") == 0


def test_a_no_mail_domain_with_a_real_problem_still_warns(audit):
    # Control: the recompute only drops the rua issue, not every issue.
    result = audit(_no_mail_zone("v=DMARC1;p=none"), DOMAIN)
    card = next(c for c in result["checks"] if c["name"] == "DMARC")

    assert card["status"] == "warn"


# ---------------------------------------------------------------
# 6. One end state, two panels
# ---------------------------------------------------------------

RECORDS = [
    "v=DMARC1; p=none; rua=mailto:d@plan.test",
    "v=DMARC1; p=none; pct=50; rua=mailto:d@plan.test",
    "v=DMARC1; p=quarantine; sp=none; adkim=s; aspf=s; rua=mailto:d@plan.test",
    "v=DMARC1; p=reject; sp=none; pct=100; ri=86400; rua=mailto:d@plan.test",
    "v=DMARC1; p=reject; t=y; rua=mailto:d@plan.test; ruf=mailto:f@plan.test",
    "v=DMARC1; p=none",
]


@pytest.mark.parametrize("record", RECORDS)
def test_the_builder_and_the_migration_path_propose_the_same_end_state(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            tags[k.strip().lower()] = v.strip()

    path = _build_migration_path(tags, tags.get("p", ""), "attention", domain=DOMAIN)
    builder = _build_record_builder(tags, tags.get("p", ""), "attention", record, [],
                                    domain=DOMAIN)

    assert path is not None and "target_record" in path
    assert builder["recommended_record"] == path["target_record"], record


@pytest.mark.parametrize("record", RECORDS)
def test_the_end_state_keeps_the_tags_the_record_already_had(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            tags[k.strip().lower()] = v.strip()
    path = _build_migration_path(tags, tags.get("p", ""), "attention", domain=DOMAIN)

    for keep in ("adkim", "aspf", "ruf"):
        if keep in tags:
            assert f"{keep}={tags[keep]}" in path["target_record"], (keep, path["target_record"])
    # And it always enforces, states the subdomain policies, and reports.
    for tag in ("p=reject", "sp=reject", "np=reject", "rua="):
        assert tag in path["target_record"], (tag, path["target_record"])
    for gone in ("pct=", "rf=", "ri=", "t=y"):
        assert gone not in path["target_record"], (gone, path["target_record"])


def test_the_no_record_case_still_starts_at_monitoring():
    builder = _build_record_builder({}, "", "", None, [], domain=DOMAIN)

    assert builder["mode"] == "first_record"
    assert builder["recommended_record"] == f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}"


# ---------------------------------------------------------------
# 7. The PDF reads the same roadmap
# ---------------------------------------------------------------

def test_the_pdf_roadmap_rows_carry_the_reworded_actions(audit):
    import io

    import pdf_report
    from pypdf import PdfReader

    zone = FakeZone({
        DOMAIN: {"MX": [(10, f"m.{DOMAIN}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.1"], "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"]},
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; sp=none; pct=50; "
                                     f"rua=mailto:d@{DOMAIN}"]},
        f"m.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    })
    result = audit(zone, DOMAIN)
    actions = [i["action"] for i in result["security_roadmap"]["items"]]
    assert "Bring the subdomain policy up to p=reject" in actions, actions

    text = "\n".join(p.extract_text() or "" for p in
                     PdfReader(io.BytesIO(pdf_report.generate_pdf(result))).pages)
    text = " ".join(text.split())

    assert "Bring the subdomain policy up to p=reject" in text
    assert "Address:" not in text
    # The biggest-risk callout leads with the action and keeps the impact.
    es = result["executive_summary"]
    assert es["biggest_risk"] in text
    if es["biggest_risk_detail"]:
        assert es["biggest_risk_detail"][:60] in text
