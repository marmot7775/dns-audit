"""Doc 92: results people can read, the backend half.

The frontend, the PDF and the articles are rebuilt around fields this module
pins, so their shape is a contract:

- every card carries plain_name, its plain title with the protocol in
  parentheses, while name stays the id everything keys on;
- every plan row carries plain_head (the consequence in plain words), who
  (the party that makes the change) and optional (an optional protocol not
  set up, which the plan groups under "Optional extras");
- executive_summary.do_first holds at most three rows, in plan order, none
  of them optional or low priority.

It also pins the rest of the backend work: rows within a tier run fail,
then warn, then absent; the rua row has a record to paste; a p=none record
without rua gets the enforcement row; the verdicts and pills use the
approved wording; and an amber DMARC card never sits above a "Misconfigured"
breakdown.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pdf_report
import result_transformer as rt
from result_transformer import build_executive_summary, build_security_roadmap
from test_verdict_names_broken_records import _over_limit_spf, _zone

DOMAIN = "gitlab-shape.test"
RUA = f"rua=mailto:d@{DOMAIN}"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLAIN_NAMES = {
    "DMARC": "Spoofing policy (DMARC)",
    "SPF": "Approved senders (SPF)",
    "DKIM": "Email signatures (DKIM)",
    "MX Records": "Where your mail arrives (MX)",
    "Nameservers": "DNS servers (nameservers)",
    "MTA-STS": "Encryption for incoming mail (MTA-STS)",
    "TLS-RPT": "Encryption failure reports (TLS-RPT)",
    "BIMI": "Logo in inboxes (BIMI)",
    "DNSSEC": "Signed DNS answers (DNSSEC)",
    "CAA": "Who can issue your web certificates (CAA)",
    "DANE": "Mail server certificate check (DANE)",
    "Certificate Transparency": "Certificates issued for your domain (CT logs)",
}
WHO = {"Your DNS host", "Your email provider", "Your email platform",
       "Whoever manages your mail server", "The report receiver"}


def _run(audit, dmarc, spf="v=spf1 mx -all", extra=None):
    return audit(_zone(dmarc, spf, extra=extra), DOMAIN, dkim_selector="s1")


def _items(result):
    return result["security_roadmap"]["items"]


# A spread of domains, so the row rules for each shape are all exercised.
SHAPES = {
    "p=none, no rua": ("v=DMARC1; p=none", "v=spf1 mx -all", None),
    "p=none, rua, pct": (f"v=DMARC1; p=none; pct=50; {RUA}", "v=spf1 mx -all", None),
    "reject, sp=none": (f"v=DMARC1; p=reject; sp=none; {RUA}", "v=spf1 mx -all", None),
    "quarantine, no rua": ("v=DMARC1; p=quarantine", "v=spf1 mx -all", None),
    "reject, ready": (f"v=DMARC1; p=reject; {RUA}", "v=spf1 mx -all", None),
    "over the SPF limit": ((f"v=DMARC1; p=reject; {RUA}",) + _over_limit_spf()),
}


@pytest.fixture(scope="module")
def shape_results():
    import audit_engine
    from conftest import fake_dns
    out = {}
    for label, (dmarc, spf, extra) in SHAPES.items():
        with fake_dns(_zone(dmarc, spf, extra=extra)):
            out[label] = audit_engine.run_full_audit(DOMAIN, dkim_selector="s1")
    return out


# ---------------------------------------------------------------
# The contract fields
# ---------------------------------------------------------------

@pytest.mark.parametrize("label", SHAPES)
def test_every_card_has_its_plain_name_and_keeps_its_name(shape_results, label):
    checks = shape_results[label]["checks"]
    assert {c["name"] for c in checks} == set(PLAIN_NAMES)
    for card in checks:
        assert card["plain_name"] == PLAIN_NAMES[card["name"]], card["name"]


def test_a_stub_card_gets_a_plain_name_too():
    card = rt._lookup_unavailable_card("CAA", {"domain": DOMAIN}, "CAA records")
    rt.attach_what_this_is([card])
    assert card["plain_name"] == "Who can issue your web certificates (CAA)"


@pytest.mark.parametrize("label", SHAPES)
def test_every_plan_row_has_a_plain_head_a_who_and_an_optional_flag(shape_results, label):
    items = _items(shape_results[label])
    assert items, label
    for item in items:
        head = item["plain_head"]
        assert head and head.endswith("."), item
        assert not re.search(r"[–—]| -- ", head), head
        assert item["who"] in WHO, item
        assert item["optional"] is (item["status"] == "absent"), item
        # The instruction is still there, under the head.
        assert item["action"], item


@pytest.mark.parametrize("label", SHAPES)
def test_do_first_is_at_most_three_urgent_rows_in_plan_order(shape_results, label):
    result = shape_results[label]
    do_first = result["executive_summary"]["do_first"]
    urgent = [i for i in _items(result) if not i["optional"] and i["priority"] != "low"]

    assert len(do_first) <= 3
    assert do_first == [{"plain_head": i["plain_head"], "title": i["action"],
                         "priority": i["priority"], "protocol": i["protocol"]}
                        for i in urgent[:3]]


def test_do_first_is_empty_when_only_optional_and_low_rows_remain():
    checks = [
        {"name": "DMARC", "status": "pass", "pill_label": "Pass",
         "record": "v=DMARC1; p=reject; rua=mailto:a@example.com"},
        {"name": "MTA-STS", "status": "absent", "pill_label": rt.PILL_ABSENT},
    ]
    roadmap = build_security_roadmap(checks)
    assert roadmap["items"], "expected the np= row and the MTA-STS row"
    assert [i["optional"] for i in roadmap["items"]
            if i["protocol"] == "MTA-STS"] == [True]

    assert build_executive_summary(checks, roadmap)["do_first"] == []


def test_the_p_none_domain_gets_the_two_actions_the_draft_shows(shape_results):
    do_first = shape_results["p=none, no rua"]["executive_summary"]["do_first"]
    assert [d["plain_head"] for d in do_first[:2]] == [
        "You get no reports on who sends mail as you.",
        "Your settings do not ask receivers to block forged mail yet.",
    ]
    assert [d["title"] for d in do_first[:2]] == [
        "Add aggregate reporting (rua=)", "Progress from p=none to enforcement"]


# ---------------------------------------------------------------
# Step 3: fail before warn before absent within a tier
# ---------------------------------------------------------------

def _medium_tier_checks(ns_serial=False):
    checks = [
        {"name": "MTA-STS", "status": "absent", "pill_label": rt.PILL_ABSENT},
        {"name": "SPF", "status": "warn", "configured": True,
         "record": "v=spf1 include:a.test include:b.test ~all",
         "spf_deep": {"lookup_count": 9}},
        {"name": "TLS-RPT", "status": "fail", "fix": "Fix the rua= address in the TLS-RPT record"},
    ]
    if ns_serial:
        checks.insert(0, {"name": "Nameservers", "status": "warn",
                          "fix": "Check zone transfer configuration",
                          "details": [{"type": "warning",
                                       "text": "SOA serial mismatch across nameservers"}]})
    return checks


def test_within_a_tier_fail_comes_before_warn_before_absent():
    items = build_security_roadmap(_medium_tier_checks())["items"]
    medium = [(i["protocol"], i["status"]) for i in items if i["priority"] == "medium"]
    assert medium == [("TLS-RPT", "fail"), ("SPF", "warn"), ("MTA-STS", "absent")]


def test_the_transient_serial_mismatch_still_sorts_last_in_its_tier():
    items = build_security_roadmap(_medium_tier_checks(ns_serial=True))["items"]
    medium = [i["protocol"] for i in items if i["priority"] == "medium"]
    assert medium == ["TLS-RPT", "SPF", "MTA-STS", "Nameservers"]
    ns = next(i for i in items if i["protocol"] == "Nameservers")
    assert ns["plain_head"].startswith("Your DNS servers gave different versions")


# ---------------------------------------------------------------
# Step 4: the rua record and the p=none row
# ---------------------------------------------------------------

def test_the_rua_row_has_a_record_to_paste(shape_results):
    row = next(i for i in _items(shape_results["p=none, no rua"])
               if i["action"] == "Add aggregate reporting (rua=)")
    assert row["record"] == f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{DOMAIN}"
    assert f"dmarc-reports@{DOMAIN}" in row["host_note"]


def test_the_rua_record_keeps_pct_below_100(audit):
    result = _run(audit, "v=DMARC1; p=quarantine; pct=50")
    row = next(i for i in _items(result) if i["action"] == "Add aggregate reporting (rua=)")
    assert row["record"] == (f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{DOMAIN}; "
                             "pct=50")
    assert "keeps pct=50" in row["host_note"]


def test_the_rua_record_drops_the_tags_rfc_9989_retired(audit):
    result = _run(audit, "v=DMARC1; p=quarantine; ri=86400")
    row = next(i for i in _items(result) if i["action"] == "Add aggregate reporting (rua=)")
    assert "ri=" not in row["record"]
    assert row["record"].endswith(f"rua=mailto:dmarc-reports@{DOMAIN}")


def test_p_none_without_rua_gets_the_enforcement_row(shape_results):
    actions = [i["action"] for i in _items(shape_results["p=none, no rua"])]
    assert actions.count("Progress from p=none to enforcement") == 1


def test_p_none_with_rua_still_gets_exactly_one_enforcement_row(shape_results):
    actions = [i["action"] for i in _items(shape_results["p=none, rua, pct"])]
    assert actions.count("Progress from p=none to enforcement") == 1


def test_an_enforcing_record_without_rua_gets_no_enforcement_row(shape_results):
    actions = [i["action"] for i in _items(shape_results["quarantine, no rua"])]
    assert "Progress from p=none to enforcement" not in actions
    assert "Add aggregate reporting (rua=)" in actions


# ---------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------

def test_p_none_verdict_with_and_without_rua(shape_results):
    expected = ("Your DMARC policy is p=none, which asks receiving mail servers to take no "
                "action on mail that fails authentication. Each server decides on its own.")
    assert shape_results["p=none, no rua"]["executive_summary"]["verdict"] == expected
    assert shape_results["p=none, rua, pct"]["executive_summary"]["verdict"] == expected


def test_ready_record_verdict_asks_receivers_to_refuse_failing_mail(shape_results):
    assert shape_results["reject, ready"]["executive_summary"]["verdict"] == (
        "Receiving mail servers are asked to refuse mail that fails authentication for this "
        "domain and its subdomains.")


def test_enforcing_without_rua_verdict(shape_results):
    assert shape_results["quarantine, no rua"]["executive_summary"]["verdict"] == (
        "Receivers are asked to block forged mail, but you get no reports on what they "
        "block or whether your own mail passes.")


def _vectors_checks(statuses, policy="reject"):
    names = ["Direct Domain Spoofing", "Subdomain Spoofing", "Non-Existent Subdomain Spoofing"]
    return [
        {"name": "DMARC", "status": "warn", "configured": True, "effective_policy": policy,
         "record": f"v=DMARC1; p={policy}; rua=mailto:a@example.com",
         "tag_breakdown": {"health": {"status": "compatible"}, "config_warnings": []},
         "attack_surface": {"vectors": [{"name": n, "status": s}
                                        for n, s in zip(names, statuses)]}},
        {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
        {"name": "DKIM", "status": "pass", "configured": True},
    ]


def _verdict(checks):
    return build_executive_summary(checks, build_security_roadmap(checks))["verdict"]


def test_two_open_routes_are_named_in_plain_words():
    assert _verdict(_vectors_checks(["protected", "exposed", "exposed"])) == (
        "Your settings do not ask receivers to block forged mail sent as your subdomains "
        "and made-up subdomains. Each receiver decides on its own.")


def test_quarantine_everywhere_says_spam_not_refuse():
    assert _verdict(_vectors_checks(["partial"] * 3, policy="quarantine")) == (
        "Receivers are asked to send forged mail to spam rather than refuse it "
        "(p=quarantine).")


def test_a_missing_dmarc_record_verdict():
    checks = [{"name": "DMARC", "status": "fail", "pill_label": "Missing"},
              {"name": "SPF", "status": "pass", "configured": True, "record": "v=spf1 -all"},
              {"name": "DKIM", "status": "pass", "configured": True}]
    assert _verdict(checks) == ("Your domain has no DMARC record, so receiving mail servers "
                                "get no instruction for mail that fails authentication.")


def test_the_broken_record_and_no_mail_branches_keep_their_wording(audit):
    spf, includes = _over_limit_spf()
    result = _run(audit, f"v=DMARC1; p=reject; {RUA}", spf=spf, extra=includes)
    assert result["executive_summary"]["verdict"] == (
        "Receivers are asked to refuse forged mail, but one record is broken: SPF.")


# ---------------------------------------------------------------
# The breakdown under an amber DMARC card
# ---------------------------------------------------------------

def test_an_amber_dmarc_card_never_has_a_misconfigured_breakdown(shape_results):
    card = {c["name"]: c for c in shape_results["reject, sp=none"]["checks"]}["DMARC"]
    health = card["tag_breakdown"]["health"]
    assert card["status"] == "warn"
    assert health["status"] == "attention"
    assert health["label"] == "Needs Attention"
    assert health["color"] == "amber"
    assert "critical issues" not in health["summary"]


# ---------------------------------------------------------------
# Pills
# ---------------------------------------------------------------

OLD_PILLS = {"Warning", "Fail", "Issue", "Not configured", "N/A", "Not applicable", "Null MX"}


@pytest.mark.parametrize("label", SHAPES)
def test_no_card_wears_an_old_pill(shape_results, label):
    for card in shape_results[label]["checks"]:
        assert card["pill_label"] not in OLD_PILLS, (card["name"], card["pill_label"])


def test_the_default_pills_use_the_new_words(shape_results):
    cards = {c["name"]: c for c in shape_results["p=none, no rua"]["checks"]}
    assert cards["DMARC"]["status"] == "warn"
    assert cards["DMARC"]["pill_label"] == "Could be stronger"
    assert cards["TLS-RPT"]["pill_label"] == "Optional, not set up"

    spf = {c["name"]: c for c in shape_results["over the SPF limit"]["checks"]}["SPF"]
    assert spf["status"] == "fail" and spf["pill_label"] == "Needs fixing"


def test_the_web_and_pdf_pill_labels_match_the_backend():
    expected = {"pass": "Pass", "warn": "Could be stronger", "fail": "Needs fixing",
                "absent": "Optional, not set up", "unavailable": "Not checked"}
    assert pdf_report.STATUS_LBL == expected
    with open(os.path.join(REPO, "static", "app.js"), encoding="utf-8") as f:
        js = f.read()
    block = re.search(r"const STATUS_LABELS = \{(.*?)\};", js, re.S).group(1)
    assert dict(re.findall(r"(\w+): '([^']*)'", block)) == expected
    assert (rt.PILL_PASS, rt.PILL_WARN, rt.PILL_FAIL, rt.PILL_ABSENT) == (
        expected["pass"], expected["warn"], expected["fail"], expected["absent"])
    assert rt.PILL_NOT_APPLICABLE == "Does not apply"
    assert rt.PILL_NULL_MX == "No mail, by design"


def test_claude_md_states_the_new_absent_pill():
    with open(os.path.join(REPO, "CLAUDE.md"), encoding="utf-8") as f:
        text = f.read()
    assert 'pill says "Optional, not set up"' in text
