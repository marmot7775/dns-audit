"""The staged DMARC path and the step check (issue 286).

A: a rules layer on the plan shows only the next DMARC stage, the condition
for moving on in plain words, the record in the change set, vendor rows from
Sendermap's catalog, and says that the site never sees DMARC reports.
C: the change set is a stepper, each step has a check that does its own
fresh lookup, and an enforcing policy never comes before the steps that
cover the senders.

Everything runs offline: unit cases on hand-built cards, the fixture zone
through the page and the PDF, and the endpoint with a fake resolver.
"""
import io
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402

import pdf_report  # noqa: E402
import plan_records  # noqa: E402
import sendermap_adapter  # noqa: E402
import staged_path  # noqa: E402
import step_check  # noqa: E402
from result_transformer import INBOX_SCOPES, _edit_dmarc_record  # noqa: E402
from test_ui_consistency_a11y import (  # noqa: E402,F401
    DOMAIN,
    _page,
    _render,
    _run,
    _zone,
    browser,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUA = f"mailto:d@{DOMAIN}"


def _stage(record, scope="complete", vendors=None, status="pass", **card):
    dmarc = {"name": "DMARC", "status": status, "record": record, **card}
    return staged_path.build(DOMAIN, dmarc, scope, INBOX_SCOPES, vendors,
                             sendermap_adapter.spf_include, _edit_dmarc_record)


# ---------------------------------------------------------------
# A: the next stage only
# ---------------------------------------------------------------

def test_no_record_starts_at_stage_one():
    st = _stage(None, status="fail", pill_label="Missing")
    assert st["stage"] == "report" and st["stage_number"] == 1
    assert st["set_p"] is None


def test_p_none_without_a_report_address_asks_for_one_first():
    st = _stage("v=DMARC1; p=none")
    assert st["stage"] == "report"
    assert "rua" in st["do"]


def test_a_placeholder_address_is_not_a_report_address():
    st = _stage(f"v=DMARC1; p=none; rua={plan_records.rua_placeholder(DOMAIN)}")
    assert st["stage"] == "report"


def test_p_none_with_reports_moves_to_quarantine():
    st = _stage(f"v=DMARC1; p=none; rua={RUA}")
    assert st["stage"] == "quarantine" and st["set_p"] == "quarantine"
    assert staged_path.record_for(st, f"v=DMARC1; p=none; rua={RUA}", _edit_dmarc_record) \
        == f"v=DMARC1; p=quarantine; rua={RUA}"


def test_quarantine_moves_to_reject():
    st = _stage(f"v=DMARC1; p=quarantine; rua={RUA}")
    assert st["stage"] == "reject" and st["set_p"] == "reject"


@pytest.mark.parametrize("card", [
    dict(record=f"v=DMARC1; p=reject; rua={RUA}"),                  # already there
    dict(record=f"v=DMARC1; p=quarantine; pct=50; rua={RUA}"),      # the pct rows own this
    dict(record=f"v=DMARC1; p=none; rua={RUA}", inherited_from="example.com"),
    dict(record=None, status="unavailable"),                        # a lookup that failed
    dict(record=None, status="fail", pill_label="Present"),         # broken, not missing
])
def test_no_stage_to_show(card):
    assert _stage(**{"status": "pass", **card}) is None


@pytest.mark.parametrize("scope", sorted(INBOX_SCOPES))
def test_inbox_scopes_do_not_ask_for_enforcement(scope):
    assert _stage(f"v=DMARC1; p=none; rua={RUA}", scope=scope) is None
    assert _stage(f"v=DMARC1; p=quarantine; rua={RUA}", scope=scope) is None


@pytest.mark.parametrize("record,status,must,never", [
    (None, "fail", "stage 1", ("quarantine", "reject", "stage 2", "stage 3")),
    ("v=DMARC1; p=none", "warn", "stage 1", ("quarantine", "reject", "stage 2", "stage 3")),
    (f"v=DMARC1; p=none; rua={RUA}", "warn", "stage 2", ("reject", "stage 1", "stage 3")),
    (f"v=DMARC1; p=quarantine; rua={RUA}", "pass", "stage 3", ("stage 1", "stage 2")),
])
def test_only_the_next_stage_is_shown(record, status, must, never):
    st = _stage(record, status=status, pill_label="Missing" if record is None else None)
    text = " ".join([st["title"], st["do"], st["condition"]]).lower()
    assert must in text
    for word in never:
        assert word not in text, word


def test_the_condition_is_plain_words_and_names_the_wait():
    st = _stage(f"v=DMARC1; p=none; rua={RUA}")
    assert "two weeks" in st["condition"] and "passing" in st["condition"]


@pytest.mark.parametrize("record,status", [
    (None, "fail"), (f"v=DMARC1; p=none; rua={RUA}", "warn"),
    (f"v=DMARC1; p=quarantine; rua={RUA}", "pass"),
])
def test_every_stage_says_the_site_never_sees_reports(record, status):
    st = _stage(record, status=status, pill_label="Missing" if record is None else None)
    assert "never sees your DMARC reports" in st["reports_notice"]
    assert "cannot tell whether moving to enforcement is safe" in st["reports_notice"]


def test_vendor_rows_come_from_the_sendermap_catalog():
    cat = sendermap_adapter.catalog()
    named = next(n for n in cat.services if sendermap_adapter.spf_include(n))
    vendors = [
        {"name": named, "category": "Email service", "role": "sender",
         "detected_via": "SPF", "missing": []},
        {"name": "Someone Else", "role": "sender", "missing": ["No DKIM key for Someone Else."]},
        {"name": "Reporter", "role": "reporting", "missing": []},
        {"name": "Account", "role": "account", "missing": []},
    ]
    rows = _stage(f"v=DMARC1; p=none; rua={RUA}", vendors=vendors)["senders"]
    assert [r["name"] for r in rows] == [named, "Someone Else"]
    assert rows[0]["spf_include"] == sendermap_adapter.spf_include(named)
    assert rows[0]["state"] == "covered" and rows[1]["state"] == "incomplete"
    assert rows[1]["spf_include"] is None


def test_no_vendors_still_says_what_that_does_and_does_not_mean():
    st = _stage(f"v=DMARC1; p=none; rua={RUA}", vendors=[])
    assert st["senders"] == [] and "shows up only in your reports" in st["senders_note"]


def test_the_rules_layer_calls_nothing_outside_the_audit():
    """No language model pass and nothing sent to a third party API."""
    for name in ("staged_path.py", "step_check.py"):
        src = open(os.path.join(REPO, name), encoding="utf-8").read()
        for banned in ("anthropic", "openai", "requests", "httpx", "urllib", "socket", "aiohttp"):
            assert not re.search(rf"^\s*(import|from)\s+{banned}\b", src, re.M), (name, banned)


# ---------------------------------------------------------------
# C: an enforcing policy never comes before the senders
# ---------------------------------------------------------------

def _item(protocol, record):
    return {"protocol": protocol, "priority": "high", "action": "x", "records": [record]}


def test_enforcing_step_moves_after_the_sender_steps():
    R = plan_records.record
    enforce = R("replace", "TXT", f"_dmarc.{DOMAIN}",
                f"v=DMARC1; p=quarantine; rua={RUA}", enforcing=True,
                edit={"kind": "dmarc", "base": f"v=DMARC1; p=none; rua={RUA}",
                      "set": {"p": "quarantine"}, "remove": []})
    spf = R("replace", "TXT", DOMAIN, "v=spf1 mx ~all")
    dkim = R("add", "TXT", f"s1._domainkey.{DOMAIN}", "v=DKIM1; k=rsa; p=abc")
    cs = plan_records.build_change_set(
        [_item("DMARC", enforce), _item("SPF", spf), _item("DKIM", dkim)],
        {"dmarc": _edit_dmarc_record, "tags": plan_records.edit_tag_list}, domain=DOMAIN)
    assert [e["protocol"] for e in cs["entries"]] == ["SPF", "DKIM", "DMARC"]
    assert [e["step"] for e in cs["entries"]] == [1, 2, 3]
    last = cs["entries"][-1]
    assert last["enforcing"] and last["hold"] == plan_records.ENFORCE_HOLD


def test_a_report_address_step_is_not_held_behind_the_senders():
    """p=none with rua= enforces nothing, and the reports are what show the
    senders, so it stays where the plan put it."""
    R = plan_records.record
    rua = R("add", "TXT", f"_dmarc.{DOMAIN}", f"v=DMARC1; p=none; rua={RUA}")
    spf = R("replace", "TXT", DOMAIN, "v=spf1 mx ~all")
    cs = plan_records.build_change_set(
        [_item("DMARC", rua), _item("SPF", spf)],
        {"dmarc": _edit_dmarc_record, "tags": plan_records.edit_tag_list}, domain=DOMAIN)
    assert [e["protocol"] for e in cs["entries"]] == ["DMARC", "SPF"]
    assert "hold" not in cs["entries"][0]


@pytest.mark.parametrize("base,new,expected", [
    (f"v=DMARC1; p=none; rua={RUA}", f"v=DMARC1; p=quarantine; rua={RUA}", True),
    (f"v=DMARC1; p=quarantine; rua={RUA}", f"v=DMARC1; p=reject; rua={RUA}", True),
    ("v=DMARC1; p=reject; sp=none", "v=DMARC1; p=reject; sp=reject", True),
    ("v=DMARC1; p=reject", "v=DMARC1; p=reject; np=reject", False),
    ("v=DMARC1; p=none", f"v=DMARC1; p=none; rua={RUA}", False),
    (None, f"v=DMARC1; p=none; rua={RUA}", False),
])
def test_what_counts_as_enforcing(base, new, expected):
    assert plan_records.makes_enforcing(base, new) is expected


def _roadmap(result):
    return json.loads(json.dumps(result, default=str))["security_roadmap"]


@pytest.fixture(scope="module")
def none_result():
    # DMARC p=none with reports, and an SPF record that needs a change, so
    # the plan has a sender step and an enforcing step.
    return json.loads(json.dumps(
        _run(_zone(dmarc=f"v=DMARC1; p=none; rua={RUA}", spf="v=spf1 mx ?all")), default=str))


def test_the_audit_puts_the_senders_before_the_policy(none_result):
    entries = none_result["security_roadmap"]["change_set"]["entries"]
    protos = [e["protocol"] for e in entries]
    assert "SPF" in protos and "DMARC" in protos
    enforcing = [n for n, e in enumerate(entries) if e.get("enforcing")]
    assert enforcing, "the next stage is a step in the change set"
    senders = [n for n, e in enumerate(entries) if e["protocol"] in plan_records.SENDER_PROTOCOLS]
    assert min(enforcing) > max(senders)
    step = entries[enforcing[0]]
    assert "p=quarantine" in step["value"] and step["hold"] and step["checkable"]


def test_the_audit_carries_the_staged_path(none_result):
    sp = none_result["security_roadmap"]["staged_path"]
    assert sp["stage"] == "quarantine"
    assert sp["record"].startswith("v=DMARC1; p=quarantine")


def test_a_quarantine_domain_gets_the_reject_step():
    result = json.loads(json.dumps(
        _run(_zone(dmarc=f"v=DMARC1; p=quarantine; rua={RUA}")), default=str))
    rm = result["security_roadmap"]
    assert rm["staged_path"]["stage"] == "reject"
    step = [e for e in rm["change_set"]["entries"] if e["protocol"] == "DMARC"]
    assert len(step) == 1 and "p=reject" in step[0]["value"] and step[0]["hold"]


def test_a_reject_domain_has_no_staged_path():
    result = json.loads(json.dumps(
        _run(_zone(dmarc=f"v=DMARC1; p=reject; rua={RUA}")), default=str))
    assert result["security_roadmap"]["staged_path"] is None


# ---------------------------------------------------------------
# C: the step check does its own fresh lookup
# ---------------------------------------------------------------

class _Rdata:
    def __init__(self, text=None, target=None, address=None):
        self.strings = [text.encode()] if text is not None else []
        self.target = target
        self.address = address


class FakeResolver:
    """Answers from a dict {(name, type): [rdata]} and records every ask."""
    cache = None

    def __init__(self, records=None, error=None):
        self.records, self.error, self.asked, self.lifetime = records or {}, error, [], None

    def resolve(self, name, rtype, *a, **k):
        self.asked.append((name, rtype))
        if self.error:
            raise self.error
        if (name, rtype) not in self.records:
            raise dns.resolver.NoAnswer()
        return self.records[(name, rtype)]


def _txt(*values):
    return [_Rdata(text=v) for v in values]


DM = f"_dmarc.{DOMAIN}"
WANT = f"v=DMARC1; p=quarantine; rua={RUA}"


def test_live_when_the_published_record_matches():
    res = step_check.check(DOMAIN, DM, "TXT", WANT, resolver=FakeResolver({(DM, "TXT"): _txt(WANT)}))
    assert res["state"] == "live"


def test_tag_order_and_policy_case_do_not_matter():
    res = step_check.check(DOMAIN, DM, "TXT", WANT, resolver=FakeResolver(
        {(DM, "TXT"): _txt(f"v=DMARC1; rua={RUA}; p=Quarantine")}))
    assert res["state"] == "live"


def test_not_yet_when_the_old_record_is_still_there():
    res = step_check.check(DOMAIN, DM, "TXT", WANT, resolver=FakeResolver(
        {(DM, "TXT"): _txt(f"v=DMARC1; p=none; rua={RUA}")}))
    assert res["state"] == "not_yet" and "different value" in res["note"]
    assert "DNS can lag" in res["note"]


def test_not_yet_when_nothing_is_published():
    res = step_check.check(DOMAIN, DM, "TXT", WANT, resolver=FakeResolver())
    assert res["state"] == "not_yet" and "Nothing is published" in res["note"]


def test_two_dmarc_records_are_not_live():
    res = step_check.check(DOMAIN, DM, "TXT", WANT, resolver=FakeResolver(
        {(DM, "TXT"): _txt(WANT, f"v=DMARC1; p=none; rua={RUA}")}))
    assert res["state"] == "not_yet" and "more than one" in res["note"]


def test_a_failed_lookup_is_not_checked_never_not_yet():
    res = step_check.check(DOMAIN, DM, "TXT", WANT,
                           resolver=FakeResolver(error=dns.exception.Timeout()))
    assert res["state"] == "unavailable"


def test_a_placeholder_matches_a_real_address_but_not_itself():
    want = f"v=DMARC1; p=none; rua={plan_records.rua_placeholder(DOMAIN)}"
    real = step_check.check(DOMAIN, DM, "TXT", want, resolver=FakeResolver(
        {(DM, "TXT"): _txt("v=DMARC1; p=none; rua=mailto:me@example.org")}))
    assert real["state"] == "live"
    left = step_check.check(DOMAIN, DM, "TXT", want, resolver=FakeResolver(
        {(DM, "TXT"): _txt(want)}))
    assert left["state"] == "not_yet" and "placeholder" in left["note"]


def test_spf_matches_on_its_terms():
    res = step_check.check(DOMAIN, DOMAIN, "TXT", "v=spf1 mx ~all", resolver=FakeResolver(
        {(DOMAIN, "TXT"): _txt("google-site-verification=abc", "V=SPF1  MX  ~ALL")}))
    assert res["state"] == "live"


def test_a_delete_is_live_once_the_value_is_gone():
    old = "v=spf1 +all"
    gone = step_check.check(DOMAIN, DOMAIN, "TXT", old, op="delete",
                            resolver=FakeResolver({(DOMAIN, "TXT"): _txt("v=spf1 mx -all")}))
    assert gone["state"] == "live"
    there = step_check.check(DOMAIN, DOMAIN, "TXT", old, op="delete",
                             resolver=FakeResolver({(DOMAIN, "TXT"): _txt(old)}))
    assert there["state"] == "not_yet"


def test_a_name_that_must_resolve():
    host = f"mta-sts.{DOMAIN}"
    res = step_check.check(DOMAIN, host, "A or CNAME", resolver=FakeResolver(
        {(host, "A"): [_Rdata(address="203.0.113.9")]}))
    assert res["state"] == "live"


def test_a_name_outside_the_domain_is_refused():
    with pytest.raises(ValueError):
        step_check.check(DOMAIN, "_dmarc.other.test", "TXT", WANT, resolver=FakeResolver())
    with pytest.raises(ValueError):
        step_check.check(DOMAIN, f"evil{DOMAIN}", "TXT", WANT, resolver=FakeResolver())


def test_the_check_uses_a_resolver_with_no_cache(monkeypatch):
    import dns_tools
    fresh = FakeResolver({(DM, "TXT"): _txt(WANT)})
    monkeypatch.setattr(dns_tools, "get_uncached_resolver", lambda timeout=5.0: fresh)

    def cached(*a, **k):
        raise AssertionError("the step check must not use the shared answer cache")
    monkeypatch.setattr(dns_tools, "get_resolver", cached)
    assert step_check.check(DOMAIN, DM, "TXT", WANT)["state"] == "live"
    assert fresh.asked == [(DM, "TXT")]


# ---------------------------------------------------------------
# C: the endpoint
# ---------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient
    import server
    server._rate_limit_store.clear() if hasattr(server, "_rate_limit_store") else None
    monkeypatch.setattr(server, "_check_rate_limit", lambda ip: True)
    return TestClient(server.app), server


def test_the_endpoint_answers_from_a_fresh_lookup_not_the_audit_cache(client, monkeypatch):
    import dns_tools
    c, server = client
    # A five minute audit result that still says p=none for this domain.
    server._set_cached(f"{DOMAIN}::complete", {"stale": True, "domain": DOMAIN})
    fresh = FakeResolver({(DM, "TXT"): _txt(WANT)})
    monkeypatch.setattr(dns_tools, "get_uncached_resolver", lambda timeout=5.0: fresh)
    monkeypatch.setattr(server, "_get_cached", lambda k: (_ for _ in ()).throw(
        AssertionError("the step check must not read the audit cache")))
    r = c.get("/api/step-check", params={"domain": DOMAIN, "host": DM, "type": "TXT",
                                         "expect": WANT, "op": "replace"})
    assert r.status_code == 200 and r.json()["state"] == "live"
    assert r.headers["cache-control"] == "no-store"
    assert fresh.asked == [(DM, "TXT")]


def test_the_endpoint_keeps_nothing(client, monkeypatch):
    import dns_tools
    c, server = client
    monkeypatch.setattr(dns_tools, "get_uncached_resolver",
                        lambda timeout=5.0: FakeResolver({(DM, "TXT"): _txt(WANT)}))
    monkeypatch.setattr(server, "_log_audit", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("a step check is not an audit and is not logged")))
    before = dict(server._cache)
    c.get("/api/step-check", params={"domain": DOMAIN, "host": DM, "type": "TXT", "expect": WANT})
    assert dict(server._cache) == before


@pytest.mark.parametrize("params", [
    {"host": "_dmarc.other.test", "type": "TXT"},
    {"host": DM, "type": "MX"},
    {"host": DM, "type": "TXT", "op": "explode"},
])
def test_the_endpoint_refuses_what_it_should_not_look_up(client, params):
    c, _ = client
    r = c.get("/api/step-check", params={"domain": DOMAIN, **params})
    assert r.status_code == 400


def test_the_endpoint_is_rate_limited(client, monkeypatch):
    c, server = client
    monkeypatch.setattr(server, "_check_rate_limit", lambda ip: False)
    r = c.get("/api/step-check", params={"domain": DOMAIN, "host": DM, "type": "TXT"})
    assert r.status_code == 429


# ---------------------------------------------------------------
# Page and PDF agree
# ---------------------------------------------------------------

def _pdf_text(result):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_report.generate_pdf(result)))
    return " ".join(" ".join((p.extract_text() or "").split()) for p in reader.pages)


def _squash(text):
    return " ".join(text.split())


def test_the_pdf_prints_the_stage_the_hold_and_the_notice(none_result):
    text = _pdf_text(none_result)
    sp = none_result["security_roadmap"]["staged_path"]
    for field in ("title", "do", "reports_notice"):
        assert _squash(sp[field]) in text, field
    assert _squash("Before this step: " + sp["condition"]) in text
    assert _squash(plan_records.ENFORCE_HOLD) in text
    assert "checks that one record with a fresh lookup" in text


def test_the_pdf_lists_the_steps_in_the_same_order(none_result):
    # A host name wraps inside its table cell, so compare without spaces.
    text = _pdf_text(none_result).replace(" ", "")
    entries = none_result["security_roadmap"]["change_set"]["entries"]
    start = text.index("Recordstochange")
    spots = []
    for e in entries:
        at = text.find(e["host"].replace(" ", ""), spots[-1] if spots else start)
        assert at >= 0, e["host"]
        spots.append(at)
    assert spots == sorted(spots)
    # The held step is last among the sender steps' records, here as on the page.
    held = next(n for n, e in enumerate(entries) if e.get("enforcing"))
    assert all(e["protocol"] not in plan_records.SENDER_PROTOCOLS for e in entries[held:])


def test_no_dashes_in_the_new_text(none_result):
    sp = none_result["security_roadmap"]["staged_path"]
    for value in (sp["title"], sp["do"], sp["condition"], sp["reports_notice"], sp["senders_note"],
                  plan_records.ENFORCE_HOLD, step_check.LAG_NOTE):
        assert "—" not in value and " -- " not in value


def test_the_privacy_page_says_nothing_new_about_the_stepper():
    """The decision on issue 286: no audit data goes to a third party and the
    step check keeps nothing, so the privacy page needs no stepper section.
    This compared the whole page body with origin/main, which also froze the
    page against the 2026-11 corrections to what the log and the lookups do
    (issues 295 and 296). It now checks the decision itself."""
    with open(os.path.join(REPO, "static", "privacy.html"), encoding="utf-8") as f:
        page = f.read().lower()
    for word in ("step-check", "step check", "stepper", "language model"):
        assert word not in page, word


# ---------------------------------------------------------------
# The stepper in the browser: both themes, wide and 375px
# ---------------------------------------------------------------

def _mock_check(page, answers):
    """Answer /api/step-check from `answers` (a list, one reply per call) and
    keep the requests."""
    seen = []

    def handler(route):
        seen.append(route.request.url)
        body = answers[min(len(seen), len(answers)) - 1]
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))
    page.route("**/api/step-check*", handler)
    return seen


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [1280, 375])
def test_the_stepper_walks_the_steps(browser, none_result, theme, width):  # noqa: F811
    ctx, pg, errors = _page(browser, theme, width)
    try:
        seen = _mock_check(pg, [
            {"state": "not_yet", "found": ["v=spf1 mx ?all"], "note": "A different value is published at this name. DNS can lag."},
            {"state": "live", "found": [], "note": "The record is published and matches."},
        ])
        _render(pg, none_result)
        entries = none_result["security_roadmap"]["change_set"]["entries"]
        # The staged path: the next stage and the notice.
        sp = pg.locator("#staged-path")
        assert sp.is_visible()
        assert "never sees your DMARC reports" in sp.inner_text()
        # One record at a time.
        visible = pg.locator(".rtc-row:visible")
        assert visible.count() == 1
        assert pg.locator("[data-rtc-progress]").inner_text().startswith(f"Step 1 of {len(entries)}")
        nxt = visible.locator("[data-rtc-next]")
        assert nxt.is_disabled()
        # Not yet keeps the step; live opens the next one.
        visible.locator("[data-rtc-check]").click()
        pg.wait_for_function("document.querySelector('.rtc-row:not([hidden]) [data-rtc-result]').textContent.startsWith('Not yet')")
        assert nxt.is_disabled()
        visible.locator("[data-rtc-check]").click()
        pg.wait_for_function("document.querySelector('.rtc-row:not([hidden]) [data-rtc-result]').textContent.startsWith('Live')")
        assert nxt.is_enabled()
        nxt.click()
        assert pg.locator("[data-rtc-progress]").inner_text().startswith(f"Step 2 of {len(entries)}")
        # The check asked for that record, with its host and value.
        assert len(seen) == 2 and "api/step-check" in seen[0] and "host=" in seen[0]
        # Controls are real targets, and nothing runs off the screen.
        for sel in ("[data-rtc-check]", "[data-rtc-next]", "[data-rtc-back]", "[data-rtc-showall]",
                    "[data-rtc-copy-all]"):
            box = pg.locator(sel).first.bounding_box()
            if box:
                assert box["height"] >= 44, sel
        assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [1280, 375])
def test_the_enforcing_step_waits_for_the_senders_and_the_owner(browser, none_result, theme, width):  # noqa: F811
    ctx, pg, errors = _page(browser, theme, width)
    try:
        _mock_check(pg, [{"state": "live", "found": [], "note": "The record is published and matches."}])
        _render(pg, none_result)
        entries = none_result["security_roadmap"]["change_set"]["entries"]
        last = next(n for n, e in enumerate(entries) if e.get("enforcing"))
        # Show every record at once: the enforcing step is still held.
        pg.locator("[data-rtc-showall]").click()
        row = pg.locator(".rtc-row").nth(last)
        assert row.is_visible()
        check = row.locator("[data-rtc-check]")
        assert check.is_disabled()
        assert "first" in row.locator("[data-rtc-result]").inner_text()
        # Sender steps live, then the box, then the check opens.
        for i in range(last):
            r = pg.locator(".rtc-row").nth(i)
            if r.locator("[data-rtc-check]").count():
                r.locator("[data-rtc-check]").click()
            else:
                r.locator("[data-rtc-published]").click()
        pg.wait_for_function(
            f"[...document.querySelectorAll('.rtc-row')].slice(0, {last}).every(r => ['live','published','skipped'].includes(r.dataset.state))")
        assert check.is_disabled()  # the box is still unticked
        row.locator("[data-rtc-confirm]").check()
        assert check.is_enabled()
        assert not errors, errors
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_stepper_text_clears_contrast(browser, none_result, theme):  # noqa: F811
    from test_ui_consistency_a11y import CONTRAST_JS
    ctx, pg, errors = _page(browser, theme, 375)
    try:
        _mock_check(pg, [{"state": "not_yet", "found": [], "note": "Nothing is published at this name yet. DNS can lag."}])
        _render(pg, none_result)
        pg.locator(".rtc-row:visible [data-rtc-check]").click()
        pg.wait_for_function("document.querySelector('.rtc-row:not([hidden]) [data-rtc-result]').textContent.startsWith('Not yet')")
        for sel in (".staged-do", ".staged-notice", ".staged-title", ".rtc-progress",
                    ".rtc-row:not([hidden]) .rtc-result", ".rtc-row:not([hidden]) .rtc-check",
                    ".rtc-showall"):
            ratio = pg.evaluate(CONTRAST_JS, [sel, None])
            assert ratio is not None and ratio >= 4.5, (sel, ratio)
        assert not errors, errors
    finally:
        ctx.close()
