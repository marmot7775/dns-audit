"""A plan row's plain head matches its card's status.

sbi.co.in and parkviewdental.com have an amber Nameservers card ("All
nameservers ... same network block"). The plan row's head read "Your DNS
servers have a fault that can stop your mail and website from being found.",
the head for a red card, and on parkviewdental.com it was the second thing to
do. An amber card is a server set that works, so it gets the warn head. The
BIMI row had the same status-blind head: sbi.co.in's amber logo record (no
fixed pixel size) read "Your logo may not show in inboxes".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import build_executive_summary, build_security_roadmap

FAULT = "Your DNS servers have a fault that can stop your mail and website from being found."
RESILIENT = "Your DNS servers work but could be more resilient."


def _ns(status, text):
    return {"name": "Nameservers", "status": status,
            "fix": "Use nameservers on different networks, ideally from different providers.",
            "details": [{"type": "warning" if status == "warn" else "error", "text": text}]}


def _row(checks, protocol):
    return next(i for i in build_security_roadmap(checks)["items"] if i["protocol"] == protocol)


def test_an_amber_nameservers_card_gets_the_warn_head():
    row = _row([_ns("warn", "All nameservers are in the same network block")], "Nameservers")
    assert row["plain_head"] == RESILIENT


def test_a_red_nameservers_card_keeps_the_fault_head():
    row = _row([_ns("fail", "Lame delegation: ns2 is not authoritative")], "Nameservers")
    assert row["plain_head"] == FAULT


def test_do_these_first_never_calls_an_amber_card_a_fault():
    checks = [{"name": "DMARC", "status": "fail", "pill_label": "Missing", "configured": False},
              _ns("warn", "All nameservers are in the same network block")]
    es = build_executive_summary(checks, build_security_roadmap(checks))
    heads = [i["plain_head"] for i in es["do_first"]]
    assert FAULT not in heads and RESILIENT in heads, heads


def test_an_amber_bimi_card_does_not_say_the_logo_may_not_show():
    bimi = {"name": "BIMI", "status": "warn", "records_found": 1,
            "fix": 'Set fixed pixel dimensions on the root <svg> element.'}
    assert _row([bimi], "BIMI")["plain_head"] == "Your logo record works but could be stronger."
    bimi["status"] = "fail"
    assert _row([bimi], "BIMI")["plain_head"].startswith("Your logo may not show")
