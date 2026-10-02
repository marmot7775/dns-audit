"""An SOA serial mismatch is never one of the first things to do.

yahoo.co.jp and usp.br got "Your DNS servers gave different versions of your
records. This usually clears within hours." as an item under "Do these
first". A change still propagating needs nothing from the owner, so that row
stays in the plan and is never put first. usp.br's serials are dated 2018, so
its mismatch is not clearing: when the serials say it has lasted, the head
says so instead of promising it will clear.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result_transformer import (_soa_mismatch_persistent, build_executive_summary,
                                build_security_roadmap)
from test_nameserver_serials_per_provider import NS1, _check

TRANSIENT = "This usually clears within hours"
PERSISTENT = ("Your DNS servers disagree about your records. Ask your DNS host to "
              "check that every server gets updates.")


def _card(lagging, current):
    serials = {ip: current for ip in NS1.values()}
    serials[NS1["dns4.p08.nsone.net"]] = lagging
    _, card = _check(NS1, serials)
    assert card["status"] == "warn"
    return card


def _today_serial(n):
    return int(datetime.now(timezone.utc).strftime("%Y%m%d") + f"{n:02d}")


def _plan(card):
    checks = [card]
    roadmap = build_security_roadmap(checks)
    return roadmap, build_executive_summary(checks, roadmap)


def test_a_fresh_mismatch_is_in_the_plan_and_not_first():
    roadmap, es = _plan(_card(_today_serial(1), _today_serial(2)))
    row = next(i for i in roadmap["items"] if i["protocol"] == "Nameservers")

    assert TRANSIENT in row["plain_head"]
    assert es["do_first"] == []
    assert "zone transfer" not in es["biggest_risk"].lower(), es["biggest_risk"]
    assert es["biggest_risk_severity"] == "none"


def test_a_mismatch_on_a_2018_serial_does_not_say_it_will_clear():
    # usp.br: a.dns.usp.br 2018085061, b and c 2018085062.
    card = _card(2018085061, 2018085062)
    assert card["soa_mismatch"]["persistent"] is True
    roadmap, es = _plan(card)
    row = next(i for i in roadmap["items"] if i["protocol"] == "Nameservers")

    assert row["plain_head"] == PERSISTENT
    assert "clears" not in row["plain_head"]


def test_the_serials_decide_whether_a_mismatch_has_lasted():
    now = datetime.now(timezone.utc)
    stamp = int(now.timestamp())
    old = int((now - timedelta(days=60)).timestamp())
    assert _soa_mismatch_persistent([_today_serial(1), _today_serial(3)]) is False
    assert _soa_mismatch_persistent([stamp - 120, stamp]) is False
    assert _soa_mismatch_persistent([old - 120, old]) is True
    assert _soa_mismatch_persistent([2018085061, 2018085062]) is True
    # A counter that moved by a handful is a change in flight; one that is
    # thousands apart, or a different kind of number, is not.
    assert _soa_mismatch_persistent([2416242911, 2416242912]) is False
    assert _soa_mismatch_persistent([2416242912, 2416992912]) is True
    assert _soa_mismatch_persistent([7, _today_serial(1)]) is True
