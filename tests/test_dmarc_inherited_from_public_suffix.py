"""A DMARC policy found at a public suffix is the registry's, not the domain's.

news24.co.za publishes no _dmarc record, and _dmarc.co.za publishes
"v=DMARC1; p=none" with no psd tag. The DMARC card read "Inherited: none (from
co.za)" and "Organizational domain: co.za". The first thing to do was "Add
aggregate reporting" at host _dmarc.co.za with rua=mailto:dmarc-reports@co.za,
and the second "Progress from p=none to enforcement", also at _dmarc.co.za.
The owner cannot edit the registry's record, and RFC 7489 receivers find no
DMARC policy for the domain at all.

The domain is now treated as having no DMARC record of its own: the critical
"Publish a DMARC record" row, with a record for the owner's own name, a line
saying the policy above it belongs to the registry, and no registry hostname
in any host field or address. The verdict does not credit the domain with the
registry's policy.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone

DOMAIN = "news-shape.co.za"


def _zone(registry_record, domain=DOMAIN, parent=None):
    records = {
        domain: {"MX": [(10, f"mx.{domain}")], "TXT": ["v=spf1 mx -all"],
                 "A": ["203.0.113.10"], "NS": [f"ns1.{domain}", f"ns2.{domain}"]},
        f"mx.{domain}": {"A": ["203.0.113.11"]},
        f"ns1.{domain}": {"A": ["203.0.113.53"]},
        f"ns2.{domain}": {"A": ["198.51.100.53"]},
        "_dmarc.co.za": {"TXT": [registry_record]},
    }
    if parent:
        records[f"_dmarc.{parent[0]}"] = {"TXT": [parent[1]]}
    return FakeZone(records)


def _dmarc(result):
    return next(c for c in result["checks"] if c["name"] == "DMARC")


def _dmarc_rows(result):
    return [i for i in result["security_roadmap"]["items"] if i["protocol"] == "DMARC"]


def test_the_card_is_the_no_record_card_with_the_registry_named(audit):
    card = _dmarc(audit(_zone("v=DMARC1; p=none"), DOMAIN))

    assert (card["status"], card["pill_label"]) == ("fail", "Missing"), card["verdict"]
    assert card["inherited_from"] is None
    assert card["effective_policy"] is None
    texts = [d["text"] for d in card["details"]]
    assert not any("Organizational domain: co.za" in t for t in texts), texts
    assert any("belongs to the co.za registry" in t and "RFC 9989" in t for t in texts), texts
    assert card["record_builder"]["deploy"]["host"] == f"_dmarc.{DOMAIN}"


def test_every_plan_row_targets_the_owners_own_name(audit):
    result = audit(_zone("v=DMARC1; p=none"), DOMAIN)
    rows = _dmarc_rows(result)

    assert [r["action"] for r in rows] == ["Publish a DMARC record"], rows
    row = rows[0]
    assert row["priority"] == "critical"
    assert row["host"] == f"_dmarc.{DOMAIN}"
    assert row["record"] == f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{DOMAIN}"
    assert "co.za registry" in row["impact"] and "RFC 9989" in row["impact"]
    for r in result["security_roadmap"]["items"]:
        assert r.get("host") != "_dmarc.co.za", r
        assert "@co.za" not in (r.get("record") or ""), r
        assert "@co.za" not in (r.get("host_note") or ""), r


def test_do_these_first_publishes_the_owners_record(audit):
    es = audit(_zone("v=DMARC1; p=none"), DOMAIN)["executive_summary"]

    assert es["do_first"][0]["title"] == "Publish a DMARC record"
    assert not any("rua" in i["title"] or "p=none" in i["title"] for i in es["do_first"])


def test_the_verdict_does_not_credit_the_domain_with_the_registry_policy(audit):
    for record in ("v=DMARC1; p=none", "v=DMARC1; p=reject"):
        verdict = audit(_zone(record), DOMAIN)["executive_summary"]["verdict"]
        assert verdict.startswith("Your domain does not tell receivers what to do"), verdict
        assert "belongs to the co.za registry" in verdict, verdict
        assert "(DMARC p=none)" not in verdict
        assert "refuse" not in verdict and "block" not in verdict, verdict


def test_a_real_organizational_domain_is_still_inherited(audit):
    # mail.shop-shape.co.za inherits from shop-shape.co.za, which the owner
    # controls. That stays an inherited policy, changed at the parent.
    child = "mail.shop-shape.co.za"
    result = audit(_zone("v=DMARC1; p=none", domain=child,
                         parent=("shop-shape.co.za", "v=DMARC1; p=none")), child)
    card = _dmarc(result)

    assert card["pill_label"] == "Inherited"
    assert card["inherited_from"] == "shop-shape.co.za"
    hosts = {r.get("host") for r in _dmarc_rows(result)}
    assert hosts == {"_dmarc.shop-shape.co.za"}, hosts
    assert "registry" not in result["executive_summary"]["verdict"]
    texts = " ".join(d["text"] for d in card["details"])
    assert "co.za registry" not in texts and "Organizational domain: co.za" not in texts, texts
