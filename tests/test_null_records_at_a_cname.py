"""No null MX or null SPF is offered at a name that is a CNAME.

news.bbc.co.uk is a CNAME. With no MX and no SPF found there, the MX and SPF
cards offered copy and paste records for that name: MX 0 . and TXT
v=spf1 -all. A CNAME cannot share its name with any other record (RFC 1034
section 3.6.2, RFC 2181 section 10.1), so neither can be published. The
cards now name the CNAME target as the place those records would go, or say
the CNAME has to be replaced first, and offer no record at the alias.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOMAIN = "news.bbc.test.uk"
TARGET = "www.bbc.test.uk"


def _card(result, name):
    return next(c for c in result["checks"] if c["name"] == name)


def _zone():
    return {
        DOMAIN: {"CNAME": [TARGET]},
        TARGET: {"A": ["192.0.2.80"]},
    }


def test_no_record_is_offered_at_the_alias(audit):
    result = audit(_zone(), DOMAIN)
    mx, spf = _card(result, "MX Records"), _card(result, "SPF")

    assert not mx.get("fix_records"), mx.get("fix_records")
    assert not spf.get("fix_records"), spf.get("fix_records")

    for card in (mx, spf):
        assert TARGET in card["fix"], card["fix"]
        assert "replace the CNAME" in card["fix"], card["fix"]
        assert "CNAME" in card["explanation"], card["explanation"]

    # Nothing anywhere in the result offers a record at the alias itself.
    for rec in (r for c in result["checks"] for r in (c.get("fix_records") or [])):
        assert not (rec.get("host") == DOMAIN and rec.get("type") in ("MX", "TXT")
                    and rec.get("value") in ("0 .", "v=spf1 -all")), rec


def test_plan_rows_send_the_reader_to_the_target(audit):
    result = audit(_zone(), DOMAIN)
    rows = [i for i in result["security_roadmap"]["items"]
            if i["protocol"] in ("MX Records", "SPF")]
    assert {r["protocol"] for r in rows} == {"MX Records", "SPF"}
    for row in rows:
        assert TARGET in row["action"], row
    assert f'"host": "{DOMAIN}"' not in json.dumps(result["security_roadmap"])


def test_a_name_that_is_not_a_cname_still_gets_the_records(audit):
    zone = {DOMAIN: {"A": ["192.0.2.80"]}}
    result = audit(zone, DOMAIN)
    mx, spf = _card(result, "MX Records"), _card(result, "SPF")

    assert mx["fix_records"] == [{
        "type": "MX", "host": DOMAIN, "value": "0 .",
        "comment": "Null MX (RFC 7505): declares this domain does not accept email",
    }]
    assert [r["value"] for r in spf["fix_records"]] == ["v=spf1 -all"]
    assert spf["fix_records"][0]["host"] == DOMAIN
