"""A probed subdomain name that does not exist is not labelled "Exposed".

intelligentsia.com publishes no wildcard, so none of the twenty probed names
resolves. The panel header read "20 subdomains probed, none exposed" (it
counts names that exist) while all twenty rows below it showed a red
"Exposed". Those rows now read "Does not exist", and the header and the rows
count the same thing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_verdict_names_broken_records import _zone

DOMAIN = "intelligentsia-shape.test"


def _subdomains(audit, dmarc, extra=None):
    result = audit(_zone(dmarc, "v=spf1 mx -all", domain=DOMAIN, extra=extra),
                   DOMAIN, dkim_selector="s1")
    return result["subdomain_audit"]


def test_names_that_do_not_exist_are_not_exposed(audit):
    sa = _subdomains(audit, "v=DMARC1; p=none")

    assert sa["total_probed"] == len(sa["subdomains"]) > 0
    for row in sa["subdomains"]:
        assert row["exists"] is False
        assert row["status_label"] == "Does not exist", row
        assert row["status"] != "exposed"
        assert row["color"] != "red"
    # The header logic in app.js (_subdomainAuditSummary) counts rows that
    # exist and are exposed; the rows now agree with its "none exposed".
    exposed_rows = [r for r in sa["subdomains"] if r["status"] == "exposed"]
    exposed_header = [r for r in sa["subdomains"] if r["exists"] and r["status"] == "exposed"]
    assert exposed_rows == exposed_header == []
    assert not any("exposed" in line for line in sa["summary_lines"])


def test_a_name_that_exists_is_still_exposed_and_listed_first(audit):
    sa = _subdomains(audit, "v=DMARC1; p=none",
                     extra={f"support.{DOMAIN}": {"A": ["203.0.113.30"]}})

    first = sa["subdomains"][0]
    assert first["subdomain"] == f"support.{DOMAIN}"
    assert first["status_label"] == "Exposed"
    assert sum(1 for r in sa["subdomains"] if r["status"] == "exposed") == 1
    assert "1 existing subdomain exposed due to policy gaps" in sa["summary_lines"]


def test_without_any_dmarc_record_missing_names_still_do_not_exist(audit):
    zone = _zone("v=DMARC1; p=none", "v=spf1 mx -all", domain=DOMAIN)
    zone._records.pop((f"_dmarc.{DOMAIN}", "TXT"))
    sa = audit(zone, DOMAIN, dkim_selector="s1")["subdomain_audit"]

    assert {r["status_label"] for r in sa["subdomains"]} == {"Does not exist"}
