"""vendor_patterns.py carries the patterns from Neil's sender discovery
vendors.json that it lacked (vendor gap report, step 5,
docs/history/vendor-gap-report.md). The vendors.json file itself stays in
Toolkit/templates: this repo is public and the file holds research notes.

SPF includes were added only where the host publishes a v=spf1 record on
2026-10-08; four that do not are pinned out here so a later sync cannot
bring them back unchecked.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vendor_patterns as vp  # noqa: E402


def test_the_added_patterns_name_their_vendors():
    assert vp.match_host("spf.ess.barracudanetworks.com", vp.SPF_INCLUDE_VENDORS) == "Barracuda"
    assert vp.match_host("ccsend.com", vp.SPF_INCLUDE_VENDORS) == "Constant Contact"
    assert vp.match_host("_spf.atlassian.net", vp.SPF_INCLUDE_VENDORS) == "Atlassian"
    assert vp.match_host("abc.eu.mx.microsoft", vp.MX_VENDORS) == "Microsoft 365"
    assert vp.match_host("pdk1._domainkey.abc.dkim1.mailgun.com", vp.DKIM_CNAME_VENDORS) == "Mailgun"
    assert vp.match_host("x.klaviyodns.com", vp.DKIM_CNAME_VENDORS) == "Klaviyo"
    assert vp.dkim_key_vendor("pdk1", None) == "Mailgun"
    assert vp.dkim_key_vendor("ga1", None) == "Google Workspace"


def test_hosts_with_no_spf_record_are_not_includes():
    for host in ("spf.barracudanetworks.com", "freshemail.io", "_spf.marketo.com", "_spf.intuit.com"):
        assert host not in vp.SPF_INCLUDE_VENDORS, host


def test_ordinary_words_and_generic_names_name_nobody():
    for name in ("wordpress", "shops", "mail", "default", "mg"):
        assert vp.dkim_key_vendor(name, None) is None, name


def test_a_zone_shared_by_a_product_suite_names_no_one_product():
    assert vp.match_host("x.freshemail.io", vp.DKIM_CNAME_VENDORS) is None


def test_one_host_names_one_vendor_across_the_tables():
    seen = {}
    for table in (vp.SPF_INCLUDE_VENDORS, vp.MX_VENDORS, vp.DKIM_CNAME_VENDORS):
        for host, vendor in table.items():
            if host in seen:
                assert seen[host] == vendor, (host, seen[host], vendor)
            seen[host] = vendor
