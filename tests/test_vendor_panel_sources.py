"""The vendor panel names every signal it counts, and a reporting service
is not shown as a sender.

_VENDOR_SOURCES named only SPF, MX, DKIM and TXT. A vendor found only as a
DMARC report address (ag.dmarcian.com) appeared as "DMARCian 90" with no
source and "Detected via DNS records", reading as something that sends the
domain's mail. A DKIM key hosted by the vendor through a CNAME printed the
same "DKIM" as a key known only by its selector name. And the fingerprinter
probed A records at bounce, autodiscover and email and read the TXT TTL for
made up vendors that always fell under the 0.5 cutoff.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
from advanced_fingerprinting import AdvancedVendorFingerprinter  # noqa: E402

DOMAIN = "panel.test"


def _panel(**prefetch):
    base = {"spf_record": None, "mx_hosts": [], "dmarc_record": None,
            "tls_rpt_record": None, "apex_txt": [], "dkim_selectors": []}
    base.update(prefetch)
    fp = AdvancedVendorFingerprinter(DOMAIN, prefetch=base)
    return audit_engine._format_vendors(fp.fingerprint_all()["vendors"])


def test_a_report_address_alone_is_a_reporting_service():
    out = _panel(spf_record="v=spf1 include:_spf.google.com ~all",
                 dmarc_record="v=DMARC1; p=none; rua=mailto:x@ag.dmarcian.com")
    assert [v["name"] for v in out] == ["Google Workspace", "DMARCian"]
    dmarcian = out[1]
    assert dmarcian["role"] == "reporting"
    assert dmarcian["sources"] == ["DMARC reports"]
    assert out[0]["role"] == "sender"


def test_a_sender_that_also_takes_reports_stays_a_sender():
    out = _panel(spf_record="v=spf1 include:pphosted.com ~all",
                 dmarc_record="v=DMARC1; p=reject; rua=mailto:x@emaildefense.proofpoint.com")
    [pp] = out
    assert pp["role"] == "sender"
    assert pp["sources"] == ["SPF", "DMARC reports"]


def test_tls_rpt_is_named():
    out = _panel(tls_rpt_record="v=TLSRPTv1; rua=mailto:t@ag.dmarcian.com")
    assert out[0]["sources"] == ["TLS-RPT reports"] and out[0]["role"] == "reporting"


def test_a_cname_hosted_key_is_labelled_dkim_cname():
    out = _panel(dkim_selectors=[{"selector": "k1", "cname_target": "dkim.mcsv.net"}])
    assert out[0]["sources"] == ["DKIM CNAME"]
    out = _panel(dkim_selectors=[{"selector": "k1"}])
    assert out[0]["sources"] == ["DKIM"]


def test_the_fingerprinter_makes_no_dns_query_with_prefetch():
    class NoDns:
        def resolve(self, *a, **k):
            raise AssertionError(f"queried {a}")
    fp = AdvancedVendorFingerprinter(DOMAIN, prefetch={
        "spf_record": None, "mx_hosts": [], "dmarc_record": None,
        "tls_rpt_record": None, "apex_txt": [], "dkim_selectors": []})
    fp._resolver = NoDns()
    assert fp.fingerprint_all() == {"vendors": []}
