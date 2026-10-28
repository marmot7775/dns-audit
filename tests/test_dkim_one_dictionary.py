"""The DKIM probe has one vendor dictionary: Sendermap's catalog (Doc 105).

Before, the audit probed from its own 1,130-name list, ordered by its own
vendor tables, beside the sender map probing Sendermap's. Now every name the
audit probes is in Sendermap's sweep, in LOCAL_SELECTORS (found in
production, waiting on a catalog entry) or in the generic fallback.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
from generic_selectors import GENERIC_SELECTORS, LOCAL_SELECTORS
from sendermap_adapter import catalog
from test_dkim_discovery_starvation import DKIM_RECORD
import spf_intelligence

DOMAIN = "one.test"


def _zone(keys=(), spf=None, mx=None):
    apex = {}
    if spf:
        apex["TXT"] = [spf]
    if mx:
        apex["MX"] = [(10, mx)]
    records = {DOMAIN: apex}
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    return FakeZone(records)


def _probe_order(zone):
    return [q[0].split("._domainkey.")[0] for q in zone.queries
            if "._domainkey." in q[0] and "_dkimwildcardtest" not in q[0]]


def _first_names(spf=None, mx=None):
    """The names a single-threaded probe asks first, in order."""
    from concurrent.futures import ThreadPoolExecutor

    zone = _zone(spf=spf, mx=mx)
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        with fake_dns(zone):
            spf_intelligence.smart_dkim_check(DOMAIN, spf, mx_hosts=[mx] if mx else [], executor=pool)
    finally:
        pool.shutdown(wait=True)
    return _probe_order(zone)


def test_no_name_is_probed_that_sendermap_does_not_know():
    zone = _zone()
    with fake_dns(zone):
        spf_intelligence.smart_dkim_check(DOMAIN, None, mx_hosts=[])
    probed = set(_probe_order(zone))
    known = {s.lower() for s in (*catalog().probe_selectors, *LOCAL_SELECTORS, *GENERIC_SELECTORS)}
    assert probed - known == set()
    # And the fallback ran, so this covered all three sources.
    assert "default" in probed and "sasl" in probed


def test_the_domains_own_mx_or_spf_vendor_goes_first():
    m365 = {s.lower() for s in catalog().selectors_of("Microsoft 365")}
    order = _first_names(mx="contoso-com.mail.protection.outlook.com")
    assert set(order[:len(m365)]) == m365, order[:5]

    sendgrid = {s.lower() for s in catalog().selectors_of("SendGrid")}
    order = _first_names(spf="v=spf1 include:sendgrid.net -all")
    assert set(order[:len(sendgrid)]) == sendgrid, order[:5]


def test_a_key_at_a_matched_rules_name_carries_that_vendor():
    zone = _zone(keys=("selector1", "default"),
                 mx="contoso-com.mail.protection.outlook.com")
    with fake_dns(zone):
        raw = spf_intelligence.smart_dkim_check(
            DOMAIN, None, mx_hosts=["contoso-com.mail.protection.outlook.com"])
    vendors = {s["selector"]: s["vendor"] for s in raw["found_selectors"]}
    assert vendors == {"selector1": "Microsoft 365", "default": None}
