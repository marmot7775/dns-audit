"""The vendor panel names the records a sender's own setup docs require that
the audit checked for and did not find (vendor gap report, step 8,
docs/history/vendor-gap-report.md), and stays silent on anything it could
not check."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_engine import _vendor_missing_records  # noqa: E402

M365_SPF = "v=spf1 include:spf.protection.outlook.com -all"


def _vendor(name, tier="In use", sources=("MX",), role="sender"):
    return {"name": name, "tier": tier, "sources": list(sources), "role": role}


def _raw(spf=M365_SPF, answered=("selector1", "selector2"), keys=(), **dkim):
    return {"spf": {"record": spf},
            "dkim": {"answered_selectors": list(answered), "found_selectors": list(keys), **dkim}}


def _run(vendor, raw):
    _vendor_missing_records([vendor], raw)
    return vendor["missing"]


def test_m365_in_mx_with_no_key_at_either_selector():
    assert _run(_vendor("Microsoft 365"), _raw()) == [
        "No DKIM key from Microsoft 365. Nothing is published at selector1 or selector2."]


def test_m365_missing_from_spf():
    out = _run(_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")), _raw(spf="v=spf1 -all"))
    assert out == ["Not in your SPF record. Microsoft 365 asks for include:spf.protection.outlook.com."]


def test_no_spf_record_at_all_is_left_to_the_spf_card():
    assert _run(_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")), _raw(spf="")) == []


def test_spf_lookup_unavailable_says_nothing():
    raw = _raw(spf="v=spf1 -all")
    raw["spf"]["status"] = "unavailable"
    assert _run(_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")), raw) == []


def test_a_vendor_key_found_is_not_missing():
    assert _run(_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")), _raw()) == []


def test_a_selector_the_scan_never_answered_is_not_checked():
    assert _run(_vendor("Microsoft 365"), _raw(answered=("selector1",))) == []


def test_no_answered_list_means_not_checked():
    # A selector typed by the user runs the direct path, which records none.
    assert _run(_vendor("Microsoft 365"), _raw(answered=())) == []


def test_wildcard_timeout_and_unavailable_say_nothing():
    for flag in ({"wildcard_detected": True}, {"timed_out": True}, {"status": "unavailable"}):
        assert _run(_vendor("Microsoft 365"), _raw(**flag)) == [], flag


def test_a_dangling_vendor_selector_is_left_to_the_dkim_card():
    raw = _raw(dangling_selectors=[{"selector": "selector1", "status": "microsoft_unfilled"}])
    assert _run(_vendor("Microsoft 365"), raw) == []


def test_an_unattributed_live_key_may_be_the_vendors():
    key = {"selector": "default", "record": "v=DKIM1; k=rsa; p=MIIB"}
    assert _run(_vendor("Microsoft 365"), _raw(keys=[key])) == []


def test_a_key_attributed_to_another_vendor_does_not_block_the_check():
    key = {"selector": "google", "record": "v=DKIM1; k=rsa; p=MIIB", "vendor": "Google Workspace"}
    assert _run(_vendor("Microsoft 365"), _raw(keys=[key])) == [
        "No DKIM key from Microsoft 365. Nothing is published at selector1 or selector2."]


def test_per_account_selectors_are_never_flagged():
    # Google Workspace lets the customer name the selector.
    assert _run(_vendor("Google Workspace", sources=("SPF", "MX")),
                _raw(spf="v=spf1 include:_spf.google.com -all", answered=("google",))) == []


def test_likely_account_and_reporting_vendors_are_skipped():
    for v in (_vendor("Microsoft 365", tier="Likely", sources=("DKIM",)),
              _vendor("Microsoft 365", tier="Account only", sources=("TXT",), role="account"),
              _vendor("Mailchimp", tier="Account only", sources=("DMARC reports",), role="reporting")):
        assert _run(v, _raw(spf="v=spf1 -all", answered=("selector1", "selector2", "k2", "k3"))) == []


def test_configured_esp_without_its_key():
    v = _vendor("Mailchimp", tier="Configured", sources=("return path CNAME",))
    assert _run(v, _raw(answered=("k2", "k3"))) == [
        "No DKIM key from Mailchimp. Nothing is published at k2 or k3."]


def test_every_vendor_gets_a_missing_list():
    vs = [_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")),
          _vendor("DMARCian", tier="Account only", sources=("DMARC reports",), role="reporting")]
    _vendor_missing_records(vs, _raw())
    assert all(v["missing"] == [] for v in vs)


def test_full_audit_m365_mailbox_domain_without_dkim():
    """End to end: MX at Microsoft 365, SPF names it, no selector1 or
    selector2 published. The panel says the key is missing; SPF is fine."""
    from conftest import FakeZone, fake_dns
    import audit_engine

    d = "m365nokey.test"
    zone = FakeZone({
        d: {"MX": [(0, "m365nokey-test.mail.protection.outlook.com")],
            "TXT": [M365_SPF], "A": ["203.0.113.80"], "NS": [f"ns1.{d}"]},
        f"_dmarc.{d}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{d}"]},
        f"ns1.{d}": {"A": ["203.0.113.53"]},
    })
    with fake_dns(zone):
        result = audit_engine.run_full_audit(d, scope="complete")
    m365 = next(v for v in result["vendors"] if v["name"] == "Microsoft 365")
    assert m365["tier"] == "In use"
    assert m365["missing"] == [
        "No DKIM key from Microsoft 365. Nothing is published at selector1 or selector2."]


def test_a_vendor_seen_only_by_tracking_or_bounce_cname_needs_no_apex_include():
    # allbirds.com: a Mailgun tracking CNAME, no Mailgun include, and the
    # sending happens on the CNAMEd subdomain.
    for sources in (("tracking CNAME",), ("return path CNAME",), ("tracking CNAME", "return path CNAME")):
        v = _vendor("Mailgun", tier="Configured", sources=sources)
        assert _run(v, _raw(spf="v=spf1 -all", answered=())) == [], sources


def test_the_spf_card_follows_the_same_rule():
    from audit_engine import _needs_apex_spf_include
    assert not _needs_apex_spf_include(_vendor("Mailgun", tier="Configured", sources=("tracking CNAME",)))
    assert _needs_apex_spf_include(_vendor("Mailgun", tier="Configured", sources=("DKIM CNAME", "tracking CNAME")))
    assert not _needs_apex_spf_include(_vendor("Mailchimp", tier="Account only", sources=("DMARC reports",), role="reporting"))


def test_an_spf_tree_with_an_unread_branch_says_nothing_about_spf():
    raw = _raw(spf="v=spf1 include:_spf.example.net -all")
    raw["spf"]["spf_indeterminate"] = True
    assert _run(_vendor("Microsoft 365", sources=("MX", "DKIM CNAME")), raw) == []


def test_a_selector_probe_that_failed_is_not_answered(monkeypatch):
    """SERVFAIL at selector1 and selector2: tested, as before, but not
    answered, so the panel cannot call the Microsoft 365 key missing."""
    import dns.resolver
    import spf_intelligence

    class _Resolver:
        lifetime = 3

        def resolve(self, name, rdtype="A", *a, **k):
            if name.startswith(("selector1.", "selector2.")):
                raise dns.resolver.NoNameservers()
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(spf_intelligence, "get_uncached_resolver", lambda *a, **k: _Resolver())
    raw = spf_intelligence.smart_dkim_check("fail.test", "v=spf1 include:spf.protection.outlook.com -all")
    assert "selector1" not in raw["answered_selectors"]
    assert "selector2" not in raw["answered_selectors"]
    assert raw["answered_selectors"], "the NXDOMAIN probes still count as answered"
    assert raw["tested_count"] >= len(raw["answered_selectors"]) + 2


def test_hosted_spf_or_a_macro_include_says_nothing_about_spf():
    # glossier.com: only a Valimail macro include, which can cover Google.
    for spf in ("v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all",
                "v=spf1 include:acme.test.smart.ondmarc.com ~all",
                "v=spf1 include:%{ir}.%{v}._spf.example.net ~all"):
        assert _run(_vendor("Google Workspace", sources=("MX", "DKIM")), _raw(spf=spf, answered=())) == [], spf


def test_klaviyo_kl_keys_are_klaviyos_not_sendgrids():
    import vendor_patterns as vp
    for sel in ("kl", "kl2"):
        target = f"{sel}.domainkey.u161779.wl030.sendgrid.net"
        assert vp.dkim_key_vendor(sel, target, None, [target]) == "Klaviyo"
    # Any other SendGrid account is still SendGrid.
    assert vp.dkim_key_vendor("s1", "s1.domainkey.u1234.wl001.sendgrid.net", None, None) == "SendGrid"


def test_klaviyo_selectors_are_all_probed_every_audit():
    from comprehensive_selectors import ESP_SELECTORS
    from vendor_patterns import VENDOR_DKIM_SELECTORS
    assert set(VENDOR_DKIM_SELECTORS["Klaviyo"]) <= set(ESP_SELECTORS)
