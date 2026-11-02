"""SPF vendor coverage counts only includes that authorize (issue 268).

The vendor coverage walk counted every include it could reach as authorizing
a sender, "-include:" and "~include:" terms and anything after "all" among
them. RFC 7208 section 5.2: an include's match takes the term's qualifier, so
a negative one rejects what the included record lists. Section 4.6.4 and 5.1:
terms after "all" are never evaluated. Only "+" includes reached before "all"
count as coverage.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import spf_recursive  # noqa: E402

PROTON = "_spf.protonmail.ch"


def _zone(domain, spf, extra=None):
    zone = {
        domain: {"TXT": [spf], "MX": [(10, "mail.protonmail.ch"), (20, "mailsec.protonmail.ch")],
                 "A": ["203.0.113.1"]},
        "_dmarc." + domain: {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{domain}"]},
        PROTON: {"TXT": ["v=spf1 ip4:185.70.40.0/24 ~all"]},
    }
    zone.update(extra or {})
    return zone


def _fix(audit, zone, domain):
    result = audit(zone, domain, scope="email_security")
    card = next(c for c in result["checks"] if c["name"] == "SPF")
    return card.get("fix") or ""


def _asks_for_proton(fix):
    """The card names Proton Mail as not covered by the record. The zone's MX
    is Proton's, so the card words it as the conditional note (issue 270);
    either wording means the record was judged not to cover it."""
    return "Proton Mail" in fix and f"include:{PROTON}" in fix


def test_a_positive_nested_include_covers_the_vendor(audit):
    domain = "pos.test"
    zone = _zone(domain, "v=spf1 include:wrap.test -all",
                 {"wrap.test": {"TXT": [f"v=spf1 include:{PROTON} ~all"]}})
    assert not _asks_for_proton(_fix(audit, zone, domain))


def test_a_negatively_qualified_nested_include_does_not_cover_the_vendor(audit):
    domain = "neg.test"
    zone = _zone(domain, "v=spf1 include:wrap.test -all",
                 {"wrap.test": {"TXT": [f"v=spf1 -include:{PROTON} ~all"]}})
    assert _asks_for_proton(_fix(audit, zone, domain))


def test_an_include_placed_after_all_does_not_cover_the_vendor(audit):
    domain = "late.test"
    zone = _zone(domain, f"v=spf1 ip4:203.0.113.0/24 -all include:{PROTON}")
    assert _asks_for_proton(_fix(audit, zone, domain))


def test_a_negative_top_level_include_does_not_cover_the_vendor(audit):
    domain = "top.test"
    zone = _zone(domain, f"v=spf1 ip4:203.0.113.0/24 ~include:{PROTON} -all")
    assert _asks_for_proton(_fix(audit, zone, domain))


def test_the_walk_marks_everything_below_a_negative_include(audit, monkeypatch):
    zone = {
        "root.test": {"TXT": ["v=spf1 include:a.test -include:b.test -all"]},
        "a.test": {"TXT": ["v=spf1 include:deep-a.test ~all"]},
        "deep-a.test": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
        "b.test": {"TXT": ["v=spf1 include:deep-b.test ~all"]},
        "deep-b.test": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
    }
    from conftest import FakeZone, fake_dns
    with fake_dns(FakeZone(zone)):
        result = spf_recursive.count_spf_lookups("root.test")
    authorizing = {e["domain"]: e["authorizing"] for e in result["chain"]}
    assert authorizing == {"root.test": True, "a.test": True, "deep-a.test": True,
                           "b.test": False, "deep-b.test": False}
    # A negative include still costs lookups: it is evaluated.
    assert result["total_lookups"] == 4


def test_tree_names_skip_negative_and_post_all_terms():
    record = "v=spf1 include:ok.test -include:no.test ~include:soft.test -all include:late.test"
    chain = [{"domain": "x.test"}, {"domain": "ok.test"},
             {"domain": "no.test", "authorizing": False},
             {"domain": "under-no.test", "authorizing": False}]
    names = audit_engine._spf_tree_names(record, {"chain": chain})
    assert names == {"ok.test"}
