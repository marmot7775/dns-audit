"""An SPF record over the 10-lookup limit does not fail every message.

The deliverability summary, the plan row and the card said "None of your
mail passes SPF". A receiver evaluates the record left to right and returns
PermError at the 11th lookup, so mail that matches a mechanism earlier in the
record still passes. static/articles/spf-lookups.html says the same thing:
the order of the record decides which mail fails. The page now says "Some or
all of your mail fails SPF, depending on the order of the record."
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_verdict_names_broken_records import DOMAIN, RUA, _over_limit_spf, _zone

SENTENCE = "Some or all of your mail fails SPF, depending on the order of the record."
OVERCLAIMS = ("none of your mail passes spf", "none of the mail passes spf")


def _strings(result):
    es = result["executive_summary"]
    spf = {c["name"]: c for c in result["checks"]}["SPF"]
    rows = [i for i in result["security_roadmap"]["items"] if i["protocol"] == "SPF"]
    return {
        "deliverability": es["deliverability_summary"],
        "biggest_risk_detail": es["biggest_risk_detail"],
        "card": spf.get("deliverability") or "",
        "plan": " ".join(i.get("impact", "") for i in rows),
    }


def test_over_the_limit_says_some_or_all(audit):
    spf, includes = _over_limit_spf()
    result = audit(_zone(f"v=DMARC1; p=reject; {RUA}", spf, extra=includes),
                   DOMAIN, dkim_selector="s1")

    got = _strings(result)
    for where in ("deliverability", "biggest_risk_detail", "plan", "card"):
        assert SENTENCE in got[where], (where, got[where])
    for where, text in got.items():
        for claim in OVERCLAIMS:
            assert claim not in text.lower(), (where, text)


def test_the_article_agrees_that_order_decides():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "static", "articles", "spf-lookups.html"), encoding="utf-8") as fh:
        article = fh.read().lower()
    assert "the order of your record decides which sender breaks" in article
