"""The RFC 7489 / RFC 9989 switch on the DMARC card fits its bar at 320px.

Below 640px the switch had a fixed 220px minimum width. At 320px the bar
it sits in is about 195px wide, so the switch ran 25px past it, into the
Details panel's padding. Nothing was clipped, which is why the Details fit
test did not see it. The minimum is now capped at the bar's width.

Uses the saved live audits from the Details fit test.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_ui_consistency_a11y import (  # noqa: F401
    _page,
    _render,
    browser,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "details_width")
DOMAINS = ["github.com", "paypal.com", "bbc.co.uk", "ietf.org"]

MEASURE_JS = r"""() => {
    document.querySelectorAll('.result-card').forEach(c => setCardExpanded(c, true));
    document.querySelectorAll('.result-card .cd-body.is-hidden').forEach(b => b.classList.remove('is-hidden'));
    const group = document.querySelector('.st-seg-group');
    if (!group) return null;
    const bar = group.closest('.st-toggle-bar');
    const cs = getComputedStyle(bar);
    const b = bar.getBoundingClientRect();
    const g = group.getBoundingClientRect();
    return {
        left: g.left - (b.left + parseFloat(cs.borderLeftWidth) + parseFloat(cs.paddingLeft)),
        right: (b.right - parseFloat(cs.borderRightWidth) - parseFloat(cs.paddingRight)) - g.right,
        labels: [...group.querySelectorAll('.st-seg')].map(s => ({
            text: s.textContent,
            fits: s.scrollWidth <= s.clientWidth,
            height: s.getBoundingClientRect().height,
        })),
    };
}"""


@pytest.mark.parametrize("domain", DOMAINS)
def test_rfc_toggle_sits_inside_its_bar_at_320(browser, domain):  # noqa: F811
    with open(os.path.join(FIXTURES, domain + ".json")) as f:
        data = json.load(f)
    ctx, page, errors = _page(browser, "dark", 320)
    try:
        _render(page, data)
        m = page.evaluate(MEASURE_JS)
        assert m is not None, "no RFC toggle on the DMARC card"
        assert m["left"] >= -0.5, f"switch starts {-m['left']:.1f}px before its bar"
        assert m["right"] >= -0.5, f"switch runs {-m['right']:.1f}px past its bar"
        assert [lab["text"] for lab in m["labels"]] == ["RFC 7489", "RFC 9989"]
        for lab in m["labels"]:
            assert lab["fits"], f"{lab['text']} is cut inside its button"
            assert lab["height"] >= 44
        assert errors == []
    finally:
        ctx.close()
