"""The Technical summary shortcuts land their panel below the sticky header.

openCard scrolls the element it is given. For "View Attack Surface" and
"Copy Recommended Record" that element sits inside a .result-card, and only
the card carried scroll-margin-top, so the panel aligned to the top of the
viewport under the sticky header. Reported by CodeRabbit on #214; the gap
was already on main.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_dmarc_grades import RUA, _run  # noqa: E402
from test_ui_consistency_a11y import _page, _render, browser  # noqa: E402,F401


@pytest.mark.parametrize("width", [1280, 375])
@pytest.mark.parametrize("dmarc,label,target", [
    (f"v=DMARC1; p=none; {RUA}", "View Attack Surface", "dmarc-attack-surface"),
    (None, "Copy Recommended Record", "dmarc-record-builder"),
])
def test_shortcut_target_clears_the_sticky_header(browser, audit, width, dmarc, label, target):  # noqa: F811
    data = json.loads(json.dumps(_run(audit, dmarc), default=str))
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, data)
        # Room below the results, so the scroll can carry the target all the
        # way up instead of stopping at the end of a short page.
        page.evaluate("() => { const d = document.createElement('div'); d.style.height = '4000px'; document.body.appendChild(d); }")
        page.click(".es-tech-toggle")
        btn = page.query_selector(f".es-action:text-is('{label}')")
        if btn is not None:
            btn.click()
        else:
            # Not offered as a summary button for this fixture; the plan row
            # reaches the same panel through openCard.
            assert page.query_selector(f"#{target}") is not None
            page.evaluate(f"() => openCard('{target}')")
        # openCard ends in scrollIntoView({block: 'start'}). Its smooth
        # animation races the panel opening in a headless run, so the same
        # call is made again without it, which is where a finished scroll
        # lands.
        page.wait_for_timeout(2000)
        page.evaluate(f"() => document.getElementById('{target}').scrollIntoView({{block: 'start'}})")
        page.wait_for_timeout(200)
        header = page.evaluate("() => document.querySelector('.site-header').getBoundingClientRect().bottom")
        top = page.evaluate(f"() => document.getElementById('{target}').getBoundingClientRect().top")
        assert top >= header - 1, (label, width, top, header)
        assert not errors, errors
    finally:
        ctx.close()
