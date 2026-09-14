"""Doc 50 item 4: with Not checked shown, the five summary tiles share one row
at 820 (iPad) as they do at 1280, instead of the fifth dropping to a
full-width slab under the other four.
"""
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_ui_consistency_a11y import _page, _render, browser, fixture_result  # noqa: E402,F401

TOPS_JS = """() => [...document.querySelectorAll('.summary-card')]
    .filter(c => getComputedStyle(c).display !== 'none')
    .map(c => c.getBoundingClientRect().top)"""


@pytest.mark.parametrize("width", [820, 1280])
def test_five_summary_tiles_share_one_row(browser, fixture_result, width):
    data = copy.deepcopy(fixture_result)
    if not any(c["status"] == "unavailable" for c in data["checks"]):
        next(c for c in data["checks"] if c["status"] == "absent")["status"] = "unavailable"
    ctx, page, errors = _page(browser, "dark", width)
    try:
        _render(page, data)
        tops = page.evaluate(TOPS_JS)
        assert len(tops) == 5, tops
        assert max(tops) - min(tops) <= 2, (width, tops)
        assert errors == []
    finally:
        ctx.close()
