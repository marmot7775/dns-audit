"""The requirement row's "See who sends as you" button is a 44px target on mobile.

CLAUDE.md: all touch targets 44px minimum on mobile. The .req-link button
had no padding and no hit area, so at 360px it was 18px tall. It now gets
an ::after box, the footer attribution links' pattern, inside the mobile
media query.
"""
import pytest

from test_visual_system import _serve_static, browser  # noqa: F401

ROW = """() => {
    const host = document.createElement('div');
    host.style.cssText = 'margin: 120px 16px; position: relative; z-index: 10';
    host.innerHTML = '<div class="req-row"><div class="req-text"><div class="req-label">'
        + 'Mailbox providers ask for this <button type="button" class="req-link" '
        + 'data-req-scope="senders">See who sends as you</button></div></div></div>';
    document.body.prepend(host);
    const b = host.querySelector('button.req-link');
    const r = b.getBoundingClientRect();
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    const hits = [-21, 21].map(dy => document.elementFromPoint(cx, cy + dy) === b);
    return {height: r.height, hits};
}"""


@pytest.mark.parametrize("width", [360, 390])
def test_req_link_hit_area_is_44px_tall_on_mobile(browser, width):  # noqa: F811
    page = browser.new_page(viewport={"width": width, "height": 800}, has_touch=True)
    try:
        page.route("**/*", _serve_static)
        page.goto("http://dns-audit.test/")
        m = page.evaluate(ROW)
        assert m["height"] < 44, "the face itself stays text-sized; the hit area does the work"
        assert m["hits"] == [True, True], m
    finally:
        page.close()
