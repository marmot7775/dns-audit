"""Doc 38 sections 7 and 8: four font weights, an unclipped logo, one PDF spacing scale."""
import mimetypes
import os
import re
import sys
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "static")


def _read(*parts):
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------
# Section 7: weight
# ---------------------------------------------------------------

def test_style_css_uses_exactly_four_font_weights_and_rations_600():
    weights = re.findall(r"font-weight:\s*([^;}\s]+)", _read("static", "style.css"))

    assert set(weights) == {"400", "500", "600", "700"}, sorted(set(weights))
    assert weights.count("600") < 60, (
        f"{weights.count('600')} declarations at 600: when almost everything is "
        "600, nothing is emphasized"
    )


# ---------------------------------------------------------------
# Section 8: the header logo is not clipped
# ---------------------------------------------------------------

def _serve_static(route):
    url = urlparse(route.request.url)
    if url.hostname != "dns-audit.test":
        return route.abort()
    path = url.path
    local = (os.path.join(REPO_ROOT, path.lstrip("/")) if path.startswith("/static/")
             else os.path.join(STATIC, "index.html") if path in ("", "/") else None)
    if not local or not os.path.isfile(local):
        return route.fulfill(status=404, body="")
    with open(local, "rb") as f:
        body = f.read()
    route.fulfill(status=200, body=body,
                  headers={"content-type": mimetypes.guess_type(local)[0] or "text/html"})


HEADER_JS = """() => {
    const box = el => el.getBoundingClientRect();
    const centre = el => box(el).top + box(el).height / 2;
    // A block has one client rect however many lines it wraps to, so lines
    // are counted from the rects of a range over its text.
    const lines = el => { const r = document.createRange(); r.selectNodeContents(el);
        return new Set([...r.getClientRects()].map(c => Math.round(c.top))).size; };
    // Baseline: top of the first text fragment plus the font's ascent.
    const baseline = el => {
        const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        let n; while ((n = walk.nextNode()) && !n.textContent.trim()) {}
        const r = document.createRange(); r.selectNodeContents(n);
        const cs = getComputedStyle(n.parentElement);
        const ctx = document.createElement('canvas').getContext('2d');
        ctx.font = `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
        return r.getClientRects()[0].top + ctx.measureText('x').fontBoundingBoxAscent;
    };
    const text = document.querySelector('.logo-text');
    const nav = [...document.querySelectorAll('.nav-link')];
    const inner = document.querySelector('.header-inner');
    return {
        scroll: [text.scrollWidth, text.clientWidth],
        rects: text.getClientRects().length,
        logoLines: lines(text),
        logoCentre: centre(text),
        navCentres: nav.map(centre),
        logoBaseline: baseline(text),
        navBaselines: nav.map(baseline),
        headerLeft: box(inner).left + parseFloat(getComputedStyle(inner).paddingLeft),
        logoLeft: box(text).left,
        cardLeft: box(document.querySelector('.audit-input-card')).left,
        titleLines: lines(document.querySelector('.audit-title')),
    };
}"""


def test_header_logo_text_is_not_clipped_in_a_browser():
    """Doc 50: one wordmark, on one line, centred on the nav, at the container edge."""
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # no browser build or missing system libraries
            pytest.skip(f"chromium is not available here: {exc}")
        try:
            for width in (1280, 390, 320):
                page = browser.new_page(viewport={"width": width, "height": 800})
                page.route("**/*", _serve_static)
                page.goto("http://dns-audit.test/")
                page.evaluate("document.fonts.ready")
                m = page.evaluate(HEADER_JS)
                assert m["scroll"][0] == m["scroll"][1], (width, m)
                assert m["rects"] == 1 and m["logoLines"] == 1, (width, m)
                for c in m["navCentres"]:
                    assert abs(m["logoCentre"] - c) <= 1, (width, m)
                for y in m["navBaselines"]:
                    assert abs(m["logoBaseline"] - y) <= 1, (width, m)
                if width == 1280:
                    assert m["headerLeft"] == m["cardLeft"] == m["logoLeft"], m
                    assert m["titleLines"] == 1, m
                if width == 390:
                    assert m["titleLines"] == 2, m
                page.close()
        finally:
            browser.close()


# ---------------------------------------------------------------
# Section 8: the PDF spacing scale
# ---------------------------------------------------------------

def test_every_pdf_spacer_uses_the_spacing_scale():
    import pdf_report

    heights = re.findall(r"Spacer\(\s*1\s*,\s*([^)]+)\)", _read("pdf_report.py"))
    assert heights
    off_scale = sorted({h.strip() for h in heights}
                       - {"SP_XS", "SP_SM", "SP_MD", "SP_LG", "SP_XL"})
    assert off_scale == [], f"Spacer heights off the scale: {off_scale}"
    assert (pdf_report.SP_XS, pdf_report.SP_SM, pdf_report.SP_MD,
            pdf_report.SP_LG, pdf_report.SP_XL) == (4, 8, 12, 18, 28)
