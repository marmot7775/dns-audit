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
             else os.path.join(STATIC, "index.html") if path in ("", "/")
             else os.path.join(STATIC, "articles", "index.html") if path.rstrip("/") == "/articles"
             else os.path.join(STATIC, path.lstrip("/") + ".html") if path.startswith("/articles/")
             else None)
    if not local or not os.path.isfile(local):
        return route.fulfill(status=404, body="")
    with open(local, "rb") as f:
        body = f.read()
    route.fulfill(status=200, body=body,
                  headers={"content-type": mimetypes.guess_type(local)[0] or "text/html"})


HEADER_JS = """() => {
    const text = document.querySelector('.logo-text');
    // A blockified span has one client rect however many lines it wraps to,
    // so lines are also counted from the rects of a range over its text.
    const r = document.createRange(); r.selectNodeContents(text);
    return {
        rects: text.getClientRects().length,
        lines: new Set([...r.getClientRects()].map(c => Math.round(c.top))).size,
        scroll: [text.scrollWidth, text.clientWidth],
    };
}"""


def test_header_logo_text_is_not_clipped_in_a_browser():
    """Doc 50: the wordmark is one unclipped line at 1280, 390 and 320."""
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
                assert m["rects"] == 1 and m["lines"] == 1, (width, m)
                assert m["scroll"][0] == m["scroll"][1], (width, m)
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


# ---------------------------------------------------------------
# Doc 53: one focus ring in both themes, one pulse when the page opens
# ---------------------------------------------------------------

# Records when .input-wrapper gains and loses the hello class, relative to
# DOMContentLoaded, so the timing can be read after the fact.
HELLO_JS = """(() => {
    window.__hello = {dcl: null, added: null, removed: null};
    document.addEventListener('DOMContentLoaded', () => {
        window.__hello.dcl = performance.now();
        const w = document.querySelector('.input-wrapper');
        new MutationObserver(() => {
            const on = w.classList.contains('input-wrapper-hello');
            if (on && window.__hello.added === null) window.__hello.added = performance.now();
            if (!on && window.__hello.added !== null && window.__hello.removed === null)
                window.__hello.removed = performance.now();
        }).observe(w, {attributes: true, attributeFilter: ['class']});
    }, true);
})();"""


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # no browser build or missing system libraries
            pytest.skip(f"chromium is not available here: {exc}")
        yield b
        b.close()


def _open(browser, theme, path="/", **ctx_kwargs):
    ctx = browser.new_context(viewport={"width": 1280, "height": 800}, **ctx_kwargs)
    ctx.add_init_script(f"try{{localStorage.setItem('theme','{theme}')}}catch(e){{}}")
    ctx.add_init_script(HELLO_JS)
    page = ctx.new_page()
    page.route("**/*", _serve_static)
    page.goto("http://dns-audit.test" + path)
    return ctx, page


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_field_pulses_once_when_the_page_opens(browser, theme):
    ctx, page = _open(browser, theme)
    page.wait_for_timeout(2500)
    h = page.evaluate("window.__hello")
    ctx.close()

    assert h["added"] is not None, "the hello class was never added"
    assert h["added"] - h["dcl"] < 100, h
    assert h["removed"] is not None and h["removed"] - h["added"] < 2000, h


def test_a_shared_result_link_does_not_pulse(browser):
    ctx, page = _open(browser, "dark", path="/?d=example.com")
    page.wait_for_timeout(1500)
    h = page.evaluate("window.__hello")
    ctx.close()

    assert h["added"] is None, h


def test_reduced_motion_gets_no_pulse(browser):
    ctx, page = _open(browser, "dark", reduced_motion="reduce")
    page.wait_for_timeout(300)
    name = page.evaluate("getComputedStyle(document.querySelector('.input-wrapper')).animationName")
    ctx.close()

    assert name == "none", name


def test_the_focus_ring_is_the_primary_token_in_both_themes(browser):
    """Doc 53 asked for the same colour in both themes. --primary itself
    differs by theme (#5b8def dark, #2f5fcc light), so the assertion is that
    both themes draw the focused border from that one token."""
    seen = {}
    for theme in ("dark", "light"):
        ctx, page = _open(browser, theme)
        page.wait_for_timeout(1500)
        seen[theme] = page.evaluate("""() => {
            const w = document.querySelector('.input-wrapper');
            const probe = document.createElement('div');
            probe.style.color = 'var(--primary)';
            document.body.appendChild(probe);
            return {
                focused: document.activeElement.id,
                border: getComputedStyle(w).borderTopColor,
                primary: getComputedStyle(probe).color,
            };
        }""")
        ctx.close()

    for theme, m in seen.items():
        assert m["focused"] == "domain-input", (theme, m)
        assert m["border"] == m["primary"], (theme, m)


# ---------------------------------------------------------------
# Doc 58: no article page scrolls sideways on a phone
# ---------------------------------------------------------------

ARTICLE_PATHS = ["/articles", "/articles/dmarcbis", "/articles/dnssec", "/articles/dane"]

OVERFLOW_JS = """() => {
    const vw = window.innerWidth;
    const over = [...document.querySelectorAll('body *')]
        .filter(el => !el.closest('.dbis-table-fig'))
        .filter(el => el.getBoundingClientRect().right > vw + 1)
        .map(el => el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).split(' ').join('.') : '')
             + ' ' + Math.round(el.getBoundingClientRect().right));
    return {vw, scroll: document.documentElement.scrollWidth, over: over.slice(0, 10)};
}"""


@pytest.mark.parametrize("width", [375, 390])
@pytest.mark.parametrize("path", ARTICLE_PATHS)
def test_article_pages_do_not_scroll_sideways_on_a_phone(browser, path, width):
    """Doc 58: at 375 and 390 wide, /articles/dmarcbis was 519px wide. Long
    inline code now wraps, and the changes table scrolls inside its figure."""
    ctx = browser.new_context(viewport={"width": width, "height": 800})
    page = ctx.new_page()
    page.route("**/*", _serve_static)
    page.goto("http://dns-audit.test" + path)
    page.wait_for_load_state("load")
    m = page.evaluate(OVERFLOW_JS)
    ctx.close()

    assert m["scroll"] == width, m
    assert m["over"] == [], m
