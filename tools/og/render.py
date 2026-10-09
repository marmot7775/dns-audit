"""Render a 1200x630 link preview card from its HTML source: render.py SRC OUT."""
import pathlib
import sys

from playwright.sync_api import sync_playwright

src, out = (pathlib.Path(a).resolve() for a in sys.argv[1:3])
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1200, "height": 630})
    page.goto(src.as_uri())
    page.evaluate("document.fonts.ready")
    page.screenshot(path=str(out))
    browser.close()
