"""Markup that passed the W3C Nu checker with no messages and axe-core with
no violations on 2026-10-09, kept that way.

- No trailing slash on void elements (the checker's info note).
- No section without a heading (its warning): the homepage loader and each
  article's opening section are divs.
- The homepage results heading is an h1 with text before results arrive, so
  the results view always has a level one heading and it is never empty.
- A code block that can scroll sideways on a phone is focusable, so a
  keyboard can scroll it (axe scrollable-region-focusable).
"""
import glob
import os
import re

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
PAGES = sorted(glob.glob(os.path.join(STATIC, "*.html")) + glob.glob(os.path.join(STATIC, "articles", "*.html")))


def _html_outside_svg(path):
    s = open(path, encoding="utf-8").read()
    return re.sub(r"<svg\b.*?</svg>", "", s, flags=re.S)


def test_no_void_element_has_a_trailing_slash():
    for path in PAGES:
        bad = re.findall(r"<(?:meta|link|img|br|input|hr|source)\b[^<>]*/>", _html_outside_svg(path))
        assert not bad, (os.path.relpath(path, STATIC), bad[:2])


def test_every_section_has_a_heading():
    for path in PAGES:
        for body in re.findall(r"<section\b[^>]*>(.*?)</section>", _html_outside_svg(path), re.S):
            assert re.search(r"<h[1-6]\b", body), (os.path.relpath(path, STATIC), body[:80])


def test_the_results_heading_is_a_nonempty_h1():
    s = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    assert re.search(r'<h1 class="domain-name" id="result-domain">[^<]+</h1>', s)


def test_article_code_blocks_are_focusable():
    for path in glob.glob(os.path.join(STATIC, "articles", "*.html")):
        for tag in re.findall(r"<pre\b[^>]*>", open(path, encoding="utf-8").read()):
            assert 'tabindex="0"' in tag, (os.path.relpath(path, STATIC), tag)
