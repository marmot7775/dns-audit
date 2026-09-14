"""Doc 36: one header on every page.

The site header drifted: the homepage and the 404 page carried a plain
wordmark while the other six pages carried the terminal-window logo, a
different spelling and the accent on a different word. This test extracts
the <header> block from every static HTML page, strips the one permitted
per-page difference (which nav link carries nav-link-active) and asserts
that all eight blocks are byte-identical, so the header cannot drift again.
"""
import os
import re

import pytest

from static_pages import EXPECTED_PAGES, PAGES, STATIC

HEADER_RE = re.compile(r'<header class="site-header">.*?</header>', re.DOTALL)

# Doc 50: the Sept 9 wordmark, exactly.
WORDMARK = ('<a href="/" class="logo"><span class="logo-text">dns<span '
            'class="logo-accent">-audit</span>.com</span></a>')


def _header(path):
    with open(path, encoding="utf-8") as f:
        html = f.read()
    blocks = HEADER_RE.findall(html)
    assert len(blocks) == 1, f"{path}: expected exactly one site header, found {len(blocks)}"
    return blocks[0]


def _normalised(path):
    return _header(path).replace(" nav-link-active", "")


def test_every_static_page_is_covered():
    """Covers the footer test too: both read PAGES from static_pages."""
    assert {os.path.relpath(p, STATIC) for p in PAGES} == EXPECTED_PAGES


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_is_identical_to_about(path):
    reference = _normalised(os.path.join(STATIC, "about.html"))
    assert _normalised(path) == reference, (
        f"{os.path.relpath(path, STATIC)}: site header differs from about.html "
        "beyond the nav-link-active attribute"
    )


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_carries_the_wordmark(path):
    header = _header(path)
    with open(path, encoding="utf-8") as f:
        assert "logo-terminal" not in f.read(), "Doc 50 removed the terminal chip"
    assert WORDMARK in header
    assert '<div class="header-right">' in header
    assert '<nav class="site-nav" aria-label="Main navigation">' in header
    for label in ("Home", "Articles", "About"):
        assert re.search(rf'class="nav-link(?: nav-link-active)?">{label}</a>', header), label
    assert 'id="theme-toggle"' in header


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_at_most_one_active_nav_link(path):
    assert _header(path).count("nav-link-active") <= 1


def test_active_link_matches_the_page():
    expected = {
        "index.html": "Home",
        "about.html": "About",
        "articles/index.html": "Articles",
        "articles/dane.html": "Articles",
        "articles/dmarcbis.html": "Articles",
        "articles/dnssec.html": "Articles",
    }
    for rel, label in expected.items():
        header = _header(os.path.join(STATIC, rel))
        assert f'class="nav-link nav-link-active">{label}</a>' in header, rel


def _index():
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        return f.read()


def test_index_carries_the_sept9_title_and_sentence():
    html = _index()
    assert '<h1 class="audit-title">DNS &amp; Email Security Audit</h1>' in html
    assert ('<p class="audit-subtitle">Most DNS tools show you your records. This one tells '
            'you what is wrong with them. Includes <a href="/articles/dmarcbis" '
            'class="audit-subtitle-link">RFC 9989 readiness</a>, DNSSEC validation, and '
            'more.</p>') in html


def test_domain_input_is_autofocused():
    tag = re.search(r'<input[^>]*id="domain-input"[^>]*>', _index()).group(0)
    assert re.search(r'\sautofocus[\s/>]', tag), tag
    assert _index().count("autofocus") == 1


def test_scope_buttons_come_before_the_form():
    html = _index()
    assert html.index('class="scope-selector"') < html.index('<form id="audit-form"')
