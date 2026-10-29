"""Doc 36: one header on every page.

The site header drifted: the homepage and the 404 page carried a plain
wordmark while the other six pages carried the terminal-window logo, a
different spelling and the accent on a different word. This test extracts
the <header> block from every static HTML page, strips the one permitted
per-page difference (which nav link carries nav-link-active) and asserts
that all eight blocks are byte-identical, so the header cannot drift again.

Doc 105: the nav is the canonical copy for all three apps. Tools first
(DNS Audit, Header Decoder, APRF Reader), a divider, then Articles and
About. Every href is absolute, and the active link also carries
aria-current="page", which the normalisation strips with the class.
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
    return _header(path).replace(" nav-link-active", "").replace(' aria-current="page"', "")


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
    for label in ("DNS Audit", "Header Decoder", "APRF Reader"):
        assert re.search(rf'class="nav-link(?: nav-link-active" aria-current="page)?"[^>]*>'
                         rf'<span class="nav-long">{label}</span>', header), label
    for label in ("Articles", "About"):
        assert re.search(rf'class="nav-link(?: nav-link-active" aria-current="page)?">{label}</a>',
                         header), label
    assert ">Home<" not in header
    assert '<span class="nav-sep" aria-hidden="true"></span>' in header
    assert header.index("APRF Reader") < header.index("nav-sep") < header.index(">Articles<")
    assert 'id="theme-toggle"' in header


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_at_most_one_active_nav_link(path):
    header = _header(path)
    assert header.count("nav-link-active") <= 1
    assert header.count('aria-current="page"') == header.count("nav-link-active")


def test_active_link_matches_the_page():
    expected = {
        "index.html": "DNS Audit",
        "about.html": "About",
        "articles/index.html": "Articles",
        "articles/dane.html": "Articles",
        "articles/dmarcbis.html": "Articles",
        "articles/dnssec.html": "Articles",
        "articles/spf-lookups.html": "Articles",
        "articles/p-reject.html": "Articles",
        "articles/postmaster-tools.html": "Articles",
        "articles/aprf.html": "Articles",
    }
    for rel, label in expected.items():
        header = _header(os.path.join(STATIC, rel))
        active = re.search(r'<a [^>]*class="nav-link nav-link-active" aria-current="page"[^>]*>(.*?)</a>',
                           header)
        assert active, rel
        assert re.sub(r'<span class="nav-short">.*?</span>|<[^>]+>', "", active.group(1)) == label, rel
    for rel in ("privacy.html", "404.html"):
        assert "nav-link-active" not in _header(os.path.join(STATIC, rel)), rel


def _index():
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        return f.read()


def test_index_carries_the_senders_title_and_sentence():
    # 2026-10-25: the home page asks the sender's question.
    html = _index()
    assert '<h1 class="audit-title">Will your email reach the inbox?</h1>' in html
    assert ('<p class="audit-subtitle">Enter a domain. See what Gmail, Yahoo, and Microsoft '
            'will check, which services send as you, and the exact record to paste for '
            'each fix.</p>') in html


def test_domain_input_is_autofocused():
    tag = re.search(r'<input[^>]*id="domain-input"[^>]*>', _index()).group(0)
    assert re.search(r'\sautofocus[\s/>]', tag), tag
    assert _index().count("autofocus") == 1


def test_scope_buttons_come_before_the_form():
    html = _index()
    assert html.index('class="scope-selector"') < html.index('<form id="audit-form"')


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_links_to_the_header_decoder(path):
    """The sister tool lives on its own subdomain; every page links to it."""
    assert ('<a href="https://headers.dns-audit.com/" class="nav-link" rel="noopener" '
            'aria-label="Header Decoder"><span class="nav-long">Header Decoder</span>'
            '<span class="nav-short">Headers</span></a>') in _header(path)


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_header_links_to_the_aprf_reader(path):
    """The APRF Report Reader lives on its own subdomain; every page links to it."""
    assert ('<a href="https://aprf.dns-audit.com/" class="nav-link" rel="noopener" '
            'aria-label="APRF Reader"><span class="nav-long">APRF Reader</span>'
            '<span class="nav-short">APRF</span></a>') in _header(path)
