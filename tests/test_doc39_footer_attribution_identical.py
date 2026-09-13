"""Doc 39: the footer line says what Neil does, and it is the same everywhere.

The footer on every page used to read "Built by Neil Anuskiewicz" with a
LinkedIn icon as the only hint that the link was a way to reach him. Doc 39
replaced it with one sentence naming the three things he helps with and a
plain text LinkedIn link. Eight pages carry the block, so a later edit to the
wording or the link could land on seven and miss one. This test reads every
.footer-attribution block and holds them byte-identical, and pins the facts
the doc asked for: the three services, one LinkedIn link, no icon, no email,
no mailto, and the results view's own closing line left as it was.
"""
import glob
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "static")

PAGES = sorted(
    glob.glob(os.path.join(STATIC, "*.html"))
    + glob.glob(os.path.join(STATIC, "articles", "*.html"))
)

ATTRIBUTION_RE = re.compile(r'<div class="footer-attribution">.*?</div>', re.DOTALL)
LINKEDIN = "https://www.linkedin.com/in/neilanuskiewicz/"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _attribution(path):
    blocks = ATTRIBUTION_RE.findall(_read(path))
    assert len(blocks) == 1, (
        f"{os.path.relpath(path, STATIC)}: expected exactly one "
        f".footer-attribution block, found {len(blocks)}"
    )
    return blocks[0]


def test_every_static_page_is_covered():
    names = {os.path.relpath(p, STATIC) for p in PAGES}
    assert names == {
        "404.html",
        "about.html",
        "index.html",
        "privacy.html",
        "articles/dane.html",
        "articles/dmarcbis.html",
        "articles/dnssec.html",
        "articles/index.html",
    }


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_footer_attribution_is_identical_to_index(path):
    reference = _attribution(os.path.join(STATIC, "index.html"))
    assert _attribution(path) == reference, (
        f"{os.path.relpath(path, STATIC)}: .footer-attribution differs from index.html"
    )


def test_footer_attribution_says_what_neil_does():
    block = _attribution(os.path.join(STATIC, "index.html"))
    assert block.startswith('<div class="footer-attribution">Built by Neil Anuskiewicz.')
    for service in ("email deliverability", "email security", "DNS"):
        assert service in block, service
    assert block.count("<a ") == 1
    assert f'href="{LINKEDIN}"' in block
    assert 'target="_blank"' in block and 'rel="noopener"' in block
    assert 'class="footer-link"' in block
    assert ">Contact me on LinkedIn</a>." in block
    assert "<svg" not in block
    assert "footer-linkedin" not in block
    assert 'href="mailto:' not in block
    assert "@" not in block
    assert "—" not in block and "--" not in block


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_no_email_address_or_mailto_anywhere(path):
    html = _read(path)
    assert 'href="mailto:' not in html, os.path.relpath(path, STATIC)


def test_results_contact_note_is_unchanged():
    """Doc 39 left the results view's closing line alone."""
    index = _read(os.path.join(STATIC, "index.html"))
    assert '<p class="results-contact-note is-hidden" id="results-contact-note"></p>' in index
    app_js = _read(os.path.join(STATIC, "app.js"))
    assert "function _renderContactNote(failCount, warnCount)" in app_js
    assert "Message me on LinkedIn</a>." in app_js
    assert 'href="mailto:' not in app_js
