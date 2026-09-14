"""Doc 39: the footer line says what Neil does, and it is the same everywhere.

The footer on every page used to read "Built by Neil Anuskiewicz" with a
LinkedIn icon as the only hint that the link was a way to reach him. Doc 39
replaced it with one sentence naming the three things he helps with and a
plain text LinkedIn link. Eight pages carry the block, so a later edit to the
wording or the link could land on seven and miss one. This test reads every
.footer-attribution block and holds them byte-identical, and pins the facts
the doc asked for: the three services, one LinkedIn link, no icon, no email,
no mailto, and the results view's own closing line left as it was.

Doc 41 added one mailto to the contact alias beside the LinkedIn link, in the
footer and in the results note, so the pinned facts below follow Doc 41. The
identical-footer check is unchanged.
"""
import os
import re

import pytest

from static_pages import PAGES, STATIC

ATTRIBUTION_RE = re.compile(r'<div class="footer-attribution">.*?</div>', re.DOTALL)
LINKEDIN = "https://www.linkedin.com/in/neilanuskiewicz/"
ALIAS = "dns" + "@" + "dns-audit" + ".com"
ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+")


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
    assert block.count("<a ") == 2
    assert f'href="{LINKEDIN}"' in block
    assert 'target="_blank"' in block and 'rel="noopener"' in block
    assert block.count('class="footer-link"') == 2
    assert f'<a href="mailto:{ALIAS}" class="footer-link">Email {ALIAS}</a> or ' in block
    assert ">message me on LinkedIn</a>." in block
    assert "<svg" not in block
    assert "footer-linkedin" not in block
    assert set(ADDRESS_RE.findall(block)) == {ALIAS}
    assert "—" not in block and "--" not in block


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_the_only_mailto_is_the_footer_alias(path):
    html = _read(path)
    rel = os.path.relpath(path, STATIC)
    assert html.count('href="mailto:') == 1, rel
    assert f'href="mailto:{ALIAS}"' in _attribution(path), rel


def test_results_contact_note_offers_email_and_linkedin():
    """Doc 39 left the results view's closing line alone; Doc 41 added the alias."""
    index = _read(os.path.join(STATIC, "index.html"))
    assert '<p class="results-contact-note is-hidden" id="results-contact-note"></p>' in index
    app_js = _read(os.path.join(STATIC, "app.js"))
    assert "function _renderContactNote(failCount, warnCount)" in app_js
    assert f"'<a href=\"mailto:{ALIAS}\">Email {ALIAS}</a> or ' +" in app_js
    assert "message me on LinkedIn</a>." in app_js
    assert app_js.count('href="mailto:') == 1
