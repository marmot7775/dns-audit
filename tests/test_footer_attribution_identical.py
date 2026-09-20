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

Doc 54 renamed the repo to dns-audit. Every GitHub link on the pages points
at the new name, and the old name survives only where it names the droplet's
checkout directory, plus the doc history.

Doc 68: the identical-footer check compared the .footer-attribution block
alone, so the footer-trust row (version, Security Policy, MIT License) sat on
index.html and on none of the other seven pages for as long as it has existed
and no test noticed. The comparison is now the whole <footer> element, which
covers the trust row, the nav and anything added beside them later.
"""
import os
import re
import subprocess

import pytest

from static_pages import PAGES, STATIC

ATTRIBUTION_RE = re.compile(r'<div class="footer-attribution">.*?</div>', re.DOTALL)
FOOTER_RE = re.compile(r'<footer class="site-footer">.*?</footer>', re.DOTALL)
TRUST_RE = re.compile(r'<div class="footer-trust">.*?</div>\s*</div>', re.DOTALL)
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


def _footer(path):
    blocks = FOOTER_RE.findall(_read(path))
    assert len(blocks) == 1, (
        f"{os.path.relpath(path, STATIC)}: expected exactly one "
        f"<footer class=\"site-footer\"> element, found {len(blocks)}"
    )
    return blocks[0]


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_footer_attribution_is_identical_to_index(path):
    reference = _attribution(os.path.join(STATIC, "index.html"))
    assert _attribution(path) == reference, (
        f"{os.path.relpath(path, STATIC)}: .footer-attribution differs from index.html"
    )


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_the_whole_footer_is_identical_to_index(path):
    """Doc 68: the whole element, not the attribution line alone.

    The narrower check let the footer-trust row live on index.html only.
    """
    reference = _footer(os.path.join(STATIC, "index.html"))
    assert _footer(path) == reference, (
        f"{os.path.relpath(path, STATIC)}: <footer> differs from index.html"
    )


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_every_page_carries_the_trust_row(path):
    """Named separately so a regression says which row went missing."""
    footer = _footer(path)
    rel = os.path.relpath(path, STATIC)
    assert '<div class="footer-trust">' in footer, rel
    assert '<span class="footer-version">' in footer, rel
    assert ">Security Policy</a>" in footer, rel
    assert ">MIT License</a>" in footer, rel


def test_the_trust_row_sits_between_the_nav_and_the_attribution():
    footer = _footer(os.path.join(STATIC, "index.html"))
    nav = footer.index('<div class="footer-nav">')
    trust = footer.index('<div class="footer-trust">')
    attribution = footer.index('<div class="footer-attribution">')
    assert nav < trust < attribution


def test_the_footer_version_matches_the_packaged_version():
    """v2.0.0 in the footer is pyproject's version, not a hand-typed string."""
    import tomllib
    repo = os.path.dirname(STATIC)
    with open(os.path.join(repo, "pyproject.toml"), "rb") as f:
        version = tomllib.load(f)["project"]["version"]
    footer = _footer(os.path.join(STATIC, "index.html"))
    assert f'<span class="footer-version">v{version}</span>' in footer, version


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


REPO_URL = "https://github.com/marmot7775/dns-audit"
# Split so this file does not match its own search.
OLD_NAME = "dns-security" + "-auditor"
DEPLOY_LINE = f'ssh DEPLOY_USER@DROPLET_HOST "cd {OLD_NAME} && git pull'


@pytest.mark.parametrize("path", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_github_links_point_at_the_renamed_repo(path):
    html = _read(path)
    rel = os.path.relpath(path, STATIC)
    links = re.findall(r'href="(https://github\.com/[^"]*)"', html)
    assert links, rel
    for link in links:
        assert link == REPO_URL or link.startswith(REPO_URL + "/"), (rel, link)


def test_old_repo_name_survives_only_in_the_droplet_path():
    """The droplet's checkout keeps the old directory name (Doc 54)."""
    repo = os.path.dirname(STATIC)
    out = subprocess.run(
        ["git", "grep", "-n", "-I", "-F", OLD_NAME, "--", ".", ":!docs/history"],
        cwd=repo, capture_output=True, text=True,
    )
    assert out.returncode in (0, 1), out.stderr
    stray = []
    for hit in out.stdout.splitlines():
        path, _, text = hit.split(":", 2)
        if path == "deploy/dns-auditor.service":
            continue
        if path == "CLAUDE.md" and DEPLOY_LINE in text:
            continue
        stray.append(hit)
    assert not stray, stray
