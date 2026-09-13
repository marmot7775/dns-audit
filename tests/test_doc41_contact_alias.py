"""Doc 41: the contact alias appears in the eight footers and the results
note, and in no other tracked file.

The alias is assembled from pieces so this file does not itself contain it.
docs/prompts/doc-41.md is the one extra file: the doc is saved verbatim and
names the alias it asks for.
"""
import os
import re
import subprocess

import test_no_personal_email_in_repo as guard

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALIAS = "dns" + "@" + "dns-audit" + ".com"
LINKEDIN = "https://www.linkedin.com/in/neilanuskiewicz/"

FOOTER_FILES = [
    "static/index.html",
    "static/about.html",
    "static/privacy.html",
    "static/404.html",
    "static/articles/dane.html",
    "static/articles/dmarcbis.html",
    "static/articles/dnssec.html",
    "static/articles/index.html",
]
SITE_FILES = FOOTER_FILES + ["static/app.js"]
PROMPT_DOC = "docs/prompts/doc-41.md"


def _read(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8", errors="ignore") as f:
        return f.read()


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def test_alias_is_in_every_footer():
    for rel in FOOTER_FILES:
        block = re.search(r'<div class="footer-attribution">.*?</div>', _read(rel), re.DOTALL)
        assert block, rel
        assert f'<a href="mailto:{ALIAS}" class="footer-link">Email {ALIAS}</a>' in block.group(0), rel
        assert f'href="{LINKEDIN}"' in block.group(0), rel


def test_alias_is_in_the_results_note_beside_linkedin():
    src = _read("static/app.js")
    start = src.index("function _renderContactNote(failCount, warnCount)")
    body = src[start:src.index("\n}\n", start)]
    assert "if (failCount > 0 || warnCount > 0)" in body
    assert f'<a href="mailto:{ALIAS}">Email {ALIAS}</a> or ' in body
    assert f'<a href="{LINKEDIN}" target="_blank" rel="noopener">message me on LinkedIn</a>.' in body


def test_alias_appears_in_no_other_tracked_file():
    holders = []
    for rel in _tracked_files():
        full = os.path.join(REPO_ROOT, rel)
        if os.path.isfile(full) and ALIAS in _read(rel):
            holders.append(rel)
    assert sorted(holders) == sorted(SITE_FILES + [PROMPT_DOC]), holders


def test_personal_address_guard_still_passes():
    guard.test_no_personal_email_address_in_any_tracked_file()
