"""Doc 37: no personal email address appears in any tracked file.

Public contact for this repo goes through LinkedIn or GitHub private
vulnerability reporting. The address was removed from the live site in
b5233ec and from the last four committed files in doc 37. This test walks
every file git tracks, docs/prompts included, and fails on any address at
the five personal domains, so a future prompt doc or page cannot bring one
back.

One occurrence is allowed, by file and exact string rather than by pattern:
a synthetic fixture in tests/test_dns_tools.py, and the line in doc 37 that
names that fixture. Both strings are assembled from pieces below so that
this file does not itself contain a literal match.
"""
import os
import re
import subprocess

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOMAINS = ("dns-audit.com", "icloud.com", "gmail.com", "outlook.com", "hotmail.com")
ADDRESS_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@(?:" + "|".join(re.escape(d) for d in DOMAINS) + r")\b",
    re.IGNORECASE,
)

# The synthetic fixture normalize_domain() is tested against. Joined at
# runtime so no literal address lives in this file.
_FIXTURE = "user" + "@" + "gmail" + ".com"

# Doc 41: the public contact alias, allowed only in the eight page footers,
# the results note in app.js, and the doc that asked for it.
ALIAS = "dns" + "@" + "dns-audit" + ".com"
ALIAS_FILES = (
    "static/index.html",
    "static/about.html",
    "static/privacy.html",
    "static/404.html",
    "static/articles/dane.html",
    "static/articles/dmarcbis.html",
    "static/articles/dnssec.html",
    "static/articles/index.html",
    "static/app.js",
    "docs/prompts/doc-41.md",
)

ALLOWED = {
    ("tests/test_dns_tools.py", _FIXTURE),
    ("docs/prompts/doc-37.md", _FIXTURE),
} | {(rel, ALIAS) for rel in ALIAS_FILES}


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _matches(relpath):
    full = os.path.join(REPO_ROOT, relpath)
    if not os.path.isfile(full):
        return []
    with open(full, "rb") as f:
        text = f.read().decode("utf-8", errors="ignore")
    return ADDRESS_RE.findall(text)


def test_git_ls_files_sees_the_repo():
    files = _tracked_files()
    assert "SECURITY.md" in files
    assert "docs/prompts/doc-37.md" in files
    assert "tests/test_dns_tools.py" in files


def test_no_personal_email_address_in_any_tracked_file():
    offenders = []
    for rel in _tracked_files():
        for addr in _matches(rel):
            if (rel, addr) not in ALLOWED:
                offenders.append(f"{rel}: {addr}")
    assert not offenders, (
        "Personal email address found in tracked files (doc 37 forbids this; "
        "point people at LinkedIn or GitHub private vulnerability reporting instead):\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("rel,addr", sorted(ALLOWED))
def test_allowlisted_fixture_is_still_where_the_allowlist_says(rel, addr):
    """If the fixture moves or is renamed, the allowlist must move with it."""
    assert addr in _matches(rel), f"{rel} no longer contains the allowlisted string"


def test_security_policy_points_to_private_reporting_not_email():
    with open(os.path.join(REPO_ROOT, "SECURITY.md"), encoding="utf-8") as f:
        text = f.read()
    assert "**Email:**" not in text
    assert "private vulnerability reporting" in text
    assert "https://www.linkedin.com/in/neilanuskiewicz/" in text
