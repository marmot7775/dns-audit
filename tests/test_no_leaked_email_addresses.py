"""Doc 37: no email address of Neil's may exist in a tracked file, because a
public repo file is as harvestable as a web page. This walks every file
`git ls-files` tracks (no extension excluded: .md, .py, .html, .js, and the
workflow files under .github/ all get scanned) and fails if any of them
contains an address at the project domain or at a personal mail domain.

The banned domains are assembled from string parts rather than written as a
literal address, so this file describes the pattern without containing a
live address for the pattern to match against itself.
"""
import os
import re
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_DOT = "."
_PROJECT_DOMAIN = "dns-audit" + _DOT + "com"
_PERSONAL_MAIL_DOMAINS = ["icloud" + _DOT + "com"]
_BANNED_DOMAINS = [_PROJECT_DOMAIN] + _PERSONAL_MAIL_DOMAINS

_LOCAL_PART = r"[A-Za-z0-9][A-Za-z0-9._%+-]*"
_EMAIL_RE = re.compile(
    _LOCAL_PART + "@" + "(?:" + "|".join(re.escape(d) for d in _BANNED_DOMAINS) + ")",
    re.IGNORECASE,
)


def _tracked_files():
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def test_no_tracked_file_contains_a_banned_email_address():
    offenders = []
    for rel_path in _tracked_files():
        abs_path = os.path.join(REPO_ROOT, rel_path)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8", errors="ignore")
        for match in _EMAIL_RE.finditer(text):
            offenders.append(f"{rel_path}: {match.group(0)}")

    assert offenders == [], (
        "a tracked file contains an address that gets harvested from public "
        "repos; redact it to a placeholder instead:\n  " + "\n  ".join(offenders)
    )
