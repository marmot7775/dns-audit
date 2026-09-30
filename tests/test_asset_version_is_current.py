"""The ?v= on the versioned assets names a commit at or after their last change.

nginx (deploy/nginx.conf) serves a /static/ request that carries ?v= with a
seven day expiry and Cache-Control immutable; one without ?v= gets a one hour
max-age and must-revalidate. So a browser or Cloudflare that holds style.css?v=X never asks for it again
while X stays the same. The only thing that moves X is the cache-bust loop in
CLAUDE.md, run by hand after the commit that changes an asset. Skipping it
used to pass every test and ship a stylesheet that returning visitors would
not see for up to a week. This fails instead: every page must carry one v,
and that v must be the last commit that touched style.css, app.js, theme.js
or articles.js, or a later one.

It needs git history. CI checks out with fetch-depth 0 for it; a shallow
clone fails with a message rather than skipping silently.
"""
import glob
import os
import re
import subprocess

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = ["static/style.css", "static/app.js", "static/theme.js", "static/articles.js"]
_V_RE = re.compile(r"(?:style\.css|app\.js|articles\.js|theme\.js)\?v=([a-zA-Z0-9]+)")


def _git(*args):
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True)


def _versions():
    found = {}
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "static", "*.html"))
                       + glob.glob(os.path.join(REPO_ROOT, "static", "articles", "*.html"))):
        with open(path, encoding="utf-8") as f:
            for v in _V_RE.findall(f.read()):
                found.setdefault(v, set()).add(os.path.relpath(path, REPO_ROOT))
    return found


def test_every_page_carries_one_asset_version():
    found = _versions()
    assert len(found) == 1, f"pages disagree on ?v=: {found}"


def test_asset_version_is_at_or_after_the_last_asset_change():
    if not os.path.exists(os.path.join(REPO_ROOT, ".git")):
        pytest.skip("not a git checkout")
    shallow = _git("rev-parse", "--is-shallow-repository").stdout.strip()
    assert shallow != "true", (
        "shallow clone: this test needs the history (actions/checkout fetch-depth: 0)")
    (v,) = _versions()
    last = _git("log", "-1", "--format=%H", "--", *ASSETS).stdout.strip()
    assert last, "no commit touches the versioned assets"
    resolved = _git("rev-parse", "--verify", "--quiet", f"{v}^{{commit}}").stdout.strip()
    fix = ("Run the cache-bust loop in CLAUDE.md after the commit that changes "
           "the asset, then commit the result.")
    assert resolved, f"?v={v} is not a commit in this history. {fix}"
    ok = _git("merge-base", "--is-ancestor", last, resolved).returncode == 0
    assert ok, (f"?v={v} is older than {last[:7]}, the last commit that touched "
                f"{', '.join(ASSETS)}. {fix}")
