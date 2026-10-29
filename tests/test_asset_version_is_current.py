"""The ?v= on the versioned assets is a hash of their contents.

nginx (deploy/nginx.conf) serves a /static/ request that carries ?v= with a
long expiry and Cache-Control immutable; one without ?v= gets a one hour
max-age and must-revalidate. So a browser or Cloudflare that holds
style.css?v=X never asks for it again while X stays the same. The only thing
that moves X is the cache-bust loop in CLAUDE.md. Skipping it used to pass
every test and ship a stylesheet that returning visitors would not see for
days. This fails instead: every page must carry one v, and that v must be the
first ten hex characters of the SHA-256 of style.css, app.js, theme.js and
articles.js, read in that order.

The version used to be a commit SHA. A squash or rebase merge rewrites the
commit the pages named, so main went red twice in October 2026 with a ?v=
that was no longer in the history. A content hash survives any merge style
and changes only when an asset does.
"""
import glob
import hashlib
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = ["static/style.css", "static/app.js", "static/theme.js", "static/articles.js"]
_V_RE = re.compile(r"(?:style\.css|app\.js|articles\.js|theme\.js)\?v=([a-zA-Z0-9]+)")


def _versions():
    found = {}
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "static", "*.html"))
                       + glob.glob(os.path.join(REPO_ROOT, "static", "articles", "*.html"))):
        with open(path, encoding="utf-8") as f:
            for v in _V_RE.findall(f.read()):
                found.setdefault(v, set()).add(os.path.relpath(path, REPO_ROOT))
    return found


def _content_hash():
    h = hashlib.sha256()
    for rel in ASSETS:
        with open(os.path.join(REPO_ROOT, rel), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:10]


def test_every_page_carries_one_asset_version():
    found = _versions()
    assert len(found) == 1, f"pages disagree on ?v=: {found}"


def test_asset_version_is_the_hash_of_the_assets():
    (v,) = _versions()
    want = _content_hash()
    assert v == want, (
        f"?v={v} but the assets hash to {want}. Run the cache-bust loop in "
        "CLAUDE.md and commit the result.")
