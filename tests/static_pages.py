"""The static pages the header and footer tests hold identical (Doc 51).

Doc 36 and Doc 39 each built this list and each asserted it covered the
same eight pages. One copy now, so a new page shows up in both at once.
"""
import glob
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "static")

PAGES = sorted(
    glob.glob(os.path.join(STATIC, "*.html"))
    + glob.glob(os.path.join(STATIC, "articles", "*.html"))
)

EXPECTED_PAGES = {
    "404.html",
    "about.html",
    "index.html",
    "privacy.html",
    "articles/dane.html",
    "articles/dmarcbis.html",
    "articles/dnssec.html",
    "articles/index.html",
}
