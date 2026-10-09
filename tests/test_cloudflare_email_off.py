"""No email_off markers anywhere in the static HTML (report copy part 1).

PR #148 wrapped every address in <!--email_off--> so Cloudflare's Email
Address Obfuscation would leave it as plain text. The address on the live
homepage was then readable by any scraper. The markers are gone: Cloudflare
rewrites each address in an HTML response into a /cdn-cgi/l/email-protection
link that its script decodes. app.js is not an HTML response and Cloudflare
never rewrites it, so app.js carries no address at all; the results note
links to LinkedIn and the footer carries the protected email link.
"""
import glob
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALIAS = "dns" + "@" + "dns-audit" + ".com"


def _html_files():
    files = glob.glob(os.path.join(REPO_ROOT, "static", "**", "*.html"), recursive=True)
    assert files
    return sorted(files)


def test_no_email_off_markers():
    marked = []
    for path in _html_files():
        with open(path, encoding="utf-8") as f:
            if re.search(r"<!--/?email_off-->", f.read()):
                marked.append(os.path.relpath(path, REPO_ROOT))
    assert not marked, marked


def test_no_address_in_app_js():
    with open(os.path.join(REPO_ROOT, "static", "app.js"), encoding="utf-8") as f:
        assert ALIAS not in f.read()
