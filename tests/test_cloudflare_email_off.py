"""Every email address in the static HTML sits inside Cloudflare's
<!--email_off--> ... <!--/email_off--> markers.

Cloudflare's Email Address Obfuscation (Scrape Shield) rewrites any address
it finds in an HTML response into a [email protected] span and a link to
/cdn-cgi/l/email-protection, decoded by a script it injects. Without that
script the contact address cannot be read, and example addresses inside
<code> become links. Doc 26 asked for a plain address with no JavaScript.
The markers tell Cloudflare to leave the address alone; the zone setting
cannot be changed from the repo. Addresses that app.js renders are added
after the response, so Cloudflare never sees them.
"""
import glob
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDRESS_RE = re.compile(r"[\w.+!-]+@[\w-]+(?:\.[\w-]+)+")
WRAPPED_RE = re.compile(r"<!--email_off-->.*?<!--/email_off-->", re.DOTALL)


def _html_files():
    files = glob.glob(os.path.join(REPO_ROOT, "static", "**", "*.html"), recursive=True)
    assert files
    return sorted(files)


def test_every_address_is_inside_email_off():
    bare = []
    for path in _html_files():
        with open(path, encoding="utf-8") as f:
            outside = WRAPPED_RE.sub("", f.read())
        bare += [f"{os.path.relpath(path, REPO_ROOT)}: {m.group(0)}" for m in ADDRESS_RE.finditer(outside)]
    assert not bare, "addresses Cloudflare would obfuscate:\n" + "\n".join(bare)


def test_markers_are_balanced():
    for path in _html_files():
        with open(path, encoding="utf-8") as f:
            src = f.read()
        assert src.count("<!--email_off-->") == src.count("<!--/email_off-->"), path
