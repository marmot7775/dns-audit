#!/usr/bin/env python3
"""Compare the header nav and footer links across the three live apps.

docs/site-chrome.html is the canonical header and footer, copied into
email-header-decoder and aprf-reader. This fetches each live home page and
prints, per host, the ordered (text, href) pairs inside the first <nav> and
inside <footer>.

    python3 tools/check_chrome.py

Exit status is 1 when the nav lists differ in text or href, or the footer
lists differ in text or in an href beyond the repo name. Footer hrefs that
differ only in the repo name are allowed and printed as info.
"""
import re
import sys
from html.parser import HTMLParser

import requests

HOSTS = [
    "https://dns-audit.com/",
    "https://headers.dns-audit.com/",
    "https://aprf.dns-audit.com/",
]
REPO_RE = re.compile(r"(https://github\.com/marmot7775/)[^/]+")
# Cloudflare email obfuscation rewrites the mailto with a per-response key.
OBFUSCATED_RE = re.compile(r"(/cdn-cgi/l/email-protection)#\w+")


class ChromeLinks(HTMLParser):
    """Collect (text, href) for links in the first <nav> and in <footer>."""

    def __init__(self):
        super().__init__()
        self.nav, self.footer = [], []
        self._navs_seen = 0
        self._in_nav = self._in_footer = False
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "nav" and not self._in_footer:
            self._navs_seen += 1
            self._in_nav = self._navs_seen == 1
        elif tag == "footer":
            self._in_footer = True
        elif tag == "a" and (self._in_nav or self._in_footer):
            self._href, self._text = dict(attrs).get("href", ""), []

    def handle_endtag(self, tag):
        if tag == "nav":
            self._in_nav = False
        elif tag == "footer":
            self._in_footer = False
        elif tag == "a" and self._href is not None:
            href = OBFUSCATED_RE.sub(r"\1", self._href)
            pair = (" ".join("".join(self._text).split()), href)
            (self.nav if self._in_nav else self.footer).append(pair)
            self._href = None

    def handle_data(self, data):
        if self._href is not None:
            # Separate the nav-long and nav-short spans with a space.
            self._text.append(data + " ")


def links(html):
    """Return (nav, footer) lists of (text, href) pairs from one page."""
    parser = ChromeLinks()
    parser.feed(html)
    return parser.nav, parser.footer


def compare(pages):
    """Return (failures, infos) for {host: (nav, footer)}."""
    failures, infos = [], []
    (ref_host, (ref_nav, ref_footer)), *rest = pages.items()
    for host, (nav, footer) in rest:
        if nav != ref_nav:
            failures.append(f"{host}: nav differs from {ref_host}")
        if [t for t, _ in footer] != [t for t, _ in ref_footer]:
            failures.append(f"{host}: footer link texts differ from {ref_host}")
            continue
        for (text, href), (_, ref_href) in zip(footer, ref_footer):
            if href == ref_href:
                continue
            if REPO_RE.sub(r"\1*", href) == REPO_RE.sub(r"\1*", ref_href):
                infos.append(f"{host}: {text} points at its own repo: {href}")
            else:
                failures.append(f"{host}: footer {text} href {href} != {ref_href}")
    return failures, infos


def main():
    pages = {}
    for host in HOSTS:
        resp = requests.get(host, timeout=20)
        resp.raise_for_status()
        pages[host] = links(resp.text)
    for host, (nav, footer) in pages.items():
        print(host)
        print("  nav:")
        for text, href in nav:
            print(f"    {text!r} {href}")
        print("  footer:")
        for text, href in footer:
            print(f"    {text!r} {href}")
    failures, infos = compare(pages)
    for line in infos:
        print(f"INFO {line}")
    for line in failures:
        print(f"FAIL {line}")
    print("FAIL" if failures else "OK")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
