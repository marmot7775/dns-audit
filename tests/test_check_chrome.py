"""Doc 105: tools/check_chrome.py reads the canonical chrome and compares hosts."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from check_chrome import SITE_ADDRESS, compare, links  # noqa: E402

with open(os.path.join(ROOT, "docs", "site-chrome.html"), encoding="utf-8") as f:
    CANONICAL = f.read()


def test_links_reads_the_nav_and_footer_in_order():
    nav, footer = links(CANONICAL)
    assert [t for t, _ in nav] == ["DNS Audit Audit", "Header Decoder Headers",
                                   "APRF Reader APRF", "Articles", "About"]
    assert [t for t, _ in footer][:4] == ["Articles", "About", "Privacy", "GitHub"]
    assert footer[-1] == ("MIT License",
                          "https://github.com/marmot7775/dns-audit/blob/main/LICENSE")


def test_own_repo_hrefs_are_info_and_anything_else_fails():
    page = links(CANONICAL)
    other = links(CANONICAL.replace("marmot7775/dns-audit", "marmot7775/aprf-reader"))
    failures, infos = compare({"a": page, "b": other})
    assert failures == [] and len(infos) == 3
    broken = links(CANONICAL.replace(">Articles</a>", ">Posts</a>", 1))
    failures, _ = compare({"a": page, "b": broken})
    assert failures == ["b: nav differs from a"]


def test_cloudflare_obfuscated_mailto_compares_without_its_key():
    a = '<footer><a href="/cdn-cgi/l/email-protection#91f5ff">x</a></footer>'
    b = '<footer><a href="/cdn-cgi/l/email-protection#2a4e44">x</a></footer>'
    assert compare({"a": links(a), "b": links(b)}) == ([], [])


def test_cloudflare_obfuscated_link_text_reads_as_the_address():
    live = ('<footer><a href="/cdn-cgi/l/email-protection#91f5ff">Email '
            '<span class="__cf_email__" data-cfemail="91f5ff">[email&#160;protected]</span>'
            '</a></footer>')
    plain = f'<footer><a href="mailto:{SITE_ADDRESS}">Email {SITE_ADDRESS}</a></footer>'
    assert links(live)[1] == [(f"Email {SITE_ADDRESS}", f"mailto:{SITE_ADDRESS}")]
    assert compare({"a": links(live), "b": links(plain)}) == ([], [])
