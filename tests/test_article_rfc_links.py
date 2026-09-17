"""Regression test for Doc 31: every RFC link in an article must name a
current RFC that the article text actually discusses, and no article may
link to captaindns.com (an uncited vendor blog used as the sole source for
a claim about Google's DANE behavior that Google's own docs do not make).

Cheap on purpose: it does not verify the RFC number is *correct* for the
claim next to it, only that the number in the URL is not orphaned from the
visible text, which is the failure mode a stale or copy-pasted link
produces (link to RFC 8624 while the prose has moved on to RFC 9904, and
nothing else on the page ever names 8624).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTICLES_DIR = os.path.join(REPO_ROOT, "static", "articles")

_RFC_LINK_RE = re.compile(
    r'href="https?://(?:www\.)?(?:rfc-editor\.org|datatracker\.ietf\.org)/'
    r'[^"]*?rfc0*(\d+)[^"]*"',
    re.IGNORECASE,
)

# Links whose anchor text names the protocol rather than the RFC number
# (e.g. linking "TLS-RPT" straight to RFC 8460) are not stale citations: the
# reader sees exactly what the link is. Exempted by number so a genuinely
# orphaned link cannot hide behind this list.
_NAMED_PROTOCOL_EXEMPTIONS = {"8460"}  # TLS-RPT


def _article_files():
    return sorted(
        os.path.join(ARTICLES_DIR, name)
        for name in os.listdir(ARTICLES_DIR)
        if name.endswith(".html")
    )


def test_every_rfc_link_names_an_rfc_the_article_text_discusses():
    for path in _article_files():
        with open(path, encoding="utf-8") as f:
            content = f.read()
        rel = os.path.relpath(path, REPO_ROOT)
        for number in _RFC_LINK_RE.findall(content):
            if number in _NAMED_PROTOCOL_EXEMPTIONS:
                continue
            assert re.search(rf"RFC\s+0*{number}\b", content), (
                f"{rel} links to RFC {number} but never names it as "
                f"'RFC {number}' in the visible text, which is what a stale "
                f"or copy-pasted link looks like"
            )


def test_no_article_links_to_captaindns():
    offenders = []
    for path in _article_files():
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if "captaindns.com" in content.lower():
            offenders.append(os.path.relpath(path, REPO_ROOT))
    assert offenders == [], (
        f"an article still links to captaindns.com, an uncited vendor blog: "
        f"{offenders!r}"
    )


# Doc 60: the DANE article was rewritten word for word, and its five
# sources had to stay on the phrases they anchored before. Each href is
# pinned to its anchor text, so a rewrite that drops or moves one fails.
_DANE_SOURCES = {
    "wrote the obituary in 2015":
        "https://www.imperialviolet.org/2015/01/17/notdane.html",
    "RFC 7672": "https://datatracker.ietf.org/doc/html/rfc7672",
    "September 2025 sample of the 10,000 domains most often emailed by "
    "Zivver's Dutch customers":
        "https://www.zivver.com/blog/use-of-email-security-standards-in-the-"
        "netherlands-september-2025-only-14-dane-6-mta-sts",
    "October 2024":
        "https://techcommunity.microsoft.com/blog/exchange/announcing-general-"
        "availability-of-inbound-smtp-dane-with-dnssec-for-exchange-on/4281292",
    "TLS-RPT": "https://datatracker.ietf.org/doc/html/rfc8460",
}


def _anchors(content):
    return re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', content)


def test_dane_article_keeps_its_five_sources_on_their_phrases():
    with open(os.path.join(ARTICLES_DIR, "dane.html"), encoding="utf-8") as f:
        anchors = _anchors(f.read())
    by_text = {text: href for href, text in anchors}
    for text, href in _DANE_SOURCES.items():
        assert by_text.get(text) == href, f"dane.html: {text!r} should link {href}"
    external = [href for href, _ in anchors if href.startswith("http")
                and "dns-audit.com" not in href and "github.com" not in href
                and "linkedin.com" not in href]
    assert sorted(external) == sorted(_DANE_SOURCES.values())


def test_dane_article_internal_links_resolve_to_pages():
    with open(os.path.join(ARTICLES_DIR, "dane.html"), encoding="utf-8") as f:
        anchors = _anchors(f.read())
    for href, _ in anchors:
        if href.startswith("/articles/") and href != "/articles/":
            name = href[len("/articles/"):] + ".html"
            assert os.path.exists(os.path.join(ARTICLES_DIR, name)), href
