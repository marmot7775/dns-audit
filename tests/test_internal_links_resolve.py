"""Every internal link on the static pages answers 200 (Doc 84).

Doc 84 added links between the articles. The suite checked that a DANE
article link named an existing file, but nothing fetched the links, so a
typo in a route or a page that lost its route went unnoticed. This walks
every static page, collects each href that stays on the site, and asks the
app for it.
"""
import os
import re
import sys
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server as server_module
from result_transformer import ARTICLE_SENTENCES
from static_pages import PAGES, STATIC

client = TestClient(server_module.app)

_HREF_RE = re.compile(r'<a\s[^>]*href="([^"]+)"', re.IGNORECASE)


def _internal_targets(html):
    targets = set()
    for href in _HREF_RE.findall(html):
        parts = urlsplit(href)
        if parts.scheme or parts.netloc:
            if parts.netloc not in ("dns-audit.com", "www.dns-audit.com"):
                continue
        elif not parts.path:
            continue  # "#main-content" and other same-page fragments
        targets.add(parts.path or "/")
    return targets


def _page_links():
    links = []
    for path in PAGES:
        with open(path, encoding="utf-8") as f:
            html = f.read()
        rel = os.path.relpath(path, STATIC)
        links.extend((rel, target) for target in sorted(_internal_targets(html)))
    return links


LINKS = _page_links()


def test_the_article_cross_links_are_in_the_set():
    targets = {target for _, target in LINKS}
    assert {"/articles/p-reject", "/articles/dmarcbis",
            "/articles/spf-lookups"} <= targets


@pytest.mark.parametrize("page,target", LINKS)
def test_internal_link_answers_200(page, target):
    response = client.get(target, follow_redirects=False)
    assert response.status_code == 200, f"{page} links {target}: {response.status_code}"


# Doc 86: the audit's findings link five articles. Those hrefs live in
# result_transformer, not in a static page, so they are collected from there.
FINDING_LINKS = sorted({t for s in ARTICLE_SENTENCES for t in _internal_targets(s)})


def test_the_finding_links_are_the_five_articles():
    assert FINDING_LINKS == ["/articles/dane", "/articles/dmarcbis", "/articles/dnssec",
                             "/articles/p-reject", "/articles/spf-lookups"]


@pytest.mark.parametrize("target", FINDING_LINKS)
def test_finding_link_answers_200(target):
    response = client.get(target, follow_redirects=False)
    assert response.status_code == 200, f"finding links {target}: {response.status_code}"
