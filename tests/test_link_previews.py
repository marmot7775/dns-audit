"""Link previews, structured data and crawler access stay consistent.

Checked before a LinkedIn post (2026-10-09): every page named the site
"DNS Security Auditor" in og:site_name and the homepage JSON-LD while the
logo, the About page and the preview image said dns-audit.com; the preview
image promised a security grade A to F (removed long ago) and "No data
stored" (the privacy page says the audit log records each domain); X got a
small summary card; pages answered HEAD with 405; the sitemap had no dates.
"""
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import server  # noqa: E402

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
client = TestClient(server.app)


def _pages():
    return [(p["loc"], open(os.path.join(STATIC, p["file"]), encoding="utf-8").read())
            for p in server._SITE_PAGES]


def _meta(html, key):
    m = re.search(r'<meta (?:property|name)="%s" content="([^"]*)"' % re.escape(key), html)
    return m.group(1) if m else None


def test_every_page_previews_the_same_site_name_image_and_card():
    for loc, html in _pages():
        assert "DNS Security Auditor" not in html, loc
        assert _meta(html, "og:site_name") == "dns-audit.com", loc
        assert _meta(html, "og:image") == "https://dns-audit.com/static/og-card.png", loc
        assert (_meta(html, "og:image:width"), _meta(html, "og:image:height")) == ("1200", "630"), loc
        assert _meta(html, "og:image:alt"), loc
        assert _meta(html, "twitter:card") == "summary_large_image", loc
        canonical = re.search(r'<link rel="canonical" href="([^"]+)"', html)
        assert canonical and _meta(html, "og:url") == canonical.group(1), loc


def test_the_preview_image_is_the_size_the_tags_say():
    with open(os.path.join(STATIC, "og-card.png"), "rb") as f:
        head = f.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", head[16:24]) == (1200, 630)


def test_article_dates_agree_in_meta_jsonld_and_sitemap():
    sitemap = client.get("/sitemap.xml").text
    for loc, html in _pages():
        if not loc.startswith("/articles/") or loc == "/articles/":
            continue
        published = re.search(r'"datePublished":\s*"([^"]+)"', html).group(1)
        modified = re.search(r'"dateModified":\s*"([^"]+)"', html).group(1)
        assert _meta(html, "article:published_time") == published, loc
        assert _meta(html, "article:modified_time") == modified, loc
        assert f"<loc>https://dns-audit.com{loc}</loc>\n    <lastmod>{modified[:10]}</lastmod>" in sitemap, loc


def test_the_homepage_jsonld_names_the_site_as_the_logo_does():
    html = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S):
        data = json.loads(block)
        if data.get("@type") in ("WebSite", "WebApplication"):
            assert data["name"] == "dns-audit.com"


def test_every_article_route_is_in_the_sitemap_and_llms_txt():
    routes = {r.path for r in server.app.routes
              if getattr(r, "path", "").startswith("/articles/") and r.path != "/articles/"}
    listed = {p["loc"] for p in server._SITE_PAGES}
    assert routes <= listed, routes - listed
    llms = client.get("/llms.txt").text
    for loc in routes:
        assert f"https://dns-audit.com{loc})" in llms, loc


def test_head_answers_like_get_without_a_body():
    for path in ("/", "/articles/aprf", "/about", "/sitemap.xml", "/llms.txt"):
        get, head = client.get(path), client.head(path)
        assert head.status_code == 200 and head.content == b"", path
        assert head.headers["content-type"] == get.headers["content-type"], path
        assert head.headers["content-length"] == get.headers["content-length"], path


def test_head_never_reaches_the_audit_api():
    assert client.head("/api/audit?domain=example.com").status_code == 405
