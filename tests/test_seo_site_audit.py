"""The pages link and say what the Semrush crawl of 2026-11-15 found missing.

- Every article links to every other article, and each link reads as the
  target's own h1, so no article depends on the index for its one incoming
  link.
- The home page shows the questions and answers its FAQPage JSON-LD
  describes, word for word, and shows no question the markup lacks.
- No title tag runs past 70 characters.
"""
import glob
import html
import json
import os
import re

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


def _read(*parts):
    with open(os.path.join(STATIC, *parts), encoding="utf-8") as f:
        return f.read()


def _articles():
    out = {}
    for path in sorted(glob.glob(os.path.join(STATIC, "articles", "*.html"))):
        slug = os.path.basename(path)[:-5]
        if slug != "index":
            out[slug] = _read("articles", slug + ".html")
    assert len(out) >= 7
    return out


def test_every_article_links_to_every_other_by_its_h1():
    pages = _articles()
    h1 = {slug: re.search(r"<h1[^>]*>(.*?)</h1>", page, re.S).group(1).strip()
          for slug, page in pages.items()}
    for slug, page in pages.items():
        nav = re.search(r'<nav class="dbis-section more-articles"[^>]*>(.*?)</nav>\s*</article>', page, re.S)
        assert nav, slug
        assert "<h2 id=\"more-articles\">More articles</h2>" in nav.group(1), slug
        links = dict(re.findall(r'<a href="/articles/([a-z0-9-]+)">(.*?)</a>', nav.group(1)))
        assert links == {s: t for s, t in h1.items() if s != slug}, slug


def _visible(page):
    return re.sub(r"<script\b.*?</script>", "", page, flags=re.S)


def test_the_home_page_shows_the_faq_its_markup_describes():
    page = _read("index.html")
    blocks = [json.loads(b) for b in
              re.findall(r'<script type="application/ld\+json">(.*?)</script>', page, re.S)]
    faq = [b for b in blocks if b.get("@type") == "FAQPage"]
    assert len(faq) == 1
    marked = [(q["name"], q["acceptedAnswer"]["text"]) for q in faq[0]["mainEntity"]]
    section = re.search(r'<section class="home-faq"[^>]*>(.*?)</section>', _visible(page), re.S)
    assert section
    assert "<h2 id=\"faq-heading\">Common questions</h2>" in section.group(1)
    shown = [(html.unescape(q), html.unescape(a)) for q, a in
             re.findall(r"<h3>(.*?)</h3>\s*<p>(.*?)</p>", section.group(1), re.S)]
    assert shown == marked


def test_the_faq_comes_after_the_form_and_the_results():
    page = _read("index.html")
    main = page[page.index("<main"):page.index("</main>")]
    assert (main.index('class="audit-input-section"') < main.index('id="results-section"')
            < main.index('class="home-faq"'))


def test_no_title_tag_is_too_long_for_a_search_result():
    for path in sorted(glob.glob(os.path.join(STATIC, "**", "*.html"), recursive=True)):
        title = html.unescape(re.search(r"<title>(.*?)</title>", _read(path), re.S).group(1))
        assert len(title) <= 70, (os.path.relpath(path, STATIC), len(title))


def test_www_redirects_to_the_apex_in_the_nginx_template():
    conf = _read("..", "deploy", "nginx.conf")
    blocks = re.findall(r"^server \{.*?^\}", conf, re.S | re.M)
    assert len(blocks) == 3
    site, www, plain = blocks
    assert re.search(r"server_name dns-audit\.com;", site)
    assert "proxy_pass" in site
    assert re.search(r"listen 443 ssl;\s+server_name www\.dns-audit\.com;", www)
    for block in (www, plain):
        assert "return 301 https://dns-audit.com$request_uri;" in block
        assert "proxy_pass" not in block
