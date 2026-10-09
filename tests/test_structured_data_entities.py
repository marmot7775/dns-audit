"""JSON-LD on every public page parses, and every @id reference resolves.

The pages link their structured data by @id: one Person (Neil, defined on
the about page), one WebSite (defined on the home page), and every
TechArticle, WebApplication author and WebSite publisher points at them.
A typo in an @id, or an entity deleted from the page that defines it,
leaves a reference to nothing. Search engines drop it without an error,
so this is the only place it would show up.
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_pages import PAGES, STATIC  # noqa: E402

SITE = "https://dns-audit.com"
PERSON = f"{SITE}/about#neil"
WEBSITE = f"{SITE}/#website"
LD_RE = re.compile(r'<script type="application/ld\+json">(.*?)</script>', re.S)
CANONICAL_RE = re.compile(r'<link rel="canonical" href="([^"]+)"')


def _rel(path):
    return os.path.relpath(path, STATIC).replace(os.sep, "/")


def _walk(x):
    """Every dict in a JSON-LD value, nested ones included."""
    if isinstance(x, dict):
        yield x
        for v in x.values():
            yield from _walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from _walk(v)


def _top_nodes(doc):
    if isinstance(doc, list):
        for d in doc:
            yield from _top_nodes(d)
    elif "@graph" in doc:
        yield from doc["@graph"]
    else:
        yield doc


# A reference may carry the type, name and url beside its @id: Google does not
# follow an @id to another page, so an article's author names itself. Any
# other property makes it a second definition.
_REF_KEYS = {"@id", "@type", "name", "url"}


def _is_ref(d):
    return "@id" in d and set(d) <= _REF_KEYS


def _load():
    site = {}
    for path in PAGES:
        html = open(path, encoding="utf-8").read()
        m = CANONICAL_RE.search(html)
        site[_rel(path)] = {
            "html": html,
            "canonical": m.group(1) if m else None,
            "docs": [json.loads(b) for b in LD_RE.findall(html)],
        }
    return site


SITE_DATA = _load()


def _defs():
    """@id -> list of (page, node) for every node that defines an entity."""
    out = {}
    for page, p in SITE_DATA.items():
        for doc in p["docs"]:
            for d in _walk(doc):
                if "@id" in d and not _is_ref(d):
                    out.setdefault(d["@id"], []).append((page, d))
    return out


def _nodes(page, type_):
    return [n for doc in SITE_DATA[page]["docs"] for n in _top_nodes(doc) if n.get("@type") == type_]


ARTICLES = sorted(p for p in SITE_DATA if p.startswith("articles/") and p != "articles/index.html")


def test_every_block_parses_and_has_a_context():
    # _load has already parsed them; a bad block fails at import.
    for page, p in SITE_DATA.items():
        for doc in p["docs"]:
            for top in doc if isinstance(doc, list) else [doc]:
                assert top.get("@context") == "https://schema.org", page


def test_every_id_is_defined_once():
    dup = {i: [pg for pg, _ in v] for i, v in _defs().items() if len(v) > 1}
    assert not dup, dup


def test_every_id_reference_resolves():
    defs = _defs()
    broken = [
        f"{page}: {d['@id']}"
        for page, p in SITE_DATA.items()
        for doc in p["docs"]
        for d in _walk(doc)
        if _is_ref(d) and d["@id"] not in defs
    ]
    assert not broken, broken


def test_each_entity_is_defined_on_the_page_its_id_names():
    for i, [(page, _)] in _defs().items():
        assert SITE_DATA[page]["canonical"].rstrip("/") == i.split("#")[0].rstrip("/"), (i, page)


def test_the_person_is_defined_on_the_about_page_and_referenced_elsewhere():
    [(page, person)] = _defs()[PERSON]
    assert page == "about.html"
    assert person["@type"] == "Person"
    assert person["name"] == "Neil Anuskiewicz"
    assert person["jobTitle"]
    assert person["url"] == f"{SITE}/about"
    assert person["sameAs"] == [
        "https://www.linkedin.com/in/neilanuskiewicz/",
        "https://github.com/marmot7775",
    ]
    inline = [pg for pg, p in SITE_DATA.items() for doc in p["docs"] for d in _walk(doc)
              if d.get("@type") == "Person" and d.get("@id") != PERSON]
    assert not inline, f"a Person written out instead of referenced by @id: {inline}"
    [app] = _nodes("about.html", "WebApplication")
    assert app["author"] == {"@id": PERSON}


def test_the_website_is_defined_on_the_home_page():
    [(page, site)] = _defs()[WEBSITE]
    assert page == "index.html"
    assert site["@type"] == "WebSite"
    assert site["url"] == f"{SITE}/"
    assert site["name"]
    assert site["publisher"] == {"@id": PERSON}


@pytest.mark.parametrize("page", ARTICLES)
def test_article_links_to_person_and_site(page):
    [art] = _nodes(page, "TechArticle")
    url = SITE_DATA[page]["canonical"]
    assert art["url"] == url
    # The @id ties the article to the one Person defined on /about. Google
    # does not follow an @id to another page, so the name and url ride along.
    for role in ("author", "publisher"):
        assert art[role] == {"@type": "Person", "@id": PERSON,
                             "name": "Neil Anuskiewicz", "url": f"{SITE}/about"}, role
    assert art["mainEntityOfPage"] == url
    card = "og-card-aprf.png" if page == "articles/aprf.html" else "og-card.png"
    assert art["image"] == f"{SITE}/static/{card}?v=1"
    assert art["isPartOf"] == {"@id": WEBSITE}
    for field in ("headline", "description", "datePublished", "dateModified"):
        assert art[field], field


@pytest.mark.parametrize("page", ARTICLES + ["about.html"])
def test_breadcrumb(page):
    [bc] = _nodes(page, "BreadcrumbList")
    items = bc["itemListElement"]
    assert [i["position"] for i in items] == list(range(1, len(items) + 1))
    assert items[0]["name"] == "Home" and items[0]["item"] == f"{SITE}/"
    if page.startswith("articles/"):
        assert len(items) == 3
        assert items[1]["name"] == "Articles" and items[1]["item"] == f"{SITE}/articles/"
        [art] = _nodes(page, "TechArticle")
        assert items[2]["name"] == art["headline"]
    else:
        assert len(items) == 2
    assert items[-1]["item"] == SITE_DATA[page]["canonical"]


def test_articles_index_lists_the_articles_in_page_order():
    page = SITE_DATA["articles/index.html"]
    [col] = _nodes("articles/index.html", "CollectionPage")
    assert col["url"] == page["canonical"]
    items = col["mainEntity"]["itemListElement"]
    shown = re.findall(
        r'<h2 class="article-card-title"><a href="(/articles/[^"]+)">([^<]+)</a></h2>', page["html"])
    assert len(shown) == len(ARTICLES)
    assert [(i["position"], i["url"], i["name"]) for i in items] == [
        (n, SITE + href, name) for n, (href, name) in enumerate(shown, 1)
    ]
