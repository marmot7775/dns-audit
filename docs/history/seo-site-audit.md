# SEO site audit fixes

Source: Semrush Site Audit crawl of dns-audit.com, Nov 15, 2026.
17 pages crawled, site health 87, JavaScript rendering off.
Written against main at 266a81b. Fetch main before starting and
stop if a file named below no longer matches.

Save this doc as docs/history/seo-site-audit.md.

## 1. Keep crawlers out of /cdn-cgi/

Finding: 12 broken internal links and 2 pages answering 404. All
14 are one URL, `/cdn-cgi/l/email-protection`, on both hosts.

Cause: Cloudflare Email Address Obfuscation rewrites the footer
address into a link to that path. A browser decodes it with
JavaScript. A crawler follows the link and gets a 404.

Fix: in `robots_txt()` in server.py (near line 1835) add
`Disallow: /cdn-cgi/` under the existing Disallow lines.

Keep obfuscation on. Do not add `email_off` markers;
tests/test_cloudflare_email_off.py forbids them.

Test: `/robots.txt` contains the new line.

## 2. Redirect www to the apex

Finding: `https://www.dns-audit.com/` serves a full copy of every
page with status 200. Semrush crawled both hosts, so each home
page finding is counted twice. The canonical tags already point at
the apex; this removes the duplicate crawl.

Fix in deploy/nginx.conf:

1. Remove `www.dns-audit.com` from `server_name` in the 443 block
   (line 25).
2. Add a 443 server block for `www.dns-audit.com` that reuses the
   same certificate lines and does
   `return 301 https://dns-audit.com$request_uri;`
3. In the port 80 block (line 79) change the return to
   `return 301 https://dns-audit.com$request_uri;` so both hosts
   reach the apex in one hop.

Apply on the droplet: copy the file into place, run `nginx -t`,
reload. The repo file and the live file match when done.

Check: `curl -sI https://www.dns-audit.com/about` answers 301 with
`location: https://dns-audit.com/about`.

## 3. Shorten one title

Finding: the title of static/articles/spf-lookups.html (line 6) is
77 characters and Semrush flags it as too long. The two longest
titles that pass are 68 and 69 characters.

Fix: change the `<title>` tag only, to

`SPF permerror: how to get back under 10 lookups | dns-audit.com`

That is 63 characters. Leave the h1, og:title, twitter:title, the
JSON-LD headline, and the card on the articles index as they are.
llms.txt reads the title tag through `_page_meta()` and follows
without a change.

## 4. Link the articles to each other

Finding: /articles/aprf and /articles/postmaster-tools each have
one incoming internal link, from the articles index. aprf.html
links to no other article. The other five link to one or two.

Fix: at the end of each of the seven article pages, inside
`<article>` and before it closes, add a `nav` with an h2 reading
`More articles` and a list linking the other six articles. Link
text is the target page's h1. Static HTML in each file, because
the crawler does not run JavaScript. Reuse existing list and link
styles. No inline style attributes; the CSP refuses them.

Test: every article page links to every other article page, and
each link text equals the target's h1.

## 5. Show the FAQ that the markup already describes

Finding: static/index.html carries a FAQPage JSON-LD block (starts
line 47) with four questions. None of the questions or answers is
in the visible page. Semrush counts 129 words on the home page and
flags low word count and low text to HTML ratio.

Fix: add a section inside `<main>`, after `#results-section` and
before `</main>`.

1. h2 reading `Common questions`.
2. Each question as an h3, each answer as a paragraph.
3. Text copied character for character from the JSON-LD block. No
   new copy.
4. Body text size, same max width as the audit card, existing
   variables and the 8px spacing grid. It stays in place when
   results render. The audit form stays the first thing on the
   page.

Test: every question and answer in the FAQPage block appears in
the visible HTML outside script tags (compare after unescaping
entities), and every visible question has a JSON-LD entry, so the
two cannot drift.

## 6. List the tools in llms.txt

Finding: `/llms.txt` lists the articles, About, and Privacy. It
does not list the Header Decoder or the APRF Reader, which the
site header links on every page.

Fix: in `llms_txt()` in server.py add a `## Tools` section above
`## Articles` with three links: `https://dns-audit.com/`,
`https://headers.dns-audit.com/`, and
`https://aprf.dns-audit.com/`. For each sister tool use the meta
description from that tool's own index page (repos
email-header-decoder and aprf-reader, or the live page). If
neither is reachable, list the name and link with no description.
Do not write new copy.

Test: extend tests/test_link_previews.py so `/llms.txt` contains
all three tool links.

## Leave alone

1. Structured data, `aggregateRating or review` missing on the
   WebApplication markup (home and About). The site has no ratings
   or reviews. Do not add any. The markup stays as it is.
2. Unminified app.js, style.css, and theme.js. There is no build
   step and this doc does not add one.
3. Two h1 elements in index.html. Deliberate: one is visible at a
   time, and tests/test_page_markup.py pins the results heading as
   an h1.

## Finish

1. Run the full test suite.
2. Static files changed, so run the cache-bust from CLAUDE.md.
3. One PR for the whole doc. Deploy, then run the checks in
   sections 1 and 2 against the live site and confirm `/llms.txt`
   and the home page show the new sections.
4. Report back inline in one fenced block: what changed, test
   count before and after, and the live check output.
