# Doc 68: Three defects on the edges of the report

The report itself is done. These three are around it: text
clipped off the screen on a phone, a domain the form refuses
that the API audits fine, and a footer that differs between
pages. All three were reproduced at ab03f4b and re-checked at
240bcb9. Front end only, plus the shared normalizer. Line
numbers are from main at 240bcb9.

## 1. Removed-tag rows run off the screen at phone width

Open example-corp.test at 390 px, open the DMARC card, open
Details, open the record breakdown. The rows listing the tags
RFC 9989 removed are laid out as one flex line and their
content runs past the viewport: measured, each .dbis-dep-item
is 304 px wide while its children end at 426 px and 509 px,
and the container clips rather than scrolls, so the reason
text is not reachable at all. The row reads "pct |
Spec-required | RFC 9989 §C.5.2 ..." and stops.

.dbis-dep-item in static/style.css is display: flex with no
flex-wrap, and .dbis-spec-ref carries flex-shrink: 0. Let the
row wrap: flex-wrap: wrap on the item, and drop the
flex-shrink on the spec reference so it can sit on its own
line. Give .dbis-dep-reason flex-basis: 100% so the reason
always starts a new line below the tags. Check the same three
panels at 390, 360 and 320 px after the change, and check that
nothing changed at 768 px and above.

While at it, sweep the opened DMARC card at 390 px for any
other element whose right edge exceeds the viewport, and
report what you find rather than fixing it in this doc.

## 2. The form refuses domains the API accepts

Type bücher.de into the search box and the page says
"bücher.de" does not look like a valid domain name. The API
takes it: curl -s -G --data-urlencode "domain=bücher.de"
--data "scope=dmarc" https://dns-audit.com/api/audit returns a
full audit of xn--bcher-kva.de. The same goes for any
internationalized name, so a reader who types their own domain
in Cyrillic, Greek, Hebrew, Arabic, or with a German umlaut is
told their domain is invalid by a tool that would have audited
it.

The cause is that normalizeDomain in static/app.js lowercases
and strips but does no punycode conversion, and the DOMAIN_RE
at app.js:251 (and its copies at 172 and 4105) allows only A
to Z, 0 to 9, and hyphen. The server does this correctly:
normalize_domain in dns_tools.py:317 to 341 runs idna.encode
after the same stripping.

Convert in the browser before validating. Use the URL
constructor, which does IDNA for the host: new URL("http://" +
d).hostname returns the punycode form for a name the browser
accepts, and throws for one it does not. Convert first, then
test the existing regex against the converted value, then
submit the converted value. A name the constructor rejects
keeps the existing inline error. Do not write a punycode
implementation and do not add a library for this.

The three DOMAIN_RE copies become one constant used in all
three places while in there.

## 3. The footer differs between pages

static/index.html carries a footer-trust row (version,
Security Policy, MIT License) above the attribution line. The
other seven pages, about, privacy, 404, the articles index,
and the three articles, have the attribution line and no trust
row. Doc 39 added an identical-footer test and it does not
cover this row.

Put the same trust row on all eight pages, with the same
markup and the same order, and extend the identical-footer
test to compare the whole footer element rather than the
attribution line alone. The version string stays whatever
index.html shows today; if the number there is stale, say so
in the PR rather than guessing a new one.

## Tests

- Browser at 390 px: every .dbis-dep-item's children end at or
  inside the viewport, and the reason text of each removed-tag
  row is visible; the same rows are unchanged at 768 px.
- Browser: typing bücher.de and pressing Run Audit submits
  xn--bcher-kva.de and renders a result; typing not a domain
  still shows the inline error; an ASCII domain is unaffected.
- The three DOMAIN_RE copies are one constant.
- The footer test compares the full footer on all eight pages
  and passes.
- Run the full suite and the browser tests.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
app.js, style.css and the HTML pages change, so cache-bust the
asset URLs per CLAUDE.md.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, load the site and audit bücher.de through the form,
and put the result domain in the PR.
Save this doc as docs/history/doc-68.md in the same commit and
add its line to docs/history/README.md.

## Done when

No text on the results page is clipped off the right edge at
phone width, an internationalized domain typed into the form
is audited rather than refused, every page carries the same
footer, and the suite passes.
