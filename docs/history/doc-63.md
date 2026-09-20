# Doc 63: The results page shows everything at once

A first-time reader called the report overwhelming. Measured
on main at 22268d6 with the Doc 38 fixture (example-corp.test)
at 1280 wide: the results page is 16,213 px tall and 3,475
words before any click. Five of the twelve check cards open by
default. The DMARC card alone is 7,891 px because its body
stacks fifteen panels in the order they were added:
explanation, issues, record, spec toggle, strict validation
checklist, attack surface, subdomain security, tag breakdown
with configuration analysis and migration path and record
builder and "Why RFC 9989", tree walk, RFC 9989 readiness,
evaluation, report delivery chain, change history. Nothing
ranks them, so the reader gets all of them. This doc changes
what shows by default and adds one level of hierarchy inside a
card. No panel is deleted, no wording changes, and no check
logic changes. Front end only: static/app.js and
static/style.css, with the browser tests. Line numbers are
from main at 22268d6.

## 1. Every card starts collapsed

app.js:1038 opens every card whose status is not absent.
Change it so every card starts collapsed. The header already
carries the status pill and the one-line verdict
(check.verdict at 1064), so the collapsed list reads as twelve
rows of name, status, and verdict. Confirm every check the
transformer emits has a non-empty verdict; if any card would
show an empty verdict slot, report which and fill it from the
check's first detail line.

Expand All at 3165 to 3192 keeps working: with every card
collapsed, majorityExpanded is false and the label reads
Expand All. syncToggleAllLabel and the comment at 896 need
their wording updated.

Anything that scrolls to a card must also open it, or the
reader lands on a closed row. Three places: the executive
summary scroll buttons at 643 to 649, the Priorities rows at
767 to 772, and any hash in the URL on load (a #check-dmarc
link from the PDF or a shared URL). Add one helper,
openCard(id), that adds the expanded class, sets aria-expanded
on the header, and then scrolls; use it in all three.

## 2. One level of hierarchy inside a card

Inside an opened card the body keeps only what answers "what
did you find": the explanation, the detail list, the
deliverability callout, the TTL badge, the record block, and
the fix preview with its propagation warning (renderCheckBody
from about 1236 through 1279, plus 1379 to 1381 and 1402 to
1406). Everything else moves under a single collapsed section
at the bottom of the card headed Details, built the way Change
History already is (cd-section, cd-header, cd-body at 1474 to
1525 and style.css:5960 onward), so the click handler at 1107
to 1121 and the is-hidden class carry over unchanged.

The panels that move, in this order inside Details: spec
toggle with strict and legacy validation (1281 to 1303),
attack surface (1306), subdomain security (1311), tag
breakdown (1316, which includes configuration analysis, the
migration path, the record builder, and Why RFC 9989), SPF
execution trace (1323), tree walk (1328), record builder for
the no-record case (1333), RFC 9989 readiness (1343), DMARC
evaluation (1349), report delivery chain (1354), SPF deep
analysis (1359), DKIM key analysis (1364), SPF include tree
(1369), change history (1384 to 1391), consistency findings
(1394). The structural errors banner at 1300 stays above
Details when it fires, since it qualifies what is under it.

Each panel inside Details gets its own collapsed sub-header
with the panel's existing title on the left and a one-line
summary on the right, so a closed Details section reads as a
table of contents. The summaries come from data the panels
already render; write them as: Strict validation "Passes RFC
9989, 10 of 10" or "3 of 10 checks fail"; Attack surface "3 of
4 paths exposed"; Subdomain security "1 of 20 probed
subdomains exposed"; Record breakdown "9 tags, 2 removed in
RFC 9989"; Tree walk "Record found at the domain itself" or
"Found N labels up"; RFC 9989 readiness the existing status
pill text; DMARC evaluation "SPF and DKIM aligned" or the
existing summary sentence; Report delivery chain "1
destination, all authorized"; SPF trace "N lookups of 10";
DKIM key analysis "N selectors found, weakest 1024-bit";
Change history the existing count; Consistency findings "N
findings". If a summary cannot be derived from the panel's
data, use the title alone rather than inventing one.

The Details header itself shows a count: "Details · 8
sections". Opening Details shows the sub-headers closed;
opening a sub-header shows that panel. Nothing auto-opens.

Panels that render for the DMARC card only in RFC 9989 mode
(the spec-dmarcbis wrappers) keep their wrappers so the mode
toggle still hides and shows them; the toggle now lives inside
Details, as the first section.

## 3. Space and separation

The page's own spacing tokens (Doc 38 8px grid) stay. Two
adjustments only: a collapsed card's header gets 4px more
vertical padding so the twelve-row list does not read as a
table, and the Details section has 16px clear above it and a
top border, so the found-versus-reference split is visible
without reading.

## 4. Copy All Records, Expand All, PDF and the mode toggle

Copy All Records reads the DOM for record blocks; confirm it
still finds them when the cards are collapsed (cards are
collapsed with CSS, so the nodes exist; verify rather than
assume). Expand All opens cards, not Details sections. The PDF
is unchanged in this doc; it gets its own doc. The spec toggle
keeps working when it is inside a closed Details section; it
should not need to be visible to have its state applied on
open.

## Tests

- Browser test: on the fixture, after render, every
  .result-card lacks the expanded class and every
  .result-header has aria-expanded="false"; the page height at
  1280 is under 5,000 px; the toggle label reads Expand All.
- Browser test: clicking a Priorities row opens the target
  card and scrolls to it; loading
  /?d=example-corp.test#check-dmarc opens the DMARC card; the
  executive summary buttons open their targets.
- Browser test: opening the DMARC card shows explanation,
  details, record, and one Details header, with the fifteen
  panels absent from the visible area (offsetParent null)
  until their sub-headers are clicked; each sub-header has
  aria-expanded and aria-controls.
- Browser test: the spec toggle inside Details still switches
  between RFC 9989 and RFC 7489 validation views.
- Browser test: Copy All Records copies the same text with all
  cards collapsed as with all expanded.
- tests/test_ui_consistency_a11y.py at 496 to 514 counts
  expanded and collapsed cards; update its expectations and
  keep its rule that every aria-expanded control has
  aria-controls.
- Run the full suite and the browser tests.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
style.css and app.js change, so cache-bust the asset URLs per
CLAUDE.md.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, put the before and after page height for github.com at
1280 in the PR.
Save this doc as docs/history/doc-63.md in the same commit and
add its line to docs/history/README.md.

## Done when

The results page loads as summary, priorities, and twelve
closed rows; opening a card shows what was found and a closed
Details section with a labeled sub-header per panel; every
panel that exists today is still reachable in two clicks;
Expand All, Copy All Records, the Priorities links, and the
spec toggle work; and the suite passes.
