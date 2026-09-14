# Doc 48: UI defects, consistency, and accessibility

Sixth doc from the Sept 13 review. Everything here was seen in
a rendered page (screenshots in the reviewer's harness at 1280
and 390, both themes) or measured from computed styles. Line
numbers are from main at 38a02d0; search for the quoted
selector or string if one has moved. Render the fixture zone
from Doc 38 and a clean p=reject zone in headless Chromium
before and after, in both themes and both widths, and keep the
screenshots out of the commit.

## 1. Layout defects

- static/style.css:7512 to 7514: .domain-valid-indicator sits
  at right: 5.5rem inside .input-wrapper, but the Run Audit
  button is 118px wide, so the green check overlaps the R of
  the button in every results screenshot. Anchor the indicator
  to the input itself (wrap the input alone) or set right to
  the button width plus 12px.
- 3457: .record-block padding-right 3rem at the 640px
  breakpoint is smaller than the copy button (54px plus its
  0.6rem offset), so record text runs under the button at 390
  wide; 4164 at 320 is worse. Use 4.25rem at both.
- 8425: at 768 and below .cache-rerun-btn gets min-height 44px
  while #cache-status-badge is a 22px tag, so the button's
  border sticks out above and below the badge. Give the badge
  height auto in that media query, or use the negative-margin
  hit-area pattern .selector-toggle already uses.
- 905 and 3277: at 390 the three .banner-actions buttons share
  one row and PDF Report wraps to two lines while Export and
  Share stay on one. Let the row wrap, or white-space: nowrap
  on the label with a smaller gap.
- 3070 and static/index.html:325: .footer-left has no width
  and .footer-brand-desc carries a hard <br>, so the brand
  line renders as four lines at 1280. Give .footer-left a flex
  basis and drop the <br>. Same block on all eight pages; the
  Doc 39 identical-footer test must still pass.
- 8460 onward: at 640 and below .footer-link becomes
  inline-flex with padding 0 0.25rem, which puts a space
  before the full stop in "message me on LinkedIn ." Keep the
  touch target with a pseudo-element hit area rather than
  padding.
- 6692 and 6780 use var(--mono), which is not defined; the
  token is --font-mono, so the TTL note and the change-history
  diff render in DM Sans. 7493, 7537, 7575 use
  var(--radius-sm), never defined, so three elements render
  square. Rename the first, define --radius-sm: 4px in both
  token blocks for the second.
- static/apple-touch-icon.png and static/favicon-32.png are
  corrupt (a tRNS chunk fails its CRC; PIL cannot open them
  and Chromium fires Image.onerror). Re-export both from
  favicon.svg at 180x180 and 32x32 and confirm they decode.

## 2. Contrast

- 427: .logo-flag uses var(--primary-light), which becomes
  #2f5fcc in light theme while the terminal chip keeps its
  dark background: 3.24 to 1 at 11px on every page. Give it a
  fixed colour that does not change with theme, for example
  #7ea6f5.
- 726: .domain-input::placeholder is rgba(255,255,255,0.35) on
  the hardcoded #2e3d54 input, 2.78 to 1 in dark theme. Use
  var(--text-tertiary).
- In light theme, .tag-warn inside .rb-verdict-monitoring is
  4.42 to 1 and .tag-high inside .anomaly-card.anomaly-warn is
  4.11 to 1, because an amber tag sits on an amber-tinted
  surface. Give tags an opaque background, or use the warn
  contrast text token on tags placed on warn surfaces.
- 7055 and the matching block near 7310 still carry the
  .footer-linkedin rule and a comment about a 2.3 to 1
  exception for an icon Doc 39 deleted. Remove both.

## 3. Behaviour

- static/app.js:1541 and 1592: _specMode persists across
  audits, but the toggle always renders RFC 9989 active, so
  after choosing RFC 7489 and running a second audit the click
  at 1592 returns early and the toggle is dead. Reset
  _specMode to 'dmarcbis' at the top of renderResults.
- 3855: the R shortcut tests resultsSection.style.display,
  which is empty before the first audit, so pressing R while
  focus is on a scope button clears a typed domain. Test
  lastAuditData instead.
- 596: the timestamp shows the client-measured duration, which
  is 0.0s for a cached result. The API emits elapsed_seconds;
  prefer it when present.
- 3820: rows.push([..., fixes, ts]) references a variable
  renamed to priorities at 3796; the CSV export throws when a
  result has no checks. Use priorities.
- 2311 to 2330: the tree walk renders any step with found
  false as "No DMARC record" and never reads
  step.lookup_failed or tw.walk_incomplete, which
  dmarc_tree_walk.py says a consumer must not do. Branch on
  lookup_failed and render "Lookup failed" with the
  unavailable icon, and show a note when walk_incomplete is
  set.
- 2577 and 737 to 742: on a clean domain the roadmap is empty
  so #priority-section is hidden, but the executive summary
  still renders a View Priorities button pointing at it and
  the risk box says "The Priorities list below names smaller
  improvements." Emit the button only when the roadmap has
  rows, and give build_executive_summary a different
  biggest-risk sentence when it is empty: "Nothing to fix.
  Every check the audit could assess passed."
- result_transformer.py:646 build_security_roadmap has no
  Nameservers entry, so a red Nameservers card has no
  Priorities row and no remediation anywhere on the page. Add
  one for the fail and warn cases with the card's existing fix
  text.
- Around result_transformer.py:800 the Priorities row copies
  the card's status, so a recommendation on a passing card
  ("Address: removed tags: pct") carries a green check that
  reads as done. Recommendation rows get the info icon, never
  pass.
- app.js:1018 hardcodes isExpanded = true while the comments
  at lines 3, 756, 870, 973, and 1013 describe collapsing
  passing cards, and isDmarc at 1015 is unused. The fixture
  page is 16,000px tall at 1280. Collapse absent cards by
  default (nothing in them needs reading), keep every other
  state open, and rewrite the five comments to say that.

## 4. Consistency

- Two link styles inside one card: .explanation a is
  underlined, .tw-footnote a (1769) uses border-bottom; the
  article lede uses underline and the body uses border-bottom.
  Pick underline everywhere and delete the border-bottom
  variants.
- 6473: .rcb-result-record .copy-btn is teal while every other
  copy button is grey. One style.
- The SPF card states the lookup count three ways: "Total: 2 /
  10 lookups" in the trace, "2/10 lookups" in the analysis
  header, and "2 of 10 DNS lookups used" on the budget bar.
  Keep the budget bar and drop the other two.
- Glyphs still used as icons after Doc 38: app.js:1358
  (clipboard emoji), 1412 and 2608 (envelope), 1450 (circular
  arrow), 2035 (books emoji), 2114 (arrow), 3444 (arrows), 180
  (up arrow), 1706 (right arrow in "Audit" followed by an
  arrow). Add mail, history, book, arrow-right, arrow-up, and
  swap to the ICON object and use them.
- Hex colours outside the two token blocks, on live surfaces:
  .copy-btn 1614 to 1640 (a GitHub palette), .rec-keyword and
  siblings 1583 to 1612, .audit-input-card #243046 at 530 and
  .input-wrapper #2e3d54 at 614, .rb-value 5766, .spfd-cost
  and .rb-chain-active 5078 and 5840, .advisory-warning 6611
  to 6613, .ttl-long 6710, and the light-theme .copy-btn:hover
  and .advisory-info. Map each to an existing token; add a
  token only where none fits, and put it in both theme blocks.
- 7982: .dbis-page is still max-width 680px while .about-page
  at 8187 is 68ch. Make it 68ch.
- border-radius values in use: 2, 3, 4, 5, 6, 7, 8, 10, 14,
  and 100px. Keep the three tokens plus the new --radius-sm
  and replace every literal with one of them.

## 5. Accessibility

- static/index.html:117 has the skip link and
  main#main-content; about.html, privacy.html, 404.html, and
  the four article pages have neither. Add both to all eight.
- On the results page the compact audit card sets the h1 to
  display none, so the heading tree starts at h2 Priorities.
  Make #result-domain the h1 for the results view, or keep the
  h1 visually hidden instead of display none.
- app.js:1028: the card title is an h3 with tabindex 0 and a
  data-tooltip inside a header that is role button and
  tabindex 0. A focusable element inside a button is invalid,
  it adds twelve tab stops, and the tooltip text reaches no
  assistive technology. Drop the tabindex on the h3 and expose
  the tooltip through aria-describedby on the header.
- 3781 to 3785: #request-id-display is a div with onclick,
  cursor pointer, no tabindex, no role, no key handler. Make
  it a button.
- 1449 (.cd-header) and 3469 (.pi-guidance-toggle) set
  aria-expanded without aria-controls; the card header does
  both. Add aria-controls.
- style.css:8250: .article-card-title a:focus-visible sets
  outline none, leaving a colour change as the only focus
  indicator. Use the same 2px primary ring everything else
  has.
- The DMARC card's sections (Strict Record Validation, DMARC
  Record Breakdown, Migration Path, Record Builder, Tree Walk,
  DMARC Evaluation, Report Delivery Chain, Change History) are
  spans and divs, so there is no heading navigation below the
  h3 in a card that runs to 18,000px on a phone. Make them h4.
- Decorative SVGs without aria-hidden: index.html:140 and 141
  (theme icons), the search icon and spinner in the audit
  form, the six scope icons, and the toolbar icons. Add
  aria-hidden="true" to each; the subdomain table's empty
  Audit column header gets a visually hidden label.
- Fonts: add <link rel="preload"> for
  dm-sans-normal-latin.woff2 and jetbrains-mono-latin.woff2 in
  every page head so first paint does not swap.

## 6. Five strings Doc 47 left

Replace these, which Claude Code listed after Doc 47:

- The p=quarantine and p=reject deliverability boxes say
  p=reject gets "better inbox placement". Replace the sentence
  with: "Google and Yahoo require a DMARC record from bulk
  senders; an enforcing policy also lets receivers act on mail
  that fails."
- The missing-rua warning opens with two near-identical
  sentences. Keep only "Without aggregate reports you cannot
  see who is sending as your domain or whether their mail
  passes."
- The sp=none warnings say mail "is delivered as if the policy
  did not exist". Replace with "receives no policy at all, so
  each receiver applies only its own filtering".
- The resilience note for a domain with no DMARC record says
  "Anyone can send email that appears to come from this
  domain." Replace with "Receivers have no policy for mail
  that fails authentication for this domain."
- The MTA-STS card says encryption "can be silently stripped".
  Replace with the Doc 47 item 7 sentence for MTA-STS.

## Tests

tests/test_doc38_visual_system.py skips in CI because
playwright is not installed there. Add playwright to
requirements-dev.txt and a playwright install chromium step to
.github/workflows/tests.yml so browser assertions run. Then
add assertions for: no element overlaps the Run Audit button
at 1280; record text right edge is left of the copy button at
390; no computed font-family falls back because of an
undefined variable (grep style.css for var(--x) where x is not
defined in the token blocks); every page has a skip link and a
main landmark; no tabindex inside role=button; the two PNGs
decode; contrast of the three pairs above is at least 4.5 to 1
in both themes.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js and style.css change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-48.md in the same commit.

## Done when

Nothing overlaps or clips at 1280 or 390 in either theme,
every CSS variable used is defined, the three contrast
failures pass, the spec toggle and R shortcut and CSV export
behave, the tree walk distinguishes a failed lookup from no
record, every fail or warn card has a Priorities row, one icon
set and one link style and one copy button style remain, every
page has a skip link and a main landmark, and the browser
tests run in CI.
