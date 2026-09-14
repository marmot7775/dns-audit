# Doc 38: One visual system for the site, the results page, and the PDF

This doc defines the status semantics, icon set, type weights,
badge vocabulary, and spacing scale, and applies them
everywhere. It replaces any earlier Doc 38 text. Line numbers
are from main at 55bf1c8; re-locate by content if they have
moved.

Measurements below come from rendering the app locally against
a fixture zone (SPF, one DKIM selector, DMARC p=none pct=50,
two MX, no DNSSEC, MTA-STS, TLS-RPT, CAA, DANE, or BIMI) at
1280 and 390 wide in both themes, and from rendering the
complete PDF for the same zone.

Do everything in one branch and one PR. Sections 1 and 2
change what users are told; do them first and do not skip them
if time runs short.

## 1. Status semantics: four states, and amber stops meaning two things

Today the fixture renders seven amber cards. Five of them
(MTA-STS, TLS-RPT, DNSSEC, CAA, DANE) are optional protocols
the domain has simply not adopted, returned as status "warn"
with pill "Not configured" or "Not enabled"
(result_transformer.py:5496, 5678, 5823, 5986, 6126, 6543).
The other two are DMARC p=none and pct=50, which are
configured and weak. Same colour, same icon, same counter. A
reader cannot tell "you set this up wrong" from "you have not
set this up", and a domain that has done nothing wrong opens
to a wall of warnings. That is the alarmism problem.

Define the states as:

- fail, red: an essential record is missing or any record is
  broken. Essential means DMARC, SPF, DKIM (when the user
  named a selector), MX on a mail domain, and nameservers.
  Broken means published but invalid, DNSSEC bogus, MTA-STS
  policy unreachable, a rua destination unauthorized.
- warn, amber: published and working but weak. p=none, pct
  below 100, sp weaker than p, SPF ~all, DKIM 1024-bit key,
  MTA-STS mode testing, DMARC without rua.
- pass, green: published and correct.
- absent, grey: an optional protocol is not published.
  MTA-STS, TLS-RPT, DNSSEC, CAA, DANE, BIMI when nothing is
  there. Nothing is wrong; something is available.
- unavailable, grey with a different icon and label "Not
  checked": the lookup did not complete or the check was out
  of scope. Already exists; keep it.

Implement "absent" as a real status value, not a rendering
trick on top of "warn", so the JSON API, the counters, the tab
title, the share text, the PDF cover, and the web page all
read the same fact. Add it to whatever status enum or
validation exists, and update `_assessed` at
result_transformer.py:697 so absent counts as assessed.

Where it applies:

- Cards: the five sites above plus BIMI when absent (currently
  pass with pill "Not configured", which is also wrong; a pass
  with nothing published is a contradiction). Pill text "Not
  configured" for all six. Card left border and icon use the
  neutral colour. Keep the explanation and the fix; the card
  still tells the reader what they would gain.
- Counters (app.js:638 to 647): four tiles become pass,
  warnings, issues, not configured. The tab title at
  app.js:659 and the share text at 3214 count only fail and
  warn. "(0 warnings)" for the fixture is correct once p=none
  and pct=50 are the only warnings; check that the fixture
  then reports 2 warnings, 0 issues, 5 not configured.
- Executive summary Protocol Coverage: absent is not
  configured; the Doc 27 `configured` boolean already says so.
- Spoofing Protection tile (app.js:2544,
  result_transformer.py:331): on the fixture it reads "None"
  in red beside an Issues counter of 0. Under these semantics
  p=none is warn, so the tile reads "Monitoring only" in
  amber. Red "None" only when DMARC is absent or unusable. The
  tile and the counters must never disagree in colour.
- Roadmap: absent items are what the roadmap is for. See
  section 3.
- PDF: mirror all of it. The cover counts, the status column,
  the protocol cards, and the roadmap table use the same four
  states. Add NEUTRAL_CLR (text grey, use #5a6678 to match
  --text-tertiary light) and NEUTRAL_BG (#f1f3f6) beside
  PASS_CLR at pdf_report.py:56 to 61.

Tests: a fixture with no optional protocols has fail count 0
and warn count 0 when its essentials pass; every card with
`configured: False` and a non-essential name has status
absent; BIMI absent is not pass; the web counters, tab title,
share text, and PDF cover agree on the four numbers for the
same result. Update
tests/test_unavailable_checks_never_pass.py and
tests/test_summary_hears_unavailable.py so unavailable and
absent are distinguished, not merged.

## 2. Two remaining sentences that predict attacks

audit_engine.py:235, the DMARC_P_NONE business impact:
"Attackers can still impersonate your domain in phishing
attacks against customers and staff." Replace the whole string
with: "DMARC monitoring-only mode collects reports but does
not block anything. Mail that fails authentication is still
delivered as if it came from you."

result_transformer.py:314: "Your domain has email
authentication but attackers can still exploit {vec_name}."
Replace with: f"Your domain has email authentication, but
{vec_name} is still open."

Add both phrasings to the existing test that bans "attackers
will"; extend it to "attackers can" and "attackers could".

## 3. One prioritized list instead of three

On the fixture the same DMARC finding appears in Key Findings
(priority_fixes, up to five plain strings,
audit_engine.py:6108), in the Email Security Roadmap (tiered
rows), and on the DMARC card. The roadmap is rendered under
the "All Checks" heading (index.html:292, app.js:780 appends
it to resultsList), so the first thing under "All Checks" is
not a check. And the Key Findings box is styled with
--fail-bg, --fail-border, and --fail-text unconditionally
(style.css:1130 to 1148) while priority_fixes includes
warnings (audit_engine.py:6108, "then fails, then warnings"),
so a domain whose worst finding is p=none gets a red box.

Merge Key Findings and the roadmap into one list, heading
"Priorities", placed where Key Findings is now
(index.html:272) and removed from under All Checks. Source of
truth is build_security_roadmap (result_transformer.py:566
onward), which already carries protocol, tier, action, and
business impact, and is sorted since Doc 34. Each row: status
icon (fail, warn, or absent), protocol name, tier tag,
one-line action, and the existing scroll-to link to the card.
Fail and warn rows come first because the sort already does
that; absent rows follow. The container is a plain surface
card, not red; the row icons carry severity. Remove
priority_fixes from the web render (keep the field in the JSON
for one release so nothing external breaks, and note that in
the commit message).

PDF: the Priority Fixes heading at pdf_report.py:670 and the
roadmap table at 586 become one section with the same rows.
Keep the tier counts line above the table.

Cards then stay as the detail layer, and nothing is stated
three times.

Test: for a result with one fail, one warn, and one absent,
the Priorities list has exactly three rows in that order, and
the same three protocols appear once each in the PDF section.

## 4. DMARC card repeats itself

On the fixture the DMARC card lists the p=none finding twice
with the same substance, once from the tag breakdown and once
from the issues list. Deduplicate card details by a normalized
key (tag name plus severity) before rendering, in the
transformer so the PDF gets the same list. Test with a p=none
record: exactly one detail row mentions p=none.

## 5. Icon set: one system

There are three today. Inline stroke SVGs (18 in index.html, 8
in app.js). Unicode glyphs in app.js: &#10003; at 1141, 1421,
1723 and nine more sites, &#10005; at 1140, &#9888; at 1140,
1422, 1889, &#8505; at 1462, 1889, and the shapes &#9632;
&#9650; &#9679; at 1579. Emoji at app.js:1627: &#x2705;
&#x26A0;&#xFE0F; &#x1F534; in the subdomain audit, which
render differently on every platform and cannot take the theme
colours.

Use one set: inline SVG, 16 by 16 viewBox, stroke 1.75, round
caps and joins, `fill="none"`, `stroke="currentColor"`,
`aria-hidden="true"`, coloured by the parent's status class.
Define them once in app.js as an `ICON` object and use it
everywhere a glyph or emoji is used now:

- pass: check mark
- warn: triangle with an exclamation stroke
- fail: x
- absent: circle drawn with a dashed stroke, no mark inside
- unavailable: circle with a diagonal slash
- info: circle with an i
- chevron: down chevron for disclosure, rotated when open

Five distinct shapes for the five statuses, so colour is never
the only signal. The attack surface at 1579 maps protected to
pass, partial to warn, exposed to fail. The subdomain audit at
1627 maps the same way. The change-detection icons at 1421 to
1422 map improvement to pass, regression to warn, no change to
info.

Card header (app.js around 975 to 1000): replace the 9px
`.status-dot` with the 16px status icon. The pill next to it
keeps the text. The dot and the pill were saying the same
thing in two visual languages.

PDF: DETAIL_ICON at pdf_report.py:94 stays glyph-based because
of the font constraint from Doc 34. Map pass to check, fail to
cross, warn to a bold "!", absent and info to a bullet in the
state's colour. The status column in tables uses the same
four.

Test: no emoji code points and none of the unicode glyphs
above remain in app.js; grep for &#10003;, &#10005;, &#9888;,
&#8505;, &#9632;, &#9650;, &#9679;, &#x2705;, &#x26A0;,
&#x1F534; returns nothing.

## 6. Badges: one component, one vocabulary

style.css has 81 distinct badge, pill, tag, chip, and label
class families, and 34 declarations of text-transform:
uppercase. Three vocabularies are visible on one results page:
uppercase status pills ("WARNING", "PASS", style.css:1384),
lowercase monospace tokens ("pass", "detected", "none") in the
strict validation and platform sections, and tier tags
(CRITICAL, HIGH, MEDIUM, LOW) in the roadmap.

Replace them with one base class `.tag` and modifiers:

- `.tag` : inline-flex, height 22px, padding 0 8px,
  border-radius 6px, font-size var(--font-xs), font-weight
  600, letter-spacing 0, text-transform none, line-height 1,
  gap 4px for an optional icon.
- `.tag-pass`, `.tag-warn`, `.tag-fail`, `.tag-absent`,
  `.tag-unavailable`: background from the matching -bg token,
  text from the matching text token. Absent and unavailable
  use the neutral tokens.
- `.tag-critical`, `.tag-high`, `.tag-medium`, `.tag-low`:
  critical and high use the fail and warn tokens, medium and
  low use neutral. Tier text stays uppercase because it is a
  rank, not a sentence; that is the one exception, set on
  these four classes only.
- `.tag-mono`: adds the mono font for record values and tag
  names, no colour change.

Pill text is sentence case: "Pass", "Warning", "Missing", "Not
configured", "Not checked", "No mail", "Not found". Delete the
uppercase transform at style.css:1392 and the other 33 sites
except headings that are deliberately eyebrow-styled (the
`.results-label` section headings may keep it; nothing else).

Migrate every badge-like element to the base class, then
delete the old families. Keep old ids where JavaScript targets
them. Verify in the browser with a script that collects every
element whose class contains tag, pill, badge, or chip and
asserts computed font-size, font-weight, height, and
border-radius are the four values above; it does not need to
be committed, but run it on the fixture in both themes before
merging.

## 7. Weight: four values and a hierarchy

style.css uses font-weight 600 in 122 rules, 700 in 71, 500 in
31, 400 in 10, and 800 once. When almost everything is 600,
nothing is emphasized.

Hierarchy:

- 700: page h1, section h2 (`.results-label`, article and
  About h2), the key numbers in the metric tiles and the four
  counters, the verdict line in the executive summary.
- 600: card titles, button labels, tags, the audit card
  headline, table headers.
- 500: labels, eyebrows, nav links, detail-row leads, form
  labels, footer links.
- 400: body, detail text, explanations, prose.

Remove the single 800. Reduce 600 to the roles above. A rule
of thumb for the migration: if the text is a full sentence, it
is 400; if it names a thing, it is 500 or 600; if it is the
biggest thing on the surface, it is 700.

Test: a script that parses style.css and asserts the set of
font-weight values is exactly {400, 500, 600, 700} and the
count of 600 declarations is under 60.

## 8. Spacing: the 8px grid, applied

Tokens exist (--space-xs 4 through --space-3xl 64) and are
unevenly used. Measured values and targets:

Homepage audit card:
- h1 margin-bottom 8px, subtitle to input 24px, input to scope
  24px. Set h1 margin-bottom to var(--space-lg) 24px, subtitle
  margin-bottom to var(--space-xl) 32px so the form sits in
  its own band, scope row margin-top 24px, trust line
  margin-top 16px.
- The headline, subtitle, and scope row are left aligned, the
  600px input row is centered, and the trust line is centered
  (`.audit-privacy-note` text-align center). Three alignment
  systems in one card. Left-align everything to one edge,
  including the input row (max-width stays 600px, margin-left
  0), and the trust line.

Logo: `.logo-terminal` (style.css:371) is width 120px with
overflow hidden, and `.logo-cmd` (407) is 11px mono nowrap "$
dns-audit --dmarc", which needs about 139px, so the header
logo renders clipped as "--dm" on every page. Set the terminal
width to auto with a min-width, or to 144px. Add a test that
renders the header at 1280 and 390 and asserts the logo text
is not clipped (scrollWidth equals clientWidth).

Results page:
- Card gap 16px, keep. Card header padding 16px, keep. Card
  body padding 16px top and 24px bottom: make it 20px both, so
  open cards do not look bottom heavy.
- `.detail-item` 13px with line-height 20.8 and 6.4px between
  rows, 8.8px gap to the icon. Set line-height 1.6, row gap
  var(--space-sm) 8px, icon gap 8px, and give the icon a fixed
  16px column so text wraps to its own left edge.
- Section spacing: `.results-label` margin-top
  var(--space-2xl) 48px, margin-bottom var(--space-md) 16px.
  Between the executive summary, counters, Priorities, and
  What's Unusual blocks: var(--space-xl) 32px. Today they are
  16px like the cards, so the page reads as one
  undifferentiated stack; at 1280 wide the fixture page is
  16,498px tall and the sections are indistinguishable while
  scrolling.
- Summary card padding 24px, keep.

About and articles:
- About paragraphs have margin-bottom 17.6px under a 28px
  line-height, so the gap between paragraphs is smaller than
  the gap between lines. Articles have 32px under 25.6px.
  Define one prose rule for both: line-height 1.65, paragraph
  margin-bottom 1.5rem, max-width 68ch (from 680px and roughly
  80 characters per line), h2 margin-top 3rem and
  margin-bottom 1rem, h1 margin-bottom 2rem. Apply to
  `.about-page` and the article body class.

PDF (pdf_report.py):
- 51 hardcoded Spacer calls with 11 distinct heights (2, 3, 4,
  6, 8, 10, 12, 14, 16, 20 and one more). Median gap between
  blocks on detail pages is about 5pt, which is why the
  protocol cards read as cramped while the cover has room to
  spare.
- Define a scale near the colour constants: SP_XS = 4, SP_SM =
  8, SP_MD = 12, SP_LG = 18, SP_XL = 28. Replace every Spacer
  height with one of these. Rules: XS only inside a list or
  between a label and its value; SM between paragraphs in the
  same block; MD between blocks in a section; LG between
  cards; XL before a section header, MD after. No gap between
  two blocks may be under 8pt.
- Margins stay as they are (top 0.7in, bottom 0.6in, sides
  0.75in); they were checked and are balanced.

## 9. Colour is already right; do not touch the tokens

Doc 35 set the palette. This doc adds only the neutral state,
which uses the existing --text-tertiary and --border tokens on
the web, and the two PDF constants in section 1. Do not
introduce any other colour.

## 10. Verification

Render the fixture at 1280 and 390 in both themes, expand
three cards, and look at the screenshots: five grey cards, two
amber, no red, Priorities list in a plain container with mixed
row icons, header logo unclipped, one left edge on the audit
card. Render the complete PDF and rasterize every page: same
states, no gap under 8pt between blocks, tier table and
Priority Fixes merged. Run the browser badge check from
section 6 and the weight test from section 7. Keep screenshots
and PNGs out of the commit.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js and style.css change.
Update the fail-red note in CLAUDE.md to describe the four
states and where the neutral tokens come from.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-38.md in the same commit.

## Done when

Grey means not adopted, amber means configured but weak, red
means essential missing or broken, and the counters, tab
title, tiles, cards, Priorities list, and PDF cover all agree
on that for the same result. One SVG icon set with five
distinct shapes and no emoji. One tag component with
sentence-case text. Four font weights with a stated role each.
Sections on the results page are visibly separated, the audit
card has one left edge, the logo is not clipped, prose
paragraphs are further apart than lines, and no two blocks in
the PDF are closer than 8pt.
