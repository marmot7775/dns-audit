# Doc 50: One wordmark in the header, and a headline that fits

Small layout and copy doc. Two things the home page shows
every visitor: the header logo cluster is two competing marks,
and the headline breaks mid-phrase. Line numbers are from main
at e1f3506; search for the quoted selector if one has moved.
Render before and after at 1280 and 390 in both themes; keep
the screenshots out of the commit.

## 1. The header: one mark, not two

The left side of the header is a 146 by 39 fake terminal chip
(title-bar dots, "$ dns-audit --dmarc" at 11px mono) next to
an 18px "dns-audit" wordmark, 242px in total. Two logos side
by side is why the left side reads cluttered and the wordmark
looks off centre; at 640 and below the chip is already hidden,
so the site has two headers. Keep the wordmark only.

- Remove the whole <div class="logo-terminal"> block
  (static/index.html:124 to 133) from all eight pages, so the
  link is <a href="/" class="logo"><span
  class="logo-text"><span
  class="logo-accent">dns</span>-audit</span></a>.
  tests/test_doc36_header_identical.py compares the headers
  byte for byte, so change all eight in one pass.
- Delete the chip CSS: .logo-terminal, .logo-titlebar,
  .logo-dot and its three colours, .logo-cmd, .logo-prompt,
  .logo-bin, .logo-flag and the comment above it
  (static/style.css:376 to 436), and the breakpoint copies at
  3342 to 3349, 4191 to 4193, and 8473 to 8477 with their
  comment. Remove gap from .logo at 366; it has one child now.
- .logo-text at 437: font-size var(--font-xl), keep weight 700
  and letter-spacing -0.01em. At 3351 (640 and below) make it
  1rem instead of 0.88rem, and delete the 0.82rem override at
  4195 to 4197. The wordmark must stay on one line beside
  Home, Articles, About, and the toggle at 390 and at 320; if
  it wraps at 320, reduce the nav gap before reducing the
  wordmark.
- Vertical alignment: .header-inner is align-items center at
  60px, so the wordmark centres on the nav without further
  rules. Confirm in the render that the wordmark baseline and
  the nav-link baselines sit within 1px of each other; if the
  wordmark's line-height pushes it off, set line-height 1 on
  .logo-text.
- Horizontal alignment is already right and must stay so:
  .header-inner and .audit-input-card both start at x=224 on a
  1280 viewport (the 880px container plus its padding). Assert
  that in the browser test below.

## 2. The headline

static/index.html:153: "Check the DNS records mail servers use
to verify your email" is 11 words and breaks at 1280 as "Check
the DNS records mail" over "servers use to verify your email",
splitting the phrase "mail servers"; text-wrap: balance at
style.css:577 cannot fix that because balancing keeps the two
lines even and the break lands in the same place. Replace the
h1 text with:

Check the DNS records behind your email

Measured at 1280 it is one line (about 700px of the 734px
column); at 390 it breaks as "Check the DNS records behind"
over "your email". It is accurate for every check the audit
runs, which the old line was not (MTA-STS, DNSSEC, CAA, and
nameservers are not records mail servers use to verify email).
Leave the text-wrap: balance rule in place for the two-line
case on narrower screens.

## 3. The subtitle

static/index.html:154 runs 67 words and five lines at 1280,
nine at 390. Replace the paragraph text with the following,
keeping the existing link markup on "RFC 9989 readiness":

Enter a domain. The audit reads the DNS records and policy
files behind email authentication, transport security, and DNS
integrity (SPF, DKIM, DMARC, MTA-STS, DNSSEC, and seven more),
says what is missing or misconfigured, cites the RFC it
checked against, including RFC 9989 readiness, and gives you
the corrected record to paste. Nothing to install, nothing to
send.

Measured: 58 words, four lines at 1280 and eight at 390.
Nothing it claims has changed: policy files are still named
because the audit fetches the MTA-STS policy and the BIMI logo
over HTTPS, and "cites the RFC it checked against" stays as
Doc 40 worded it. Do not add a word to it; at 59 words it went
back to five lines. The speakable block at index.html:87
points at .audit-title and .audit-subtitle by selector, so it
needs no change; the meta and og descriptions are separate
text and stay as they are.

## Tests

- tests/test_doc36_header_identical.py:63 to 67: rename the
  test to test_header_carries_the_wordmark, drop the two
  .logo-terminal and .logo-bin assertions, keep the wordmark,
  header-right, nav, and label assertions, and add an
  assertion that "logo-terminal" appears in no page.
- tests/test_doc38_visual_system.py section 8 (lines 35 to
  95): delete
  test_logo_terminal_has_no_fixed_width_narrower_than_its_command.
  Rewrite test_header_logo_text_is_not_clipped_in_a_browser to
  assert, at 1280, 390, and 320: .logo-text scrollWidth equals
  clientWidth and its getClientRects() length is 1 (one line);
  the .logo-text and .nav-link bounding boxes share a vertical
  centre within 1px; at 1280 .header-inner and
  .audit-input-card have the same left edge; and .audit-title
  has one client rect at 1280 and two at 390.
- No existing test asserts the old headline or subtitle text
  (grep confirms), so add one in
  test_doc36_header_identical.py that index.html carries the
  new h1 and the new first sentence.
- Extend the dash test's file list if it does not already
  include static/index.html; the new strings contain no dash
  of any kind.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since style.css changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-50.md in the same commit.

## Done when

The header shows one wordmark at the container's left edge,
vertically centred on the nav, identical on all eight pages
and on one line at 320; the headline is one line at 1280 and
never splits a phrase; the subtitle is four lines at 1280; and
the browser test asserts all of it.
