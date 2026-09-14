# Doc 50: Put the Sept 9 home page back, and the iPad summary row

Replaces the earlier Doc 50 draft about the header and
headline; if that one was pasted, this supersedes it. The home
page as it stood on the morning of Sept 9 (git f1caf02~1,
before "Homepage wording, layout, and type: input first") is
the look to restore: a short title, one sentence under it, the
scope buttons, then the input. The audit form is the point of
the page and the current hero pushes it down. Line numbers are
from main at e1f3506. Render before and after at 1280, 1024,
820, 768, and 390 in both themes; keep the screenshots out of
the commit.

## 1. Header: the old wordmark, no terminal chip

static/index.html:123 to 134 and the same block on the other
seven pages: delete the whole <div class="logo-terminal"> and
make the link exactly what it was on Sept 9:

<a href="/" class="logo"><span class="logo-text">dns<span
class="logo-accent">-audit</span>.com</span></a>

Delete the chip CSS: .logo-terminal, .logo-titlebar, .logo-dot
and its three colours, .logo-cmd, .logo-prompt, .logo-bin,
.logo-flag and the comment above it (static/style.css:376 to
436), the breakpoint copies at 3342 to 3349, 4191 to 4193 and
8473 to 8477 with their comment, and gap on .logo at 366. Keep
.logo-text at var(--font-lg) 700 and .logo-accent as they are;
at 3351 make the small-screen size 1rem instead of 0.88rem and
delete the 0.82rem override at 4195 to 4197. The wordmark
stays on one line beside Home, Articles, About and the toggle
at 390 and 320.

## 2. Hero: the Sept 9 copy and size

static/index.html:153 and 154, replace the h1 and the
paragraph with the Sept 9 text:

<h1 class="audit-title">DNS &amp; Email Security Audit</h1>
<p class="audit-subtitle">Most DNS tools show you your
records. This one tells you what is wrong with them. Includes
<a href="/articles/dmarcbis" class="audit-subtitle-link">RFC
9989 readiness</a>, DNSSEC validation, and more.</p>

static/style.css:557 to 573: .audit-title keeps
var(--font-3xl) and 700 but margin-bottom becomes
var(--space-sm); .audit-subtitle loses max-width: 64ch and its
margin-bottom becomes var(--space-md). Delete the @media
(min-width: 768px) block at 575 to 582 that raises the title
to var(--font-4xl) with text-wrap: balance; the title is one
line at every width above 400 without it. On Sept 9 the title
measured 34px tall and the whole card 444px at 1280; now it is
82px and 587px. Land within 20px of the old card height.

## 3. Form back under the scope buttons, and focus in the input

Move the <form id="audit-form"> block (index.html:155 to 177)
back below the scope section, where it sat on Sept 9, so the
order inside .audit-input-card is title, sentence, Audit scope
buttons and their description, then the input row and the DKIM
selector toggle. Centre the selector toggle under the input as
it was: .selector-toggle-row text-align back to center. Keep
everything else about the form as it is now: the example.com
placeholder, the valid-domain indicator, the button, the Doc
48 spacing.

Add autofocus to #domain-input so the cursor is in the field
when the page opens. Nothing in the repo's history ever set
it; the field is focused only after Run another audit and the
R shortcut. Keep both of those. On iOS and iPadOS autofocus
places the caret without raising the keyboard, which is the
platform's behaviour and fine. Add nothing else that moves
focus on load.

## 4. iPad: five summary tiles in one row

On the results page between 769 and 1024 wide,
static/style.css:7746 to 7752 forces .summary-grid to four
columns and gives .summary-card.unavailable-card grid-column:
1 / -1, so when Not checked is shown the fifth tile becomes a
full-width slab under the other four (seen at 820 with the Doc
38 fixture). The :has rule at 1096 that switches to five
columns never wins there because the media block comes later.
Fix: inside that media block, set
.summary-grid:has(.unavailable-card:not(.is-hidden)) to
repeat(5, 1fr) and delete the grid-column span; the tiles are
about 140px each at 820, which the 1280 layout already uses at
160. At 768 and below (3452 and 7758) the fifth tile may keep
spanning both columns, but give it a row layout there: label
and number on one line, padding 0.75rem 1.1rem, so it reads as
a footnote and not as a fifth big tile.

## Tests

- tests/test_doc36_header_identical.py:63 to 67: rename the
  test to test_header_carries_the_wordmark, drop the
  .logo-terminal and .logo-bin assertions, assert the exact
  <a> line from item 1 on every page, and assert
  "logo-terminal" appears in no page.
- tests/test_doc38_visual_system.py section 8 (35 to 95):
  delete
  test_logo_terminal_has_no_fixed_width_narrower_than_its_command;
  rewrite test_header_logo_text_is_not_clipped_in_a_browser to
  assert at 1280, 390 and 320 that .logo-text has one client
  rect and scrollWidth equals clientWidth.
- Add to test_doc36: index.html has the h1 and sentence from
  item 2, #domain-input carries autofocus, and .scope-selector
  comes before #audit-form in source order.
- Add a browser test on the Doc 38 fixture at 820 wide: the
  five .summary-card tops are within 2px of each other when
  .unavailable-card is shown, and at 1280 the same.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since style.css changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-50.md in the same commit.

## Done when

The home page at 1280 matches the Sept 9 layout: one wordmark,
a one-line title, one sentence, the scope buttons, then the
input with the cursor in it; the card is within 20px of its
Sept 9 height; and at 820 the results summary is one row of
five tiles.
