# Doc 73: Collapsed cards take their content out of reach

Main at 3d7ef86. Re-fetch before starting.

## Problem

A collapsed result card hides its body with CSS only:
.result-body is grid-template-rows 0fr with overflow hidden
(style.css ~1530). Nothing sets hidden or inert, so every link,
button and copy control inside a collapsed card is still in the
Tab order and the accessibility tree. The Sept 20 review counted
44 focusable children on one page. A keyboard user tabs into
content they cannot see; a screen reader reads it.

The expanded state is set in four places, each toggling the class
and aria-expanded by hand:
- header click, app.js ~1090
- header Enter or Space, app.js ~1104
- the Expand all / Collapse all button, app.js ~3583
- openCard(), app.js ~3599
Also check anywhere cards are expanded at render (failures and
warnings open by default) and include it.

## Fix

One helper, e.g. setCardExpanded(card, open), that sets the
expanded class, aria-expanded on the header, and the inert
attribute on .result-body (inert when closed, removed when open).
Route every site above through it, and call it at render so a card
that starts collapsed is inert from the first paint.

Keep the open and close animation. inert does not affect layout,
so the grid-template-rows transition should be unchanged; confirm.

The inner Details sections (.cd-body) already use display none via
.is-hidden and are out of scope.

## Tests

Playwright, on the fixture results page:
- Tab from the domain field through the whole page never lands on
  an element inside a collapsed card.
- Open a card with Enter: its links and copy buttons are reachable
  by Tab. Close it: they are not.
- Expand all, then Collapse all: same two checks.
- openCard via a Priorities row: the target is focusable and
  aria-expanded is true.
- A collapsed card's body is absent from the accessibility tree
  (page.accessibility.snapshot or an axe equivalent).

CI-style venv run of the full suite.

## Housekeeping

- Save this doc as docs/history/doc-73.md and add its line to
  docs/history/README.md.
- Cache-bust static assets, since app.js changes.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and the focusable
  element count inside collapsed cards on a live github.com
  results page, before and after.
