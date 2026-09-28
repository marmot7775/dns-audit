# Doc 74: Internal validation codes stay out of the page

Main at cfba467. Re-fetch before starting.

## Problem

Two places print internal rule codes (SINGLE_RECORD, V_FIRST,
PCT_REMOVED and the rest) next to the plain message:

- Strict validation list, app.js ~2101, <code class="sv-check-code">.
  Shown on desktop, hidden under 640 px by style.css ~4980, so
  desktop and phone readers see different pages.
- RFC 9989 delta callout, app.js ~1867,
  <span class="st-future-code">. Shown at every width.

The codes mean nothing to a reader and look like debug output.

## Fix

Stop rendering both elements. Keep the code field in the JSON; API
users and tests may rely on it. Delete the .sv-check-code and
.st-future-code rules and the media query line that hid one of
them, plus any layout rule that only existed to make room for them.

Read every message these lists can show and confirm each one stands
alone without its code. If any message only makes sense with the
code beside it, rewrite that message in plain words.

Check the PDF: if pdf_report.py prints these codes anywhere, remove
them there too so web and PDF agree.

## Tests

- Rendered results page for a fixture with strict-validation
  findings and RFC 9989-only items: no element carries either
  class, and no text node matches ^[A-Z][A-Z0-9_]{3,}$.
- The API response still includes code on each item.
- CI-style venv run of the full suite.

## Housekeeping

- Save as docs/history/doc-74.md, add its line to
  docs/history/README.md.
- Cache-bust static assets.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and a live github.com
  strict-validation list at 1280 and 390, showing they match.
