# Doc 58: The DMARC article scrolls sideways on phones

One layout defect, reported by Claude Code after Doc 57 and
reproduced here: at 375 and 390 wide, /articles/dmarcbis is
519px wide and scrolls sideways. The other two articles and
the index do not. Two causes, both in static/style.css at main
9b51a51.

## 1. Inline code cannot wrap

static/style.css:6985, .dbis-section code sets white-space:
nowrap. The longest code string in the article,
yourdomain.example._report._dmarc.thirdparty.example, is 424px
wide in the mono face at that size, so it sets the article's
minimum width. Change that rule to white-space: normal and
keep overflow-wrap: anywhere, so a long token breaks inside
the line. Short tokens such as p=reject are unaffected because
they fit. Measured: this alone brings the page from 519 to
384.

## 2. The changes table has a minimum width

.dbis-table th at 6999 sets white-space: nowrap, and the
three-column table then needs 350px, which is more than the
343px the article has at 375 wide. Add a rule for the figure
that wraps it, .dbis-table-fig (none exists yet), with
overflow-x: auto and max-width: 100%, so the table scrolls
inside its own figure on a narrow phone and the page itself
stays at viewport width. The existing .dbis-table-wrap rule at
6988 already does this for another table; reuse its
declarations. Do not remove nowrap from th; the headings read
better unbroken and the figure now contains them.

## Tests

Extend tests/test_visual_system.py: for each of the three
article pages and the articles index, at 375 and 390,
document.documentElement.scrollWidth equals the viewport
width, and no element's bounding right edge exceeds the
viewport by more than 1px except descendants of
.dbis-table-fig. Run the suite.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since style.css changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-58.md in the same commit.

## Done when

No article page scrolls sideways at 375 or 390, the long
report authorization name wraps inside its line, the changes
table scrolls inside its figure if it must, and the suite
passes.
