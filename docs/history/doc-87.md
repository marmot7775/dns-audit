# Doc 87: root type size inherits the reader's setting

Main at 3683076. Re-fetch before starting.

First, cleanup. Close the open pull request for the text size
control, then delete the remote branches
claude/text-size-increase-xp0hio and
claude/text-size-increase-xp0hio-readability. The control is not
wanted. Nothing from those branches is merged; only the idea
below is carried over, reimplemented against current main.

Then the fix. In static/style.css the html rule sets font-size to
16px. Change it to 100% so the site inherits the default text
size the reader set in their browser or OS. Every --font-* token
is already in rem, so text scales with that setting; confirm the
layout tokens (--space-*, --max-width) stay in px so a reader who
scales up gets larger text inside the same containers rather than
a page that grows sideways. Search style.css for any other px
font-size on body text and convert it to rem; leave px sizes on
icons and controls where they are intentional.

Add a test that the html rule's font-size is a percentage, not a
pixel value. Render the home page and a results page at 1280 and
390 in both themes with the browser default at 16px and at 20px,
and confirm nothing overflows sideways and no card clips its own
text.

Save this as docs/history/doc-87.md with its index line. Run the
suite, open a PR, merge on green, deploy, and report the version
from /api/health.
