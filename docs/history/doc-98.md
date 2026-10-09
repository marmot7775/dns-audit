Results page cleanup. Static files and one test. Re-fetch main
first; this was written against 57c6f69.

1. Move the contact note above the services section.

In static/index.html, <p class="results-contact-note is-hidden"
id="results-contact-note"></p> sits after #services-section. Move
it so it sits after #draft-standards-section and before
#services-section. The note says "Some of these are a five-minute
DNS change", and in its current spot "these" reads as the collapsed
services list instead of the findings. No JS change; it looks the
element up by id.

2. Center the Run Another Audit and Export CSV pair on desktop.

In static/style.css, .run-another-btn (line 3217) has margin: 0
auto. Inside .run-another-inner, a flex row with justify-content:
center, the auto margins absorb the free space and push Export CSV
to the right edge. Remove the margin line and keep display:
inline-flex. Check the 768px column layout and the 640px
.run-another-btn rule still look right.

3. Remove the debug details from the results page.

Visitors get nothing from these. Remove all of them:
  The Fresh result / Cached result badge and its Re-run button:
  _renderCacheBadge and its call in app.js, #cache-status-badge.
  The Request ID: _renderRequestId and its call, and the
  .request-id-display rules in style.css, including the 640px
  rule.
  The Audits this session line: the .session-audit-count div in
  the run-another markup, the line that updates it, the
  sessionAuditCount variable and its increment, and the
  .session-audit-count rules, including the sticky one.
  The #results-meta div in index.html and its .results-meta rules,
  once nothing renders into it.
Keep request_id in the API response and the server logs; only the
page display goes. Grep app.js, style.css and index.html for every
name above and leave no dead references. Update
tests/test_results_short_answer.py, which asserts the badge sits
in #results-meta (lines 174 to 176): drop those assertions and add
one that #cache-status-badge, #request-id-display and
.session-audit-count are absent after an audit.

Then run the cache-bust from CLAUDE.md, run the full suite, and
deploy. Verify on the live site with a real audit of github.com at
1280px and 390px wide, scrolled to the bottom: the note sits right
under the last check card, the services heading follows it,
nothing sits between the note and the buttons, the two buttons sit
centered together on desktop, and the sticky bar on scroll still
works. Report what changed, the test count, and what the
screenshots show.
