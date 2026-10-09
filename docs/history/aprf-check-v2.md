# dns-audit: APRF detection, informational only (version 2)

Version 1 is aprf-check.md, which shipped as PR #153. Neil's note with this
version: "Two changes from the last one: a domain with no record gets a
single collapsed line instead of a full card, and the review date check
warns instead of failing the suite, so it can't block an unrelated deploy in
January." The full doc repeats version 1 apart from those two changes; the
changed sections follow word for word.

## The card (changed part)

Not published. This will be the state for nearly every domain, so
it renders as one collapsed line, not a full card:

  APRF, a draft reporting standard, is not published for this
  domain.

Expanding the line shows the shared note, then:

  You aren't missing anything yet. With one provider sending
  reports in beta, publishing a record is worth it only if a
  meaningful share of your mail goes to Comcast addresses.

Check app.js for an existing collapsed or compact card pattern and
reuse it. If there isn't one, use a details and summary element
styled to match the page. Say which you used.

Every other state is a full card that opens with the shared note.

## PDF (changed part)

Render APRF in its own short section after Protocol Details, titled
Draft standards. In the not published state the section holds the
one collapsed line and nothing else. Every other state gets the
shared note and its state text. The section stays off the cover and
out of the table of contents numbering that the cover hardcodes.
The web page and the PDF must say the same thing.

## Keeping the note honest (changed part)

The note states a fact that will go stale. Put a review date of
2026-10-08 beside the constant. Add a test that passes but emits a
pytest warning once 90 days have passed since that date, with a
message saying to recheck provider support and update the note and
date. It must not fail the suite or block a deploy.

## Tests (changed part)

11. Not published renders as the one collapsed line on the web and
    in the PDF, with the note and advice only inside the expanded
    web view.
14. The review date warning from the section above, checked with a
    frozen date on both sides of the 90 day mark.

The other tests are version 1's, renumbered: 12 no count changes, 13 out
of scope runs, 15 no dashes or quotation marks.

## What shipped

- The not published state carries collapsed_line. The web page renders it
  as a details element that reuses the subdomain table's toggle
  (sua-details, sua-toggle, sua-toggle-icon). The note and the advice sit
  only inside its body. It is not a result card, so Expand All leaves it
  alone.
- The PDF prints the line alone under Draft standards.
- The review date test calls a helper that raises an AprfNoteStale warning
  after day 90. A parametrized test checks days 0, 90, 91 and 400.
- Version 1 was already merged and deployed (215387c) when this version
  arrived, because Neil approved that merge first. Version 2 is a follow-up
  branch and is not deployed.
