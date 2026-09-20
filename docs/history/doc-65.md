# Doc 65: The PDF gets the same shape as the page

The web results page is now summary, plan, checks, with the
evidence one click down (Docs 63 and 64). The PDF still has
the old shape. On the fixture at 49064b3 it is 19 pages, and
the order is cover, Executive Summary, Priorities, DMARC Deep
Dive (five pages: validation checklist, tag breakdown,
configuration analysis, record builder), Attack Surface
Analysis (two pages with the twenty-row subdomain table),
Protocol Details (six pages, each check with its details,
explanation, fix, and the SPF and DKIM deep tables), Migration
Path (two pages), About. A reader who wants to know what to do
has to pass the five-page deep dive to reach it, and the
Priorities table gives one line per item with no record. A PDF
cannot collapse, so the hierarchy has to come from order and a
labeled appendix. pdf_report.py only; the data it reads does
not change. Line numbers are from main at 49064b3.

## 1. Two parts

The report becomes two parts with a divider page between them.
Part 1 is the report: everything a reader needs to decide and
act. Part 2 is the appendix: the evidence, for the reader who
wants to check the work. The cover's table of contents (the
builders list at _build_sections, 1766 to 1800, and
_cover_page at 348) lists both parts, with a one-line note
under the list: "Part 1 is the report. Part 2 holds the detail
behind it."

Part 1, in order:

1. Summary. _executive_summary_page (529) as it is: verdict,
   the three tiles, biggest risk with the action as the
   headline and biggest_risk_detail as the line under it (Doc
   64 made those two fields), the deliverability line, and the
   attack surface overview at 630 stays here because it is
   four lines.
2. What to do. _roadmap_page (669) renamed to match the site.
   The tier counts stay. The table is replaced by one block
   per item, in roadmap order, each with the same three parts
   as the web row: the action as a bold heading with its
   priority tag; "Why it matters" with the impact sentence;
   "What to change" with the record to publish (host, type,
   value in the mono record block, from the card's fix_records
   or, for DMARC, the readiness suggested_record, exactly as
   the web row chooses it) or the card's fix text when there
   is no record; "How to confirm" with the one line from Doc
   64. The "Business Impact" column heading goes with the
   table. No item invents a record.
3. Checks. _protocol_details (1214) becomes the check section
   for all twelve, DMARC included, in the site's card order.
   Each check is compact: name and status pill, the verdict
   line, the record, the detail lines, the fix when the status
   is warn, fail, or absent. The explanation paragraph moves
   to the appendix; the SPF and DKIM deep tables (1226 and
   1234) move to the appendix; vendors (1282) stays at the end
   of this section as it is. Each check ends with one line,
   "Detail in Appendix A" (or the letter that holds it), only
   when the appendix has a section for that check.

A divider page: "Part 2: Appendix" with three sentences: what
the appendix is, that nothing in it changes the plan above,
and that page references from Part 1 point here.

Part 2, lettered A onward, each starting on a new page:

- A. DMARC in depth: what _dmarc_deep_dive (759) builds today,
  in this order: validation checklist, tag breakdown,
  configuration analysis, then the record builder labeled "End
  state: enforcement" (Doc 64 wording) and the readiness
  record labeled "Next edit: clean up the record, same
  policy".
- B. Attack surface and subdomains: _attack_surface_page
  (1012). The subdomain table keeps its rows.
- C. SPF and DKIM in depth: the two deep sections, plus each
  check's explanation paragraph from _protocol_card (1331 to
  1336) for every check, grouped by check.
- D. Migration path: _migration_page (1561), unchanged.
- E. About this report: _about_page (1641), unchanged.

Section numbers in Part 1 are 1, 2, 3; appendix sections are
letters. _section_header (502) takes a string already, so
letters need no change there. Builders that return nothing for
a scoped run still drop out of the TOC as today.

## 2. Pages and words

On the fixture, Part 1 should fit in about six pages: cover,
summary, plan (two pages at most with five items), checks (two
to three pages). Put the fixture's before and after page
counts for Part 1 and for the whole report in the PR. If Part
1 runs past eight pages on the fixture, the checks section is
too loose; tighten the detail lines' spacing before anything
else.

## 3. Cover and header

The cover's findings block, tiles, and the running header and
footer stay. The footer's page number stays as it is. The
"DMARC audited against RFC 9989, 9990, and 9991" line at 1657
is in About and stays there.

## Tests

- PDF builds for the fixture and for a scoped run (dmarc
  scope) and for a domain with no DMARC record (the no-record
  record builder case).
- The cover TOC lists "1. Summary", "2. What to do", "3.
  Checks", then "Part 2" and lettered entries in the order
  above; entries for sections that did not render are absent.
- Page text of the plan section contains "Why it matters",
  "What to change", and "How to confirm" for every roadmap
  item, and for the fixture the DMARC item's record block
  contains v=DMARC1; p=none; sp=none; np=none.
- "Business Impact" and "Address:" appear nowhere in the PDF.
- The DMARC validation checklist text ("Strict Record
  Validation" or its first row) appears only after the divider
  page, and the check section for DMARC appears before it.
- Existing PDF tests (test_pdf_report_accuracy.py,
  test_pdf_rendering_defects.py, test_pdf_dkim_key_columns.py,
  test_pdf_fonts.py) updated where they assert section order
  or the table's column headings; their accuracy assertions
  keep passing.
- No em dashes and no double hyphens in any page's text.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
No calendar timelines on DMARC monitoring anywhere in the PDF.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; static/ does not change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, generate the PDF for github.com through the live
endpoint and put its page count and TOC in the PR.
Save this doc as docs/history/doc-65.md in the same commit and
add its line to docs/history/README.md.

## Done when

The PDF opens as cover, summary, plan with records, checks,
then a labeled appendix holding everything else; the TOC
matches the pages; every plan item carries why, what, and how
to confirm; nothing that was in the PDF before is gone; and
the suite passes.
