# Doc 52: The PDF in the site's typefaces

The PDF is the one surface not on the Doc 38 visual system.
The site sets DM Sans for text and JetBrains Mono for records;
pdf_report.py sets Helvetica, Helvetica-Bold,
Helvetica-Oblique (11, 11 and 1 uses) and Courier (two style
definitions and five inline font tags), because those ship
with ReportLab. Embed the site's two typefaces so a client who
reads the PDF beside the page sees one design. Line numbers
are from main at 59b6c59.

## 1. Font files

static/fonts/ holds only woff2, which ReportLab cannot read;
the TTFs were removed at dc00ed4 as unused. Add a top-level
fonts/ directory (not static/, nothing serves it) with the
static TTF builds from Google Fonts: DMSans-Regular.ttf,
DMSans-Bold.ttf, DMSans-Italic.ttf, and
JetBrainsMono-Regular.ttf, plus the two OFL.txt licence files
as shipped. Do not commit the variable-font TTF; ReportLab
needs one file per weight. Record the download source and
version in fonts/README.md (three lines). Check each file
loads with reportlab.pdfbase.ttfonts.TTFont before committing.

## 2. Registration

At module import in pdf_report.py, register the four faces
with pdfmetrics.registerFont(TTFont(name, path)) using the
names DMSans, DMSans-Bold, DMSans-Italic and JetBrainsMono,
then pdfmetrics.registerFontFamily("DMSans", normal="DMSans",
bold="DMSans-Bold", italic="DMSans-Italic",
boldItalic="DMSans-Bold") so the existing <b> tags inside
Paragraph markup resolve to the bold face. Resolve paths
relative to the module file, not the working directory;
server.py is started from the repo root but tests are not
always.

If a font file is missing, fall back to the Helvetica and
Courier names with one logged warning rather than failing the
PDF endpoint; tests/test_pdf_runtime_dependency.py shows the
pattern this module already uses for a missing reportlab.

## 3. Replace the names

Helvetica becomes DMSans, Helvetica-Bold becomes DMSans-Bold,
Helvetica-Oblique (236, the verdict style) becomes
DMSans-Italic, and every Courier, both the two
fontName="Courier" styles and the five <font name='Courier'>
tags (849, 1045, 1114, 1333, 1402), becomes JetBrainsMono. The
canvas call at 267 (c.setFont("Helvetica", 8)) changes too.
Keep every size and leading as it is; DM Sans is slightly
wider than Helvetica, so after the swap render the Doc 38
fixture and the Doc 45 long-record fixture (25 rua addresses)
and confirm no table cell wraps into a new page break or
clips. Adjust a column width only where the render shows it.

Keep the U+26A0 workaround at 95 to 97 as it is; DM Sans has
no glyph there either. The check, cross and bullet glyphs
(U+2713, U+2717, U+2022) must render in DM Sans: assert in the
test below that the PDF's text contains them, and if DM Sans
lacks any of them, keep that glyph on a face that has it.

## 4. Tests

- tests/test_pdf_report_accuracy.py (or a new
  tests/test_pdf_fonts.py): render the fixture, open the bytes
  with pypdf or a regex, and assert the embedded font names
  include DMSans, DMSans-Bold and JetBrainsMono and do not
  include Helvetica or Courier; assert the file is under 250
  KB (it is 28 KB now; four subset fonts should add well under
  100 KB, and the cap catches a full-font embed by mistake).
- Assert the fallback path: with the fonts directory patched
  to an empty temp dir, the PDF still renders and the names
  fall back to Helvetica.

## 5. One stale line

CLAUDE.md:14 says style.css has "5 responsive breakpoints". It
has about nine max-width breakpoints. Delete the number: "all
styles, responsive breakpoints in one file".

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; static/ does not change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, fetch one PDF from the live site and confirm the fonts
are embedded there too, since the droplet must have the fonts/
directory.
Save this doc as docs/history/doc-52.md in the same commit.

## Done when

A PDF from the live site uses DM Sans for text and JetBrains
Mono for records, every glyph renders, no table clips, the
file stays small, the endpoint survives a missing font file,
and the suite passes.
