# Doc 70: The DMARC output overstates the RFC 9989 change

The tag classification is right. I read the whole breakdown on
paypal.com and github.com against RFC 9989: pct, rf and ri are
marked removed, np is marked as imported from RFC 9091, psd
and t are marked new, and the notes on the tree walk, on aspf
covering MAIL FROM only, and on reporting splitting into 9990
and 9991 are accurate. Both validation passes run and
spec_comparison counts the RFC 9989-only findings correctly.
The problem is not the facts, it is what the page says around
them. Three things, all in the DMARC card, all reproduced on
live at f41cf61. Line numbers are from main at 683a82e.

## 1. pct shows a value on records without it

paypal.com publishes v=DMARC1; p=reject; rua=...; ruf=... and
no pct. The tag breakdown row for pct reads "100 (default)"
with the badge "Removed in RFC 9989" beside it. A reader sees
a value for a tag the record does not have, labeled as
removed, and cannot tell whether it is there or not.

result_transformer.py:3188 is the absent branch for pct and
returns _entry(tag, "100", True, True, ...): value "100",
is_default True, is_absent True. app.js:2157 tests is_absent
and value == null first, so a non-null value skips the "not
set" branch and falls through to is_default at 2159, which
prints the value followed by "(default)".

This was already fixed for pct's two siblings. rf at 3204 and
ri at 3219 both return _entry(tag, None, False, True, ...)
with an empty dmarcbis string, and the comment above rf says
why: printing the old RFC 7489 default with a badge sent
readers looking for a tag the record does not contain. pct was
missed.

Make pct's absent branch match rf and ri: value None,
is_default False, is_absent True, dmarcbis empty, explanation
"Not in this record. RFC 9989 removed the tag." The present
branch does not change. Check whether anything downstream
reads the pct entry and expects the string 100; the PDF's tag
table is the likely one.

Leave adkim, aspf, fo and psd alone. Those have real defaults
under RFC 9989, so "r (default)" and "u (default)" are true
statements. pct has no default under 9989 because the tag does
not exist there.

## 2. The readiness score contradicts its own label

github.com's RFC 9989 Readiness header reads: Compatible, 1/4.
Its checklist is one pass, one warn for pct, and two info
rows. Both info rows say in their own text that they are
optional. The np row's note says RFC 9989 section 4.7 does not
require an explicit np tag. The psd row's note says publish it
only if this domain is a public suffix. The score counts them
as misses anyway.

result_transformer.py:1837 computes pass_count as the count of
items whose status is "pass". Items with status "info" are
neither passes nor problems, so a record whose only real issue
is one removed tag scores 1 of 4 while the label beside it
says Compatible.

Change the score to count what the reader is actually being
graded on: numerator is items with status "pass", denominator
is items with status "pass", "warn" or "fail". github.com then
reads 1/2 with one warn to fix. If that reads oddly, the
alternative is to drop the numeric score from the header and
let the label and the per-item icons carry it, which is what
removing the letter grades did elsewhere in this tool. Pick
one, say in the PR which and why, and do not leave a score
that disagrees with the label next to it.

Either way the info rows stay in the checklist with their
notes. They are useful. They are not failures.

## 3. The page never says publication is not deployment

The article at static/articles/dmarcbis.html:226 has the right
sentence: publication is not deployment, most receivers still
evaluate DMARC the RFC 7489 way, tree walk support arrives one
receiver at a time, and the existing record keeps working
throughout. about.html:60 says something similar. The results
page, where a reader decides what to do, says none of it, and
what it does say points the other way.

- app.js:1857 labels the toggle "RFC 7489 (Obsolete)" and 1858
  labels the other "RFC 9989 (Current)". A reader with a
  working enforcing record sees it graded against something
  labeled obsolete.
- app.js:1837 titles the comparison block "This record passes
  under the obsolete RFC 7489 but has issues under RFC 9989".
- app.js:1838 says the RFC 9989-only findings "are problems
  with the record today, not problems it will have later". On
  github.com the one RFC 9989-only finding is pct being
  removed. pct=100 on a live record is honored by receivers
  running RFC 7489, which is most of them, and ignored by the
  rest. Calling that a problem with the record today is a
  claim the audit cannot support.

Three changes.

Relabel the two toggle buttons to "RFC 7489" and "RFC 9989",
leaving the Validation Mode label above them as it is. The
obsolete and current framing goes. If a qualifier is wanted,
"RFC 7489 (what most receivers run)" and "RFC 9989 (published
May 2026)" are both true, but the plain names are enough.

Add one line at the top of the spec toggle bar, visible in
both modes: "RFC 9989 replaced RFC 7489 in May 2026. Most
receivers still evaluate DMARC the RFC 7489 way, so a record
that passes there keeps working. The RFC 9989 view shows what
to clean up." Tighten the wording if you can; the two facts it
has to carry are that 9989 is the standard and that 7489 is
what is running.

Reword 1837 and 1838. The title becomes "This record passes
RFC 7489 validation and has findings under RFC 9989". The
subtitle drops "problems with the record today, not problems
it will have later" and says instead that these are edits
worth making so the record reads cleanly under both specs,
which is the article's own framing and is accurate.

Then read the rest of the DMARC copy for the same
overstatement and list what you found in the PR. The two delta
banners at 1848 and 1851 both say obsolete and need the same
treatment.

## Tests

- Transformer: a record with no pct yields a pct entry with
  value None and is_absent True, matching the shape of the rf
  and ri entries. A record with pct=50 is unchanged.
- Browser: on a fixture with no pct the pct row renders "not
  set" and the string "(default)" does not appear in it; on a
  fixture with pct=50 the row renders 50 with the removed
  badge.
- Transformer: the github.com record shape (p=quarantine,
  sp=reject, pct=100, no np, no psd) produces a readiness
  score matching the chosen rule, and the score never implies
  more failures than there are warn or fail rows.
- Browser: the deployment sentence is present in both toggle
  modes, and the string "bsolete" appears nowhere in the DMARC
  card.
- The tone test's banned-string list gains "obsolete" for the
  results page.
- The PDF still builds and its DMARC tag table shows no value
  for an absent pct.
- Run the full suite and the browser tests.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
No calendar timelines on DMARC monitoring anywhere in this
copy.
Run python3 -m pytest tests/ -q. All must pass.
app.js changes, so cache-bust the asset URLs per CLAUDE.md.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. Main is
at 683a82e and live reports f41cf61, so confirm the deploy
picks up both. After deploy, audit paypal.com and github.com
through the live API and put the pct row and the readiness
score for each in the PR.
Save this doc as docs/history/doc-70.md in the same commit and
add its line to docs/history/README.md.

## Done when

A tag the record does not contain is never shown with a value,
the readiness score agrees with the label beside it, and the
results page tells the reader that RFC 9989 is the standard
and RFC 7489 is what their mail is still evaluated against,
without calling a working record obsolete. Suite passes.
