# Doc 64: Priorities becomes a plan the reader can follow

Doc 63 made the results page short. What is left at the top is
the summary block and the Priorities list, and the list is
where a reader goes to find out what to do. Today it is
one-line rows with no why, no record, and no way to confirm
the change worked; the how is a click away in a card, and for
DMARC the card offers three different recommended records that
disagree. Some of the rows are also wrong, and the summary
above them contradicts them. This doc makes the plan correct,
then makes each row carry what the reader needs. Line numbers
are from main at d396b22. Cross-check them after the Range fix
lands; that fix is in server.py and should not move these.

## 1. Make the plan and the summary say true things

Each of these was reproduced on the live site.

- The deliverability line says "Your configuration looks
  solid. SPF, DKIM, and DMARC are properly set up" whenever
  all three ran, including when one or more is warn
  (result_transformer.py:583 to 587 counts any non-unavailable
  status as assessed and fine). On ibm.com that sentence sits
  under a verdict of "significant gaps"; on github.com under
  SPF at 10 of 10 lookups. Change the length-3 branch: all
  three pass keeps the current sentence; any warn and no fail
  gives "SPF, DKIM, and DMARC are all in place. The plan below
  has what to tighten."; a fail already takes the earlier
  branches at 555 to 573 and stays as it is.
- ibm.com publishes p=reject; sp=none. The attack surface
  panel marks subdomains exposed, the DMARC card says "sp=none
  contradicts your p=reject", and the only DMARC row in
  Priorities is the low "Consider adding an explicit np= tag"
  with the impact "Subdomains already inherit your enforcing
  policy without it", which is false when sp is published
  weaker than p. At 837 to 842: when p is quarantine or reject
  and sp is present and weaker than p, emit a high DMARC row
  "Bring the subdomain policy up to p=" with the impact
  "sp=none leaves every subdomain unprotected while the
  organizational domain is enforced; spoofed mail from any
  subdomain passes" (adjust the sp value in the text), and do
  not emit the np row for that domain. The np row keeps its
  current gate otherwise.
- "Your biggest risk right now" at 522 shows the top item's
  impact alone. For the rows built at 855 to 860 impact is the
  card verdict, so bbc.co.uk showed "SPF record configured" as
  its biggest risk, and the DKIM row's impact begins "These
  keys", which has no antecedent on its own. Show the action
  as the headline and the impact as a second line. For the
  fallback rows at 855 to 860 set impact to the fix text and
  leave the verdict out; if fix and verdict are both empty,
  impact is empty and only the action shows.
- The RFC 9989 readiness rows at 813 to 816 print the raw
  reason string: "Address: Removed tags: pct, ri". Word them:
  for removed tags, action "Remove the tags RFC 9989 retired:
  pct, ri" with impact "Receivers on RFC 9989 ignore them, and
  pct never gave predictable control"; for any other reason,
  drop the "Address:" prefix and use the reason as the action.
  The impact "Record is not fully RFC 9989-ready" goes.
- example.com's DMARC card carries the Warning pill and drives
  the Warnings tile while every detail on it is good or info,
  because 1705 to 1709 strips the rua issue for no-mail
  domains after the engine set the status from it, and 1711
  reads the stale status. Recompute the status from the
  remaining issues after the strip.
- Two Details summaries from Doc 63: app.js
  _subdomainAuditSummary at 1338 to 1345 counts every probed
  name as exposed ("20 of 20 probed subdomains exposed" on the
  fixture, where one of twenty exists). Count rows with exists
  true and status exposed, and word it "1 of 20 probed
  subdomains exists and is exposed" or "N of M probed
  subdomains exposed" when N is more than one, and "M
  subdomains probed, none exposed" when zero.
  _tagBreakdownSummary at 1348 to 1355 counts the fourteen
  tags DMARC defines rather than the tags in the record; count
  tags whose value is present in the record and word it "6
  tags, 2 removed in RFC 9989".

## 2. One DMARC path, not three

Three panels propose a record for the same domain and they do
not agree. On the fixture, RFC 9989 Readiness suggests
v=DMARC1; p=none; sp=none; np=none; rua=..., the Migration
Path ends at p=reject; sp=reject; np=reject, and the Record
Builder recommends p=reject; sp=reject; np=reject. The first
is the minimal edit that keeps the current policy and cleans
the record; the other two are the enforcement end state.
Nothing tells the reader which to paste.

- The Record Builder's recommended_record
  (result_transformer.py:3869 to 4021) derives from the same
  function as the Migration Path's target_record (3835 to
  3847) so they cannot diverge. If the builder has cases the
  migration function does not cover (the no-record case at
  3900), keep those and add a test that the two agree wherever
  both exist.
- Label the two records where they render. The readiness
  record is "Next edit: clean up the record, same policy". The
  migration target and the builder record are "End state:
  enforcement". Under the end-state record, one sentence:
  "Reach this through the migration steps, moving only when
  your aggregate reports show every legitimate sender aligned.
  There is no date on that." Do not add any calendar language
  anywhere in the path.
- The DMARC plan row (section 3) shows the next edit as its
  record. When the domain is already at enforcement and clean,
  the row does not exist.

## 3. Each row carries why, what, and how to confirm

Rename the section heading from Priorities to "What to do".
The tier summary ("1 high, 4 medium") stays. Each row keeps
its icon, protocol, priority tag, and action text, and opens
on click (same pattern as the cards, aria-expanded on the
row). Opened, it shows three short parts in this order:

- Why it matters: the item's impact sentence. Where the item
  comes from a card whose fix text says more than the impact,
  append that.
- What to change: the record. Source it from the card's
  fix_records (host, type, value, with the existing Copy
  button and the propagation note built from ttl_info), and
  for DMARC from the readiness suggested_record when one
  exists, as host _dmarc.domain, type TXT. For items with no
  record to publish (reduce SPF lookups, rotate a DKIM key,
  change nameservers, configure MTA-STS), show the card's fix
  text instead, and where the card carries a step list
  (MTA-STS, TLS-RPT, DANE fixes), show it. No item invents a
  record: if there is no fix_records entry, no readiness
  record, and no fix text, the part reads "See the [protocol]
  card below" with a link that opens the card.
- How to confirm: one line, "Run this audit again after the
  change has propagated. This row disappears when the check
  passes." If ttl_info is available, put the propagation time
  in it.

Keep the row's link to its card (openCard from Doc 63); it
moves to a "Open the DMARC card" link at the end of the opened
row rather than being the whole row's click.

## 4. Fold Authentication Resilience into the card

The Authentication Resilience panel (app.js:721 to 757,
index.html:259) restates the three cards a screen below it.
Remove it from the top of the page. Its risk sentence
(data.resilience.risk, the "p=none is the right starting
point" text) becomes the "Why it matters" text of the DMARC
plan row when the policy is none, and the mechanisms table
moves into the DMARC card's Details as a section titled
"Authentication resilience" with the level pill as its
summary, so nothing is lost. Keep data.resilience in the API
response unchanged; the PDF reads it and Doc 65 will decide
its place there.

## 5. The PDF

Not restructured here (Doc 65). But the PDF's roadmap table
reads the same roadmap items, so the corrections in section 1
reach it. Confirm the PDF still builds and that its roadmap
rows show the reworded actions and impacts.

## Tests

- Transformer: fixture with SPF warn, DKIM pass, DMARC pass
  gives the "all in place" sentence, not "looks solid"; all
  three pass keeps "looks solid".
- Transformer: p=reject; sp=none yields the high "Bring the
  subdomain policy up to" row and no np row; p=reject with no
  sp yields the low np row as before; p=reject; sp=reject
  yields neither.
- Transformer: biggest_risk for a fallback row is never a bare
  verdict; on a fixture whose top item is the weak DKIM key,
  the headline is the action and the second line the impact.
- Transformer: readiness rows never start with "Address:".
- Transformer: no-mail domain with no rua has DMARC status
  pass and the Warnings count excludes it.
- Transformer: record builder recommended_record equals
  migration target_record on every fixture where both exist;
  the labels render once each in the DMARC card.
- Browser: the What to do section renders one row per roadmap
  item; opening a row shows the three parts; the DMARC row on
  the fixture shows the readiness record with host
  _dmarc.example-corp.test; a row with no record shows the
  card link; the resilience panel is absent from the top and
  present in the DMARC Details.
- Browser: Details summaries read "1 of 20 probed subdomains
  exists and is exposed" and "6 tags, 2 removed in RFC 9989"
  on the fixture.
- PDF test: builds for the fixture; roadmap rows contain the
  reworded actions.
- Existing summary, roadmap, tone, and a11y tests updated
  where wording changed; the tone test's banned-string list
  gains "Address:" and "looks solid" for the warn case.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
No calendar timelines on DMARC monitoring anywhere in the path
or the plan text.
Run python3 -m pytest tests/ -q. All must pass.
app.js, style.css, and index.html change, so cache-bust the
asset URLs per CLAUDE.md.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, audit ibm.com and bbc.co.uk through the live API and
put the biggest_risk text and the DMARC roadmap rows for each
in the PR.
Save this doc as docs/history/doc-64.md in the same commit and
add its line to docs/history/README.md.

## Done when

The summary line and the plan never contradict each other or
the cards on ibm.com, bbc.co.uk, github.com, and example.com;
every plan row opens to why, what, and how to confirm, with a
real record or the card's fix text and never an invented one;
the DMARC card shows one next edit and one labeled end state
that agree with the migration path; the resilience panel lives
in the DMARC card's Details; the two Doc 63 summaries are
right; and the suite passes.
