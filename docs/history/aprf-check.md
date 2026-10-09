# dns-audit: APRF detection, informational only

Repo state this was written against: main at 63d94bc. Re-fetch
before starting. If main has moved, check that the functions named
below still exist under those names before changing anything.

## Goal

Detect whether a domain publishes an APRF record and explain what
that means. This check is educational. It never affects a score,
the cover tally, Protocol Coverage, the roadmap, the executive
summary, or the biggest risk callout. Every state of the card says
plainly that APRF is a draft and that one provider sends reports,
in beta.

## What APRF is, for your reference

The source is draft-brotman-aggregate-performance-reporting-01,
dated 8 September 2026. It's an individual Internet-Draft with no
formal standing. The mailmaint working group has issued a call for
adoption. It expires 12 March 2027.

A mailbox provider that supports it emails the DKIM signer a daily
JSON report for one UTC day. The report holds placement counts
(inbox, unwanted) and engagement counts (positive, neutral,
negative). Values are bucketed and reported at the bucket's upper
bound, so they are not exact counts.

Discovery is keyed on the DKIM signature, not the From domain. For
a signature with s=sel1 and d=example.org, the receiver checks, in
order of specificity, with the most specific match winning:

1. sel1._aprf._domainkey.example.org
2. *._aprf._domainkey.example.org
3. _aprf._domainkey.example.org

Section 4.2 of draft 01 lists the selector form as
selector1._domainkey.email.example.org, without the _aprf label.
That reads as a typo, because section 4 defines the name as
<s>._aprf._domainkey.<d>. Implement section 4, and put a comment
citing both sections.

Record rules from section 4.1. v must be present and equal APRFv1,
or the record is ignored. rua must be present, each destination
prefixed mailto:, comma separated, or the record is ignored. sdi is
optional. Parse it and show it, but don't validate its contents.

Destination validation, section 9. When a report address is on a
domain that does not match the DKIM domain, the receiver SHOULD
check for a TXT record at
<selector>.<DKIM domain>._aprf.<report destination domain>
whose value is v=APRFv1. The selector or DKIM domain labels may be
a wildcard. Treat match as the same organizational domain, the way
DMARC external destination checks already do in this codebase.
Reuse that logic rather than writing a second version.

As of 8 October 2026, Comcast is the only provider sending reports,
in beta, for comcast.net recipients only. Google co-authored the
draft but Gmail does not send reports. No other provider has
announced support.

## The lookups

Run the check only in the complete and email_full scopes. Do not
add it to ALL_SCOPE_CHECK_KEYS unless the cover denominator work
below requires it, and say which you chose.

1. Query _aprf._domainkey.<domain>.
2. Query <random label>._aprf._domainkey.<domain> with a fresh
   random label per audit. An answer there means a wildcard exists.
3. For each live selector the DKIM check found, query
   <selector>._aprf._domainkey.<domain>. Cap this at 10 selectors.
   Revoked keys don't count, so use _split_dkim_selectors.
4. For each rua destination on a different organizational domain,
   query the section 9 authorization name, using the real selector
   where one applies and a random label otherwise. Cap at four
   destinations.

Step 3 needs DKIM results, so run the selector lookups after the
DKIM future resolves, inside the existing wall clock budget. If
DKIM timed out or found no live selectors, run steps 1, 2, and 4
and say on the card that selector specific records were not
checked. Keep the added work to these few TXT queries. The DKIM
starvation fix depends on Phase 2 staying light, so don't put the
lookups on _dkim_executor.

A failed lookup is not an absent record. SERVFAIL, timeout, or any
exception sets lookup_failed and produces the unavailable card via
_lookup_unavailable_card. This codebase has shipped that bug in
DNSSEC, CAA, and Nameservers. Don't add a fourth.

## The card

Title: APRF (draft standard). Status is informational in every
state. Read _tally in pdf_report.py and statusCounts in app.js and
pick a mechanism that keeps this card out of every count, on the
web and in the PDF alike, then report what you chose. Don't invent
a new status string that _tally will log as unrecognised.

Every state opens with this note, kept in one constant:

  APRF is a proposed standard that is not yet adopted. A mail
  provider that supports it sends you a daily report on how much
  of your mail reached the inbox and how recipients reacted to it.
  As of October 2026, only Comcast sends these reports, in beta,
  and only for mail delivered to Comcast addresses. This check is
  for information and does not affect your results.

Pill labels and state text:

Not published:

  No APRF record found. You aren't missing anything yet. With one
  provider sending reports in beta, publishing a record is worth
  it only if a meaningful share of your mail goes to Comcast
  addresses.

Published:

  An APRF record is published at <name>. Reports go to <rua list>.

Add this line in the published state:

  Reports cover only mail signed with DKIM as <domain>. If an
  email service signs your mail with its own domain, reports for
  that mail go to the service, not to you.

When a destination lacks the section 9 record:

  Reports are set to go to <destination>, which is on a different
  domain. Under the draft, that domain should publish a record
  allowing reports for <domain>. None was found, so providers may
  not send reports there.

Ignored, meaning the record exists but breaks a section 4.1 rule:

  A record exists at <name>, but a provider following the draft
  would ignore it because <reason>.

Reasons are missing or wrong v tag, or no mailto destination in
rua.

Unavailable: the standard unavailable card.

No state carries fix text, a roadmap entry, or a severity above
info. Name the record location in every published or ignored
state, since the wildcard and bare forms both exist.

## PDF

Render the card in its own short section after Protocol Details,
titled Draft standards, with the same note and state text. It
stays off the cover and out of the table of contents numbering
that the cover hardcodes. The web page and the PDF must say the
same thing.

## Log

Check whether the audit log already records per card status. If
it doesn't, add one field: aprf with values none, published,
ignored, or unavailable. The goal is an adoption count later.
Update test_audit_log_schema to match.

## Keeping the note honest

The note states a fact that will go stale. Put a review date of
2026-10-08 beside the constant and add a test that fails 90 days
after it, with a message saying to recheck provider support and
update the note and date. That makes the review happen rather than
relying on someone remembering.

## Tests

Each test runs offline with mocked DNS.

1. Bare record found and reported with its location.
2. Wildcard found through the random label probe.
3. Selector record found, and it wins over bare and wildcard.
4. Missing v tag, and v=APRFv2, both give the ignored state.
5. Missing rua gives the ignored state.
6. Two rua destinations are both listed.
7. Same organization destination needs no authorization lookup.
8. Cross domain destination with and without the section 9 record.
9. DKIM timed out, so selector lookups are skipped and the card
   says so.
10. SERVFAIL on the bare name gives unavailable, not not published.
11. The card changes no count: tally, Protocol Coverage, roadmap,
    executive summary, and biggest risk are identical with and
    without it, on the web and in the PDF.
12. Out of scope runs (dmarc, transport, dns_infra, security_scan)
    make no APRF queries and show no card.
13. The review date test from the section above.
14. Card copy contains no dashes and no quotation marks.

## Workflow

Work on one branch. Run the full suite before and after, and give
both counts. Don't deploy. Report back inline in one fenced
markdown block: what changed, the counting mechanism you picked,
whether you touched ALL_SCOPE_CHECK_KEYS, the test count, and
anything in the draft that didn't match this doc.

## Later, not in this doc

An article on the site explaining the check. It waits until the
check has run long enough to produce adoption numbers from the
log.

(Neil, when sending this doc: hold off on the article; ignore that
part for now.)

## What shipped

- Counting: the card is not in checks. It goes in a separate
  draft_standards list in the response, which _tally, statusCounts,
  Protocol Coverage, the plan, the executive summary and the biggest
  risk callout never read. Its status is the existing neutral
  "absent" (or "unavailable"), with its own pill labels: Not
  published, Published, Ignored, Not checked.
- ALL_SCOPE_CHECK_KEYS unchanged.
- Web: a Draft standards section after the check cards. PDF: an
  unnumbered Draft standards section after Checks, not in the
  contents.
- Log: new aprf field, present only when the check ran.
- The DMARC external destination rule moved into _report_org_domain
  and _is_external_destination, used by both checks.
- Judgement calls: only a TXT answer whose v tag starts APRF, or
  that has no v tag and an rua tag, counts as an attempt at an APRF
  record, so a DKIM or apex wildcard answer is not read as an
  ignored APRF record. A selector name that answers with the
  wildcard's own record is the wildcard, not a selector record. A
  failure on any discovery name (bare, probe, selector) gives the
  unavailable card; a failure on a section 9 name marks only that
  destination as not checked.
- Found on 8 October 2026: the IETF datatracker moved the draft
  from Call For Adoption to Adopted by a WG (MAILMAINT) that day.
  The note says "not yet adopted"; it was kept word for word and
  flagged for Neil.
