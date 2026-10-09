# Doc: APRF check, verify against the draft and our own record

## Why
dns-audit.com publishes an APRF record at the no-selector name
and nowhere else. If the APRF check from PR #153 only looks up
the selector or wildcard names, an audit of dns-audit.com reports
no APRF record. That is a false statement on our own domain.

## Facts to work from
- Live record, checked Oct 9 2026 over DoH with the AD flag set:
  _aprf._domainkey.dns-audit.com TXT
  "v=APRFv1; rua=mailto:<our alias>"
  No wildcard record and no per-selector records exist.
- draft-brotman-aggregate-performance-reporting-01 section 4.2
  gives the discovery order as:
  1) _aprf._domainkey.<d>
  2) *._aprf._domainkey.<d>
  3) <selector>._aprf._domainkey.<d>
  The draft says the most specific match wins, the reverse of
  that list. Item 3 in the draft text leaves out the _aprf label.
  Treat that as a typo, since section 4 defines
  <s>._aprf._domainkey.<d>.
- Section 4.1: v is required and must be APRFv1. A record with no
  rua MUST be ignored. Each rua destination needs its own mailto:
  and destinations are separated by commas. sdi is optional.
- Section 4.1.1, the record ABNF, is still marked TODO. Whitespace
  after a semicolon is therefore undefined. Accept it, the way
  DMARC parsing does, and do not grade it as an error.

## Tasks
1. Find out whether the draft is a working group draft. Check the
   datatracker for draft-ietf-mailmaint-aggregate-performance-
   reporting. Report its latest revision and date. If it does not
   exist, list every place that calls APRF a working group draft:
   the article, the og-card-aprf.png tag, the app copy, and the
   README. Do not change them yet.
2. If the WG draft exists, diff its section 4 against the facts
   above and report any change to the names, tags or discovery
   order before writing code.
3. Read the APRF check and report exactly which names it queries
   and in what order.
4. Run the check against dns-audit.com through the real audit
   path on marmot, not from a cloud container, where TXT lookups
   time out. Report what the card says.
5. If the check misses the no-selector record, fix it so it
   queries all three forms and applies the most specific match.
   Add tests with mocked DNS for each form on its own, for wildcard
   plus no-selector (the wildcard wins), for a record with no rua
   (ignored), and for a space after a semicolon (accepted).
6. Use example.org addresses in the tests. Do not commit our
   real report address anywhere in the repo.

## Constraints
- The check stays informational and unscored.
- Leave /tmp/aprf-fix from the other session untouched.
- One PR. Run the full suite and report the count before and
  after.

## Report back
The datatracker result, the names the check queries, the card
text for dns-audit.com before and after, the test count, and the
PR number.

## What happened (2026-10-09)
- No draft-ietf-mailmaint-aggregate-performance-reporting exists.
  draft-brotman-aggregate-performance-reporting is at -01
  (2026-09-08). Its stream moved to IETF / MAILMAINT on 2026-09-24
  and its state changed to "Adopted by a WG" on 2026-10-08. No
  revision under the draft-ietf name has been posted yet.
- The check already queries all three forms in one parallel batch:
  _aprf._domainkey.<d>, a random label under it (wildcard probe),
  then <s>._aprf._domainkey.<d> for up to 10 live DKIM selectors.
  Records rank selector, wildcard, bare; the first valid one wins.
- dns-audit.com on marmot and on production: Published at
  _aprf._domainkey.dns-audit.com. No code change was needed.
- Tests added for the gaps: bare only beside live selectors (all
  three forms queried), selector on its own, wildcard over bare
  with different records, whitespace after a semicolon.
