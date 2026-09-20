# Doc 66: The report still contradicts itself in five places

The shape is right now. What is left are places where two
parts of the same report say different things, or where a line
says nothing at all. Every one was reproduced against the live
site at 5467ed4, mostly on github.com. Line numbers are from
main at 5467ed4.

## 1. The validator passes a tag the card says is removed

github.com publishes v=DMARC1; p=quarantine; sp=reject;
pct=100; rua=...; ruf=...; fo=1. On the DMARC card the strict
validation panel reads "This record passes RFC 9989 strict
validation", 12 of 12, and one of the twelve rows is "pct=100
is valid" (code PCT_VALID). Four inches away the same card
says RFC 9989 §C.5.2 removes pct, the plan carries a medium
row "Remove the tag RFC 9989 retired: pct", and
spec_comparison reports dmarcbis_only_count 0, which the page
reads as the two specs agreeing.

In _validate_dmarc_strict (audit_engine.py:1684 onward) the
pct block at 1829 to 1844 scores a syntactically valid pct as
a pass, and rf and ri get no row at all. The legacy validator
at 2059 to 2069 is right to pass pct, because RFC 7489 has it.

In the strict validator only: pct, rf, and ri each get a warn
row instead. Codes PCT_REMOVED, RF_REMOVED, RI_REMOVED, in the
tag_values category, worded "pct is removed in RFC 9989
(§C.5.2). Receivers on RFC 9989 ignore it." and the same shape
for rf and ri. Keep the existing PCT_INVALID and
PCT_LEADING_ZEROS rows for a malformed value; a removed tag
that is also malformed gets the fail, not the warn. The
summary at 1930 to 1936 then reads "This record passes strict
validation with warnings", which is true, and spec_comparison
(result_transformer.py:2430 to 2460) picks the rows up as RFC
9989-only findings, which is the difference the panel exists
to show.

## 2. A plan row with nothing in it

github.com's plan ends with a LOW row "Review the Certificate
Transparency findings". Opened, it has no "Why it matters" at
all, and "What to change" reads "See the Certificate
Transparency check in section 3". The card it points at has
plenty to say: 58 active certificates, and three warnings
naming subdomains whose certificates expire in 29 and 30 days.

The fallback rows at result_transformer.py:918 to 926 take the
card's fix text as the action and set impact to empty. When
the card has no fix text, as CT does, the row is empty. Fix it
there: when fix is empty, take the card's first detail of type
error or warning as the action and the card's verdict as the
impact. On github.com that gives "16 active certificates will
expire soon. Ensure auto-renewal is working." with "58 active
certs from 8 issuers" under it. If the card has no error or
warning detail either, emit no row at all rather than a row
that says nothing; a card with no fix and no bad detail has
nothing for the reader to do.

Certificates are not renewed in DNS, so this row's "What to
change" should say so rather than showing a record:
"Certificates are renewed with the certificate authority or
the host that issued them, not in DNS." Word that from the
check, not as a rule for every row.

### Follow-up: reorder the CT details

Inside the CT transform only: the summary warning ("16
active certificates will expire soon. Ensure auto-renewal
is working.") comes before the per-certificate "Expiring
in N days" lines, which keep their own order under it.
Nothing else about the card changes, and the rule in
section 2 stays as written: the plan row takes the card's
first error or warning detail.

The reason: the per-certificate lines are evidence for the
summary, so the card reads better with the summary first
whether or not the plan row reads from it, and this keeps
one rule for every check rather than a Certificate
Transparency special case.

## 3. The same ruf note is printed twice

github.com's DMARC card shows, three lines apart:

Forensic reporting (ruf) configured (note: most mailbox
providers do not send failure reports because of PII concerns)

Forensic reporting (ruf) is configured. Most mailbox providers
do not send failure reports because of PII concerns.

Two writers: result_transformer.py:2124 and 2127, and the
engine's own issue at audit_engine.py:633 to 636, which is
merged in downstream. Keep one, the engine's sentence version,
and drop the transformer's duplicate. Check the other detail
lists for the same pattern while in there; report anything
else that prints twice rather than fixing it silently.

## 4. Two number agreements

spf_recursive.py:556 produces "Only 1 slots remain." at nine
lookups, and 564 produces "1 DNS lookups (well within the
10-lookup limit)." at one lookup, next to a correctly singular
"1 include mechanism". Both take the singular.

## 5. A no-mail domain is told about inbox placement

example.com publishes a null MX and gets "Your configuration
looks solid. SPF, DKIM, and DMARC are properly set up, giving
you the best chance of reaching inboxes." It sends no mail, so
there is no inbox placement to speak of.

build_executive_summary (result_transformer.py:206) does not
receive the no-mail flag. The engine has it as is_defensive at
audit_engine.py:5554 and already passes it to the roadmap.
Pass it to build_executive_summary the same way, and when it
is set, the deliverability line becomes "This domain publishes
a null MX, so it sends no mail. Its authentication records are
configured to say so." Nothing else in the summary changes.

## Tests

- Strict validation on a record with pct, rf, or ri emits a
  warn row per tag, the summary says "with warnings", and
  spec_comparison's dmarcbis_only_count counts them; the
  legacy validation for the same record still passes pct with
  no warning.
- A malformed pct (pct=abc, pct=150) still fails in strict,
  and does not also emit the removed-tag warn.
- A fallback roadmap row on a card with no fix text takes the
  first error or warning detail as its action and the verdict
  as its impact; a card with no fix and no bad detail produces
  no row.
- The DMARC details list contains exactly one ruf line.
- "1 slots remain" and "1 DNS lookups" do not appear at any
  lookup count; the nine-lookup and one-lookup fixtures read
  "Only 1 slot remains." and "1 DNS lookup".
- A null-MX fixture gets the no-mail deliverability line and
  never the "reaching inboxes" sentence.
- The tone test's banned-string list gains "slots remain."
  preceded by " 1 " and "Review the Certificate Transparency
  findings".

## Repo rules

No em dashes and no double hyphens in any user-facing text.
No calendar timelines on DMARC monitoring anywhere.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust unless static/ changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, audit github.com and example.com through the live API
and put the strict validation summary, the last plan row, and
the deliverability line for each in the PR.
Save this doc as docs/history/doc-66.md in the same commit and
add its line to docs/history/README.md.

## Done when

The RFC 9989 panel and the plan agree about pct, rf, and ri;
every plan row says why it is there and what to do; no detail
line is printed twice; the singulars are right; a no-mail
domain is not told about inbox placement; and the suite
passes.

## What shipped

All five, plus two things the doc's own text did not predict:

- The SPF card at result_transformer.py:4333 prints the same
  "{n} DNS lookups (well within the 10-lookup limit)" sentence
  as spf_recursive.py:564 and had the same count-of-one bug.
  The test in section 4 says the string must not appear at any
  lookup count, so both writers take the singular.
- Section 2's rule and its worked example disagreed. The CT
  card appends the check's own issues after the
  per-certificate rows, so "the card's first detail of type
  error or warning" was "Expiring in 30 days:
  support.enterprise.github.com", not the summary line the doc
  quotes. Resolved by the follow-up above: the details are
  reordered inside transform_ct and the rule stays as written.

The "What to change" note travels as plan_note on the check's
card, which build_security_roadmap copies onto the row as
what_note, and both renderers print before they look for a
record. It is a per-check field, not a rule in the renderer,
so any later check whose fix is not a DNS record can use it.

Reported, not fixed, per section 3: the CT card prints a CAA
mismatch twice, in two wordings, both from the same
caa_mismatches list. transform_ct writes "CAA allows
[digicert.com] but certs found from Acme R1" and the engine's
own issue writes "CT logs show certificates issued by Acme R1,
but CAA only allows: digicert.com. These may be older certs
issued before CAA was configured." The reorder in this doc
puts the two lines next to each other. Nothing else on any
card repeated: a near-duplicate scan over the live github.com
result and six fixture zones found only the ruf pair this doc
names and the CAA pair above.
