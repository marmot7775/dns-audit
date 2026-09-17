# Doc 57: The DMARC article, rewritten

Copy only, for static/articles/dmarcbis.html. The article is
written as a viral post: one-line paragraphs, "Here is the
part that matters", "I need to tell you something mildly
absurd", pull quotes, a tribute ending. Replace the prose with
the text below, word for word, and keep every fact, link, code
element, the changes table, the two-column tree walk figure,
the ordered step list, the closing call to action, and the
page's head and meta. Nothing technical changes. Line numbers
are from main at d851277.

## 1. Title and head

- The title element becomes "What RFC 9989 changes for your
  DMARC record | dns-audit.com". The h1 (line 60) becomes
  "What RFC 9989 changes for your DMARC record". The
  dbis-article-sub (61) becomes "DMARC is on the Standards
  Track. The Public Suffix List is out, the DNS tree walk is
  in, and your record needs a few small edits."
- The meta description, og:description, and
  twitter:description become: "DMARC is now RFC 9989. What the
  tree walk replaces, why the Public Suffix List is out, and
  the five small edits your record needs."
- The article-card-meta "Updated" time (62) becomes the deploy
  month.
- On static/articles/index.html, the card for this article
  (the h2 currently "RFC 9989" and its blurb) takes the new h1
  as its title and this blurb: "DMARC is on the Standards
  Track. The Public Suffix List is out, the DNS tree walk is
  in, and your record needs a few small edits." Keep the
  card's date and read time; recompute the read time from the
  new word count at 200 words a minute.

## 2. Body

Replace everything from the first dbis-lede (63) to the end of
the article (the section after the dbis-closing div) with the
following. Keep the class names shown in brackets; the two
pull quotes are deleted; the figures stay exactly where they
are marked.

[dbis-lede] For most of its life, DMARC has depended on a text
file. Before a receiver can check your policy it has to work
out your organizational domain, and for that it consulted the
Public Suffix List, a catalogue of every registry-controlled
suffix on the internet, maintained by volunteers. RFC 9989
replaces that list with a DNS lookup. This article covers what
changed, why, and the handful of edits your own record needs.

[dbis-section, no heading]

DMARC policy lives at the organizational domain, and alignment
is judged against it. So before a receiver can do anything
with a message from mail.example.co.uk, it has to decide
whether the organizational domain is example.co.uk or co.uk.
RFC 7489 answered that with the Public Suffix List: find the
longest public suffix, add one label, and that is your
organizational domain. The list began as a Mozilla project in
2007 for scoping browser cookies, and DMARC borrowed it
because nothing better existed.

It worked, and it worked because volunteers kept it current
through every new TLD and every private suffix for more than a
decade. But it was a dependency the protocol did not own: an
external file that every receiver had to download, cache, and
refresh, with no standard saying how often. Two receivers
holding copies of different ages could reach different
organizational domains for the same message, and neither would
know.

[dbis-section] h2: DMARC was never a standard until now

RFC 7489, the document everyone deployed, was Informational.
It was published in 2015 on the Independent Submission stream,
so it never went through IETF working group consensus, and
vendors had room to interpret it, which some of them used.
Operators deployed it anyway. They compared notes in forums
and in groups like the Messaging, Malware and Mobile
Anti-Abuse Working Group, built tooling, and worked out from
aggregate reports what each alignment failure meant. By the
time Gmail and Yahoo required DMARC from bulk senders in 2024,
the practice was mature; the mandate made it compulsory.

The revision went by the working group name DMARCbis for
years. In May 2026 the IETF published it as three Standards
Track documents: RFC 9989 for the protocol, RFC 9990 for
aggregate reporting, and RFC 9991 for failure reporting.
Together they obsolete RFC 7489. RFC 9989 also retires RFC
9091, the experimental public suffix domain spec, and keeps
its psd tag. Now that it is published, the standard is RFC
9989, and that is the name to use.

[keep the dbis-table-fig figure here, unchanged]

[dbis-section] h2: The tree walk replaces the list

Under RFC 9989 the receiver asks DNS directly. It queries
_dmarc at the From domain first. If a record is there, that is
the policy and no walk happens. If not, it moves up one label
at a time, querying _dmarc at each parent, capped at eight
queries so a domain with fifty labels cannot tie a receiver
up. The walk stops early only at a record carrying psd=y or
psd=n. Otherwise it runs to the top, and the record with the
fewest labels marks the organizational domain.

The walk finds the organizational domain, not the policy. A
receiver still uses the From domain's own record when there is
one, and falls back to the organizational domain's record only
when there is not.

[keep the dbis-compare figure here, unchanged]

That removes the download, the cache, and the question of
whose copy of the list is current. It also fixes things
operators had reported for years: inconsistent handling of the
list, the unreliable pct tag, and spoofing of subdomains that
do not exist, which the np tag now covers.

Publication is not deployment. Most receivers still evaluate
DMARC the RFC 7489 way, and tree walk support will arrive one
receiver at a time over a long period. Your existing record
keeps working throughout. There is no deadline and nothing to
rush. There are a few edits worth making so the record reads
cleanly under both specs.

[dbis-section] h2: What to change in your record

The heavy lifting is on the receiver side. On yours, it is
five edits you can make in one sitting.

[dbis-steps ol, five items; keep the strong lead and the code
elements]

1. Remove the retired tags. RFC 9989 removes pct, rf, and ri.
   Receivers on the new spec ignore them, and they clutter the
   record. If you were using pct to ramp enforcement in
   stages, there is no replacement: the new t tag is on or
   off, t=y for testing and t=n for enforcement. That is less
   of a loss than it sounds. Receivers applied percentage
   sampling inconsistently, so pct never gave the control it
   promised. Stay at p=none until your aggregate reports show
   every legitimate sender aligning, and use sp to enforce on
   subdomains ahead of the organizational domain if you want a
   staged path.

2. Drop the report size suffix. If a rua or ruf address
   carries a size limit such as mailto:dmarc@example.com!10m,
   remove the !10m. RFC 9989 Appendix C.4 removes that syntax,
   and receivers on the new spec ignore it. The address itself
   is unchanged.

3. Leave psd alone unless you run a public suffix. The tag has
   three values: y for a public suffix domain, n for an
   organizational domain, and u for unknown, which is also the
   default when the tag is absent and lets the tree walk
   decide. Registries and public suffix operators declare
   psd=y. Everyone else can omit it.

4. Consider np=reject while you are still below full
   enforcement. Under RFC 9989 a subdomain that does not exist
   inherits sp if you publish it, otherwise p, so a domain at
   p=reject already covers them. If you are still working
   through your senders at p=none or p=quarantine, np=reject
   stops spoofing of subdomains that are not in DNS, at no
   risk to real mail, because no real mail comes from a
   subdomain that does not exist.

5. Check external reporting authorization. If rua points at a
   domain you do not control, that domain has to publish a TXT
   record at
   yourdomain.example._report._dmarc.thirdparty.example
   containing v=DMARC1, which says it accepts your reports.
   The rule moved from RFC 7489 into RFC 9990, Section 4, and
   the record is unchanged. Most report processors publish it
   for you. Confirm it anyway, because without it receivers
   drop the reports and nothing tells you.

[closing paragraph of the section] Each of these is a small
DNS edit. The tree walk itself is the receivers' work, not
yours.

[dbis-closing div, keep the link] dns-audit.com checks your
record both ways, against RFC 9989 and against RFC 7489, and
shows what changes between them.

[final dbis-section, one paragraph] The Public Suffix List
carried DMARC for more than a decade. RFC 9989 moves that job
into DNS, where a DNS protocol should have kept it.

## Tests

The article link tests (RFC links, header, footer, alias,
dashes) cover this page; run them. Add the page to the tone
test's banned-string scan with these strings: "mildly absurd",
"Here is the part", "You made it work", "in the trenches",
"Now the honest part", "You do not need to panic", "tidy up
your side of the fence".

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; only HTML changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-57.md in the same commit.

## Done when

The article carries the new title on the page, in the head,
and on the articles index; the body is the text above with the
table, the two-column figure, and the step list intact; every
RFC link still resolves; and the suite passes.
