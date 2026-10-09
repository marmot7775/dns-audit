# Article: APRF is now an IETF working group draft

Sent 2026-10-09 with "publish to articles section". Published at
/articles/aprf.

## What shipped beyond the text

- A short version box at the top, as on the other articles, written only
  from facts already in the article.
- No source links (Neil: "no citations in article"). The byline's About
  link is the only link in the article; a test pins that.

## What was taken out

Neil: "if info is proprietary to one person i dont want to publish it".

- One consultant's figures from their own clients' reports (bucket values
  and how they step). The sentence after them became "For a small sender,
  a report may say little more than that some mail arrived."
- The time of day Comcast sends reports. Only that same write-up gives it.
- "since at least June" on Comcast's beta. No second source gives a start
  date.

The passages are redacted from the text below too, since this repo is
public.

Kept, because a second public source says the same thing: the Comcast beta
payloads carry inbox/unwanted and positive/negative with no neutral count,
and sdi is not in use (Spam Resource, July 2026, sample payload).

## Checked before publishing

- Datatracker: draft-brotman-aggregate-performance-reporting -00 on
  2026-03-17, -01 on 2026-09-08, call for adoption 2026-09-24, adopted by
  MAILMAINT 2026-10-08. Authors from Comcast, Iterable, Google.
- Kucherawy's closing note (mailmaint, 2026-10-08) and Brotman's
  September 30 direction on a shared report preamble.
- Draft -01: v=APRFv1 and rua required, mailto list, selector, bare and
  wildcard records with selector precedence, destination validation
  record, sdi up to four parts, one UTC day, selector roll up, file name,
  gzip, volume threshold, sending to any destination not required, ABNF
  still TODO.

## The text as sent (one person's data redacted)

```text
# APRF is now an IETF working group draft

What the new inbox placement report gives you today, and what it
doesn't.

October 9, 2026

A DMARC pass has never told you whether a message reached the inbox.
You publish SPF, DKIM, and DMARC, the mailbox provider checks them,
and DMARC reports tell you whether your mail authenticated. Postmaster
tools count complaints. Seed tests measure addresses nobody reads.
None of it says where your real mail landed. On October 8, the IETF's
Mail Maintenance working group adopted a proposal to change that.

## What APRF is

APRF, Aggregate Performance Reporting, is a proposed standard written
by engineers at Comcast, Iterable, and Google, with Alex Brotman of
Comcast as lead author. The first version appeared in March 2026 and
a revision on September 8.

A mailbox provider that supports it sends a daily report on the mail
you signed: roughly how much went to the inbox, how much it treated
as unwanted, and how recipients reacted. Reports arrive by email as
small data files, the way DMARC reports do, and each covers one day.

The reports are tied to DKIM, not to the From address. DKIM is the
signature your mail server or sending platform adds to each message,
and it names the domain that signed. That choice is deliberate. The
From address says who a message claims to be from. The DKIM signature
says who took responsibility for sending it, and that is what a
provider's reputation system tracks.

## What a report tells you

A report has two parts, and the provider decides whether to include
either. The first is placement: how many messages went to the inbox,
to spam, or to some other folder the provider names. The second is
engagement: how many actions recipients took that the provider counts
as positive, neutral, or negative. The draft leaves those definitions
to each provider, and most will keep them private.

The numbers are rough on purpose. The draft recommends that providers
report each count as the top of a range, a bucket, rather than an
exact figure, and lets each provider pick the bucket sizes. [Redacted:
one consultant's figures from their clients' reports, and a sentence
built on them.]

There are two more reasons not to turn these numbers into an inbox
rate. A bucket is a ceiling, so dividing one by another gives a ratio
nobody measured. And the two halves of a report count different mail.
Placement counts messages received that day. Engagement counts
actions taken that day, on mail from any day.

Comcast's beta reports carry inbox and unwanted for placement,
positive and negative for engagement, and no neutral count.

## Where it stands

APRF is still a draft. On September 24, Murray Kucherawy, one of the
working group's two chairs, opened a call for adoption, and it closed
October 8. His closing note said the responses clearly supported the
draft and that the group would consider it adopted absent an
objection in the final hours. The IETF's records show it adopted that
day. Adoption means the working group now owns the document and will
revise it. It does not make APRF an RFC, the IETF's published
standard. The formal grammar for the record is still marked TODO, and
Brotman has agreed to try, inside the APRF draft, a report header
that other email report types could share. Record details and report
fields could change.

Sending reports is voluntary. Comcast has run a beta for comcast.net
mail since at least June and is the only provider known to send them.
Google is represented among the authors but hasn't said it will send
reports. No other provider has announced support.

## Should you publish a record?

The record takes a few minutes and does no harm if no report ever
arrives. Before you add it, check who signs your mail.

If your email platform signs with its own domain, the provider looks
for the record on the platform's domain, not yours. A record on your
domain will never be read, and any reports go wherever the platform
asks for them, if it asks at all.

If your mail is signed with your own domain, you can publish the
record. That includes the common setup where a platform gives you DNS
records that point your DKIM key at the platform. The platform holds
the key, but the signature names your domain, so the APRF record is
yours to publish.

If you send real volume to Comcast addresses, you'll see placement
data now, and when the next provider turns reporting on, you're
already set up. A day with no report usually means too little Comcast
traffic to report. The draft also lets a provider hold back reports
below a volume threshold, or decline to send to any address it
chooses. Treat the data as what it is: rounded, voluntary, and from
one provider.

dns-audit.com checks each domain you audit for an APRF record, shows
where reports would go, and checks whether an outside destination has
agreed to receive them. The check is for information and doesn't
change your results.

## Technical details

The record is a DNS TXT record at

  <selector>._aprf._domainkey.<signing domain>

where the selector and signing domain are the `s=` and `d=` values in
your DKIM signature. A minimal record reads

  v=APRFv1; rua=mailto:aprf@example.org

The `v` tag must be exactly `APRFv1` and `rua` must be present, or the
provider ignores the record. `rua` takes one or more `mailto:`
addresses separated by commas. A record at
`_aprf._domainkey.<signing domain>`, or a DNS wildcard at
`*._aprf._domainkey.<signing domain>`, covers every selector. A record
for a specific selector takes precedence over either.

If the `rua` address isn't on the signing domain, the draft says the
provider should confirm that the destination domain wants the
reports, as DMARC does for outside report addresses. The destination
publishes a TXT record at

  <selector>.<signing domain>._aprf.<destination domain>

with the value `v=APRFv1`. A wildcard in the selector position accepts
reports for every selector on that signing domain. Without the
record, a provider that follows the draft won't send.

The optional `sdi` tag names a header you sign with DKIM, plus a one
character separator, for example `sdi=Signer-Info,^`. That header can
carry up to four values from broad to narrow, such as brand, stream,
and campaign, and a provider may split the report by them. Those
values appear in the reports, so choose names you don't mind a report
recipient seeing. Comcast's beta doesn't use `sdi` yet.

Reports are JSON, each covering one UTC day for one signing domain
and selector, though the draft lets a provider roll all selectors
into one report. They arrive as an email attachment named
`<yyyymmdd>_<domain>_<selector>_<source>.json`, sometimes gzipped.
[Redacted: one sentence on when Comcast sends reports.]
```
