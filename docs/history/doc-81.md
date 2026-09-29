Nearly. The article text is done; what Claude Code needs is the implementation doc around it, the same shape as Doc 80 for the SPF article. Let me check whether Doc 80 has landed so this one gets the right number and slot.It is, once it is wrapped in the implementation doc. The article text above is final; below is the doc for Claude Code, one purpose, same shape as Doc 80. Numbered 81 on the assumption Doc 80 merged; the first step tells Claude Code to confirm that.

````
# Doc 81: article page for What to check before you publish p=reject

## Context

A fifth article for dns-audit.com. Build it exactly the way Doc 80
built /articles/spf-lookups: same template, same card on the
articles index, same sitemap entry, same tests. Before starting,
confirm Doc 80 is on main and read docs/history/doc-80.md so this
page matches it in every structural detail. If Doc 80 has not
merged, stop and say so.

## Route and metadata

Route: /articles/p-reject

Title: What to check before you publish p=reject

Standfirst (the one line under the title, same element the other
articles use): You have been at p=none for months and the reports
look clean. The DMARC standard adds one requirement before the
last step, and it is the one small setups miss.

Date line: Updated September 2026

Meta description: RFC 9989 makes DKIM on every stream a
requirement for p=reject. Why forwarding breaks SPF, what the
mailing list warning is worth, and when a domain is ready.

Meta keywords: p=reject, DMARC enforcement, DMARC policy, DKIM,
RFC 9989, email forwarding, mailing lists, SPF, p=quarantine,
aggregate reports

## Rules for the body

Use the body below verbatim between the START and END markers.
Do not edit wording, add sentences, or rephrase for tone. Render
the ## lines as section headings, backticked terms in the mono
face the other articles use, the table as a table with the
italic caption under it, the same as the RFC 9989 article.

No em dashes, no double hyphens, no first person anywhere on the
page. The tone test that guards About, Privacy and the existing
articles must also guard this page; add it to that test's page
list. The footer, trust row and identical footer tests must pass
with the page included. No email address appears on the page
except the existing obfuscated footer alias.

The sentence about bulk sender rules at Google, Yahoo and
Microsoft may carry links to each provider's official sender
requirements page only if you fetch each page and confirm it
states that a DMARC policy of none is accepted. If you cannot
confirm all three, leave the sentence unlinked. Do not link to
vendor blogs.

## Articles index and sitemap

Add the card to /articles/ in the same position and format as the
Doc 80 card, with the title and the meta description as the
blurb. Add the route to the sitemap. Do not change the home page.

## Verification

Run the full suite. Render the page at 1280 and 390 in both themes
and confirm no horizontal overflow, the table scrolls inside its
own container on the phone width, and no console errors. Deploy,
then report main SHA and /api/health.

## Body

ARTICLE BODY START

Most DMARC deployments follow the same path. Publish `p=none`,
watch the aggregate reports, fix every legitimate sender that
fails, then publish `p=reject`. Most domains skip quarantine
entirely and go from remediation straight to reject, and that
works. What the vendor guides leave out is that the DMARC
standard published in May 2026, RFC 9989, puts a condition on
that last step. A domain at reject has to sign all of its mail
with DKIM. Not most of it. All of it. This article explains why
the standard says so, what it costs you if you ignore it, and
how to tell when a domain is ready.

One word to settle first. A stream is any system that sends mail
using your domain: your mail server, your marketing platform,
your help desk, your invoicing tool. A company with four of those
has four streams, and each one either signs or it does not.

## A statement that never arrived

The standard explains the DKIM requirement with a bank, and the
example is worth walking through because it is exactly what
happens to small companies.

A bank sends a statement to a customer at an alumni address,
something like `jones@alumni.example.edu`. The alumni association
does not run mailboxes; it forwards everything to the address the
graduate gave them years ago. The same happens with a role
address such as `finance@association.example`, which forwards to
whoever holds the job this year.

When the forwarder passes the statement along, the receiving
server sees a connection from the forwarder's IP address, not the
bank's. SPF works by checking that IP against the list the bank
published, and the forwarder is not on it, so SPF fails. Nothing
was wrong with the bank's SPF record. Forwarding just moved the
message to a server the record does not cover.

DKIM behaves differently. It is a signature the bank's server
adds to the message itself, checked against a key in the bank's
DNS. The forwarder does not touch it, so the signature still
verifies at the final destination. If the bank signed the
statement, it passes DMARC on DKIM and arrives. If the bank
relied on SPF alone, the statement fails DMARC, and at
`p=reject` the receiver bounces it. The customer never sees the
statement and the bank never learns why.

That is the whole argument. Forwarding breaks SPF and leaves
DKIM alone, and forwarding is everywhere: alumni addresses, role
addresses, people who forward their work mail to a personal
account. RFC 7960 catalogs every variety.

## The requirement

So RFC 9989 makes it a rule. A domain that publishes `p=reject`
must not rely on SPF alone for its DMARC pass and must sign its
mail with DKIM. In RFC language that is a MUST, the strongest
word the standard has, and it appears twice: in the section on
interoperability and again in the list of requirements for full
participation. The same standard recommends both SPF and DKIM
for every domain at any policy; at reject the recommendation
becomes a requirement.

In a small company the stream that fails this test is usually a
platform that was added to the SPF record when it was set up and
never configured to sign with the company's domain. It signs
with its own domain instead, or not at all. In the aggregate
reports it shows up as a source that passes SPF and has no
aligned DKIM, where aligned means the domain in the signature
matches the domain in the From address. Every message that
platform sends is one forward away from a bounce. That stream is
not ready for reject, and until it signs, neither is the domain.

## The mailing list warning

RFC 9989 carries a second warning about reject, and it is worth
knowing what it is worth. The standard says a domain whose users
post to mailing lists should not publish `p=reject`. The reason
is the same forwarding problem in a different shape: a list
resends your message to every subscriber from the list's own
server. Where the standard uses should not rather than must not,
it means you may proceed once you understand the cost.

The standard is candid about that cost. In the ten years since
the large consumer mailbox providers started publishing
`p=reject`, mailing list software has adopted workarounds that
rewrite the From address on relayed messages so they pass DMARC
under the list's own domain. The RFC calls those workarounds far
from ideal and firmly established. ARC, a newer mechanism meant
to let lists stop rewriting, had not caught on at publication.

So for most lists, a person posting from a reject domain is
fine, because the list repairs the message before it goes out.
What remains is the list that never adopted rewriting. There,
the receiver rejects the relayed post, the list software reads
the rejection as a dead address, and the subscriber is quietly
dropped from the list. That is a real cost. For most companies
it is also a small one, and most look at their reports, decide
the occasional lost list post is acceptable, and publish reject.
That is a fair reading of the standard, not a violation of it.

## Plan as if reject means reject

The standard also tells receivers not to reject a message solely
because the sender's policy says reject, and to treat failing
mail as quarantine when they have nothing else to go on. Then it
admits, in the same section, that few receivers do any of that,
and that mail relayed through lists without a rewritten From is
frequently rejected under `p=reject`. Take the admission at face
value. Receivers are not going to soften your policy for you.

The one place you will see a receiver deviate is the aggregate
report itself, which has a field for it, PolicyOverride. If a
receiver decides to deliver mail your policy says to reject, that
is where it tells you.

## Why most domains skip quarantine

Under DMARC, quarantine and reject both keep failing mail out of
the inbox at receivers that honor your policy. The difference is
where the mail goes instead. Quarantine sends it to the spam
folder, where the recipient can still open it and be fooled by
it. Reject refuses it during delivery, before the receiver has
accepted it, so a spoofed message produces no bounce and no
trace. For a domain that exists to be trusted, a bank, a payroll
provider, a store sending order confirmations, that difference is
the point of DMARC, and reject is the destination.

The standard prescribes a quarantine stage on the way there,
so you can see what receivers do with failing mail before you
go to reject. In practice most domains skip it. They remediate
at `p=none` until the reports are clean, then publish reject,
and that works because the aggregate reports at none already
show, for every source, whether it passed on DKIM or only on
SPF. Once every source that belongs to you shows aligned DKIM,
the quarantine stage has little left to tell you.

Quarantine earns its place in one situation: a domain with a
stream that cannot be signed yet. Reject is off the table for
that domain by the standard's own rule, and quarantine is as far
as it can go until the stream is fixed. A domain sitting there is
not finished. It is blocked on one sender.

## Which policy for which domain

| Domain | End state | Condition |
| --- | --- | --- |
| Main company domain, the one with people's mailboxes on it | `p=reject` | Every stream signs with aligned DKIM and the reports have settled. The mailing list cost has been looked at and accepted. |
| Transactional or brand domain | `p=reject` | Every platform signs with the domain in the From address. |
| Subdomain dedicated to one sending service, with its own DMARC record | `p=reject` | Moves on its own evidence. A problem with one service does not hold the others back. |
| Domain that sends no mail | `p=reject` plus null MX (RFC 7505) and `v=spf1 -all` | No legitimate mail to lose. |
| Any domain with a stream still passing on SPF alone | `p=quarantine` at most | Reject is prohibited until the stream signs. |

*Reject is the end state for every domain that can meet the DKIM
requirement. Quarantine is where a domain waits when one cannot.*

## When a domain is ready

List every domain and subdomain that sends mail and give each
its own DMARC record. For each one, readiness is two questions.
Does every source in the reports that belongs to you show an
aligned DKIM pass, not just an SPF pass? And has the list of
sources stopped changing?

The second question is the one that takes time. The standard
says the process can take many months depending on how often a
domain sends, and it often takes longer than that, because a
system that sends once a quarter does not appear in the reports
until it sends. Waiting costs nothing. The standard requires
receivers to leave mail handling unchanged under `p=none`, and
the bulk sender rules at Google, Yahoo and Microsoft require a
DMARC record but accept `p=none`. Nothing about inbox placement
forces the move to reject. The reports tell you when.

The guides are right that reject is where a domain should end
up. They leave out the condition the standard now attaches to
it. A domain at `p=reject` with a stream on SPF alone is not
finished. It is losing mail every time someone forwards a
message, and the standard says it should not be there.

## Where this comes from

RFC 9989, Section 7.4, has the bank example, the DKIM
requirement, the mailing list warning, the staging advice, and
the admission about receivers. Section 8 repeats the DKIM
requirement and the receiver rule as conformance requirements.
Section 5.4 covers what receivers do with `p=none` and the
PolicyOverride field. Section 4.5 recommends SPF and DKIM
together. Section 5.1.7 says enforcement may take many months.
Section 3.2.9 defines enforcement and Section 7.2 explains why
rejecting during delivery beats bouncing. RFC 7960 catalogs
indirect mail flows, RFC 7505 defines the null MX, and RFC 8617
defines ARC.

dns-audit.com reads your DMARC record, checks the DKIM selectors
you have published, audits which subdomains exist and what policy
each inherits, and evaluates the record under both RFC 7489 and
RFC 9989. It cannot see which streams are signed; your aggregate
reports do that.

ARTICLE BODY END
````

When it reports back, the two things to check are the main SHA against /api/health and whether it linked the three provider pages or left the sentence plain. The DMARC card check for a domain at p=reject with no DKIM selectors is separate and stays out of this doc.
