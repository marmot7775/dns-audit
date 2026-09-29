# Doc 80: New article, SPF lookup limit

Main at e64f645. Re-fetch before starting.

A fourth article at /articles/spf-lookups, file
static/articles/spf-lookups.html, built the way Doc 57 and Doc 59
handled the existing three: same page skeleton as
static/articles/dane.html (head, JSON-LD, header, article wrapper,
footer), the prose below word for word, and every place the site
lists an article updated so the tests stay green. Copy only; no
new CSS beyond the one accent rule in section 3.

## 1. The page

- Clone dane.html to spf-lookups.html and replace the head and
  body. The title element becomes "SPF permerror from too many
  lookups: how to get back under 10 | dns-audit.com". The h1 is
  "SPF permerror from too many lookups: how to get back under 10".
  The dbis-article-sub is "The limit is 10 lookups, the order of
  your record decides which sender breaks, and flattening trades a
  problem you can see for one you can't. How to count, what to
  cut, and what to do when cleanup isn't enough."
- Meta description, og and twitter titles and descriptions, and
  the JSON-LD headline and description follow the h1 and the
  subtitle, as the other three do. JSON-LD datePublished and
  dateModified are 2026-09-29. Canonical and og:url point at
  https://dns-audit.com/articles/spf-lookups.
- Body: each line below that stands alone as a heading is an h2.
  Every other block is a p. The two indented SPF records are each
  a pre containing a code element, the record on two lines exactly
  as written. Wrap SPF mechanism and modifier names (include, a,
  mx, ptr, exists, redirect, ip4, ip6, all), record tags such as
  p=reject, header names and header fields (Return-Path,
  Authentication-Results, smtp.mailfrom, spf=pass, dkim=pass) and
  DNS names such as _spf.google.com in code elements, the way
  dmarcbis.html does for tags. Change no wording.
- Further reading section, one entry: a link to
  https://www.rfc-editor.org/rfc/rfc7208 with the text "RFC 7208",
  followed by ", Sender Policy Framework (Kitterman, April 2014).
  Section 4.6.4 is the lookup limit and the void lookup limit,
  section 3.4 the record size guideline." RFC 7208 is the only
  RFC the text names, so this is the only RFC link on the page;
  test_article_rfc_links.py checks that.
- Read time on the card: count the body words and divide by 200,
  rounded, as Doc 59 did.

## 2. Everywhere an article is listed

- server.py: an articles_spf_lookups route beside the other three
  serving the file at /articles/spf-lookups, and a sitemap entry
  {"loc": "/articles/spf-lookups", "changefreq": "monthly",
  "priority": "0.8"} after /articles/dane.
- static/articles/index.html: a filter pill data-filter="spf"
  labelled SPF after DANE, and a new card first in the list
  (newest first), class "article-card article-card-spf",
  data-tags="spf", label tag "SPF", title linking to
  /articles/spf-lookups, description "Ten lookups per check, and
  the order of your record decides which sender breaks. How to
  count, what to cut, and why flattening once by hand makes it
  worse.", time datetime="2026-09-29" shown as "September 2026",
  and the read time from section 1.
- tests/static_pages.py PAGES, test_tone_and_repetition.py
  PROSE_PAGES, test_no_personal_email_in_repo.py,
  test_site_header_identical.py (active nav item "Articles") and
  test_contact_alias.py each get the new page added beside
  articles/dane.html. Any other test that enumerates the article
  pages or counts eight static pages gets the same treatment;
  grep for dane.html to find them.

## 3. One CSS rule

.article-card-spf .article-card-accent and the matching hover
rule for .article-card-title a, following the dmarcbis pattern at
style.css 7336 and 7400, using an existing color token that none
of the three current cards use. Name the token you picked in the
PR description.

## 4. Verify

- pytest passes, including the tone, RFC link, header, footer,
  alias and personal email tests.
- /articles/spf-lookups answers 200 with the article,
  /sitemap.xml lists it, /articles shows four cards and the SPF
  pill filters to the new one.
- Render at 1280 and 390 in both themes: the two pre blocks scroll
  inside their own container and the page does not scroll
  sideways.

## 5. The article

SPF gives a receiver 10 lookups per check. Go past that and some of
your legitimate mail stops passing SPF. Which mail depends on the
order of your record, so the failure is easy to miss and easy to
misread.

RFC 7208 sets the limit and says what counts. Every include, a, mx,
ptr, and exists mechanism costs one lookup, and so does a redirect.
ip4, ip6, and all cost nothing. Includes nest, and the nested ones
don't show up when you read your own record. As of September 2026,
include:sendgrid.net costs two, because SendGrid's record pulls in
one more include. _spf.google.com costs one. For years it pulled in
three more, so the old advice that Google costs four is out of
date. Mailgun costs five.

Order decides who breaks

A receiver reads your record left to right and stops at the first
mechanism that matches the sending server. It counts lookups as it
goes, so it only counts the ones it spent getting to the match. A
sender listed early passes. Senders listed late reach the 11th
lookup and get permerror. Take this record, which a lot of domains
would recognize:

  v=spf1 a mx ptr include:_spf.google.com include:sendgrid.net
  include:mailgun.org include:mail.zendesk.com ~all

Count it. a, mx, and ptr are three. Google is one, four so far.
SendGrid is two, six. Mailgun is five, eleven. Zendesk is one,
twelve. Mail from Google Workspace passes on the fourth lookup and
mail from SendGrid on the sixth. Mail from Mailgun trips the limit
inside Mailgun's own tree and gets permerror, and Zendesk never
gets checked at all. Nobody at the company sees a problem in their
own inbox, because Google is the sender that passes.

The number to fix is still the worst case, every counted term in
the tree, because you don't choose which sender a receiver checks
last. Order is damage control while you fix it. It isn't the fix.

permerror isn't a warning

A message that gets permerror can't pass SPF. DMARC can still pass
on an aligned DKIM signature, and most platforms sign with your
domain when you let them, so the first question is which of your
senders don't. Mail with no aligned DKIM pass fails DMARC.
Receivers honoring p=quarantine or p=reject then send it to spam or
refuse it.

An include that points at a domain with no SPF record is worse than
a wasted lookup. Any check that reaches it returns permerror on its
own. A vendor you stopped paying can pull its record down years
after you added the include, and nothing on your side changes.
There's a second cap on top of the 10. RFC 7208 tells receivers to
allow two lookups that come back empty, meaning the name doesn't
exist or has no record of that type, and to return permerror on
the third. An a or mx term naming a host that no longer exists
spends one of those.

Check where you stand

Run your domain through dns-audit.com. The SPF card gives you the
worst case count, and the lookup tree shows what each include
costs, nested ones too. The audit also flags the other common
permerror, two SPF records at the same name. Your DMARC aggregate
reports show the other side. Each source carries its own SPF
result, so you can see who's already getting permerror before
anyone complains.

Find out which includes matter

Pull a message from each platform that sends as you and open the
headers. In Gmail that's Show original. Look for smtp.mailfrom in
the Authentication-Results header. That's the envelope domain the
receiver checked SPF against, and it's more reliable than
Return-Path, which forwarders rewrite. If it's the platform's own
domain, that platform's include in your record isn't doing
anything for that mail. SPF is passing on their name, not yours,
and it never counted toward DMARC either, so removing the include
costs you nothing at the DMARC level. If it's a subdomain of yours
that the platform had you point at them with a CNAME, the record
being checked is theirs, and the include is idle for the same
reason. Confirm with the vendor's setup docs before you remove
anything. Some platforms use your domain for part of their mail
and their own for the rest.

Now the DKIM question from earlier. A sender that already passes
aligned DKIM is the one whose include you can afford to demote or
move out, because DMARC holds on DKIM alone for that mail. The
exception is bulk. Google and Yahoo ask bulk senders for both SPF
and DKIM, so the room is with low volume transactional platforms,
not your marketing tool.

Then the includes for services you've stopped using. Your
aggregate reports show which sources still send. A source that has
been quiet for months is a candidate, but ask whoever owns it
first. Some systems send a few times a year, and the annual
renewal notice is the one nobody remembers until it bounces.

Look hard at a, mx, and ptr

They're usually left over from a template someone pasted in a
decade ago. a authorizes whatever your domain name resolves to. On
most domains today that's a CDN edge or a shared web host, so the
lookup buys SPF pass for thousands of strangers on the same
address and nothing for you, unless your web server sends mail as
your domain. mx authorizes your inbound mail hosts, which on a
hosted filter means the filter vendor's whole pool. It costs one
lookup however many MX hosts you have, though a domain with more
than 10 MX names gets permerror from that term alone. If those
machines don't send as you, removing both terms is the rare
cleanup that improves your count and closes a hole at the same
time.

If your record has ptr, remove it. RFC 7208 says not to publish
it. It costs you a lookup and the receiver a slow one.

Put addresses first

ip4 and ip6 terms cost nothing, and mail from those addresses
passes before the receiver spends a lookup. Put them first. Order
the includes after them by volume, biggest sender first, so the
most mail passes earliest.

Dedicated IPs belong here too, because they're the one case where
listing addresses beats the include. If you're on dedicated IPs
with a platform, those addresses are yours under contract, the
vendor tells you when they change, and ip4 terms for them cost
nothing. That isn't flattening. Nothing goes stale behind your
back. Confirm with the vendor that none of your mail leaves from
their shared pool, since some route bounces or transactional mail
that way, before you drop the include. While you're asking, ask
whether they publish a narrower include for your product or
region. The catch all is what the setup doc gives everyone.

Move bulk senders to a subdomain

If your marketing platform supports a custom return path, point it
at news.example.com instead of example.com. SPF then checks the
subdomain's record, with its own budget of 10, and it still aligns
for DMARC under relaxed alignment, the default, because both names
share an organizational domain. The subdomain's SPF record is
usually the vendor's, reached through a CNAME, so you don't
maintain it.

For a lot of domains, that's the whole fix. The record from
earlier looks like this after cleanup, with Mailgun on a custom
return path and the three template terms gone. The ip4 is an
invoicing server that sends directly.

  v=spf1 ip4:203.0.113.25 include:_spf.google.com
  include:sendgrid.net include:mail.zendesk.com ~all

Four lookups, and room for the next service someone signs up for.

Don't flatten and walk away

When cleanup isn't enough, the usual advice is to flatten: replace
each include with the ranges it expands to today. The count drops
to zero and the problem looks solved.

A flattened record is a snapshot of one afternoon. Vendors add and
retire ranges, and the include you replaced was what kept you
current. Once it's gone your record goes stale quietly, and you
hear about it from bounces, or from customers who stopped getting
your mail. It cuts the other way too. When Google trimmed its
include, everyone who kept the include got the saving for free.

Stale is also a security problem, and that's the stronger
argument. A flattened record keeps authorizing ranges the vendor
gave back, and cloud address space gets reassigned. A year on, you
may be passing SPF for whoever holds those addresses now. And once
an include becomes a wall of ip4 terms, an address in your
aggregate reports no longer tells you which vendor it belongs to.

There's a size problem as well. RFC 7208 says the answer to a
query for your record should fit in 512 bytes, and gives 450 bytes
for the whole DNS message as the working number. A big vendor
publishes more ranges than that allows. Most flattening tools
handle it by splitting the record across several includes, and
your lookups start coming back.

Flattening works only if something watches the names you flattened
and rewrites the record when they change. Done once by hand, it
trades a problem you can see for one you can't.

Hosted SPF with monitoring

If you still need more than 10 after cleaning up, have a DMARC
provider host your SPF. Several offer it, and so do some services
that only manage SPF. Your record points at theirs, and they
update it when your vendors change what they publish. Some skip
the rewriting and use SPF macros, so the check looks up the
sending address directly and there's no snapshot to go stale.
Salesforce's own include already works this way, one exists term
with a macro in it. It's flattening with someone on watch, and
it's what I'd set up.

Know what changes when you do. A macro record has no tree. The
published record is one term, and no checker can expand it,
because the answer depends on the sending address at check time.
dns-audit.com will count it as one lookup and tell you nothing
about coverage, and so will every other tool. Verification moves
entirely to Authentication-Results and your aggregate reports.

If you'd rather keep it in house, open source flatteners exist
that resolve your includes again on a schedule and push the result
through your DNS provider's API. The watching is the part that
matters, not who does it.

There's a cost to the hosted route. Part of your SPF now depends
on that provider, and after the switch their record is the only
place your sender inventory lives. Keep your own list of vendor
includes somewhere you control, and work out how you'll take the
record back before you ever cancel.

Then confirm

Before any of this, save a dated copy of the record you're
replacing and a list of every term you removed. Then run the audit
again after each change. You want room left for the next service,
and every service that still sends as you showing in the tree,
unless you went the macro route. Send yourself a message from each
platform and read Authentication-Results. You want spf=pass with
dkim=pass beside it.

Watch your aggregate reports through the next quarter end, not for
a week or two. The sender you cut by mistake is the one that runs
quarterly. Anything that newly fails SPF goes back in first.
Diagnose second.
