# Doc 82: SPF lookups article, three edits

## Context

Two versions of Doc 80 were written on Sept 29 for the same
article, one at /articles/spf-lookups and one at
/articles/spf-lookup-limit. Before any edit, find out what is on
main and live. If exactly one of those routes exists, work on it.
If both exist, stop, report both routes with their commit SHAs,
and wait; do not delete either. If neither exists, stop and say
so.

Then apply the three edits below to the article prose. Nothing
else on the page changes. The wording given here is final; do not
rephrase it.

## Edit 1: remove the first person line

In the hosted SPF section, find the sentence that begins It's
flattening with someone on watch and replace the whole sentence
with:

It's flattening with someone on watch, and it's the better route
when cleanup isn't enough.

Then search the page for any other first person pronoun (I, I'd,
I've, my, me) outside the footer and report any you find rather
than editing them.

## Edit 2: split the header check into steps

In the section headed Find out which includes matter, replace the
first paragraph (the one that begins Pull a message from each
platform) with the following. Render it as an ordered list in the
same list style the RFC 9989 article uses for its five edits.

1. Pull a message from each platform that sends as you and open
   the headers. In Gmail that's Show original.
2. Find the Authentication-Results header and look for
   smtp.mailfrom. That's the envelope domain the receiver checked
   SPF against. It's more reliable than Return-Path, which
   forwarders rewrite.
3. If smtp.mailfrom is the platform's own domain, that platform's
   include in your record isn't doing anything for that mail. SPF
   is passing on their name, not yours, and it never counted
   toward DMARC either. Removing the include costs you nothing at
   the DMARC level.
4. If it's a subdomain of yours that the platform had you point at
   them with a CNAME, the record being checked is theirs, and the
   include is idle for the same reason.
5. Before you remove anything, confirm with the vendor's setup
   docs. Some platforms use your domain for part of their mail and
   their own for the rest.

The paragraph that follows, beginning Now the DKIM question from
earlier, stays as it is apart from Edit 3.

## Edit 3: name all three bulk sender programs

In that following paragraph, replace:

Google and Yahoo ask bulk senders for both SPF and DKIM

with:

Google, Yahoo and Microsoft ask bulk senders for both SPF and DKIM

## Verification

Run the full suite, including the tone test for this page. Render
the page at 1280 and 390 in both themes and confirm the new list
renders as a list, nothing overflows, and there are no console
errors. Deploy, then report main SHA and /api/health, and state
which route the article lives at.
