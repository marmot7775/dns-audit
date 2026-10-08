# Article: Gmail Postmaster Tools without the reputation ratings

Sent 2026-10-07 as the final text, with the note: "Whole article, the API
section laid out as its own sub heading with the one table, and a last
light polish on a dozen sentences. Facts unchanged. Ignore every version
above." Published at /articles/postmaster-tools.

## What shipped beyond the text

- A short version box at the top, as on the other five articles, written
  only from facts already in the article.
- Source links: Google help pages 16594218 (V2), 14668346 (dashboards),
  81126 (sender guidelines), 14229414 (bulk sender FAQ), 3726730 (SMTP
  codes), the V2 API migration guide, and the Spam Resource August 2026
  post. Internal links to /articles/spf-lookups and /articles/dmarcbis,
  and two in-page links to the checks and the bounce codes.
- Three fact fixes from a source check against the live pages:
  1. The setup rows include DNS records (forward and reverse DNS), which
     the text left out.
  2. 5.7.32 is the permanent form of 4.7.32.
  3. "4.x.x are rate limiting and 5.x.x are rejections" is true of the
     codes listed, not of all Gmail codes (4.2.2 is a full mailbox), so it
     is scoped to "In this list".
- Left as written, flagged: Google's FAQ gives 4.7.31 for a missing DMARC
  policy while its SMTP codes page lists the same text under 4.7.40; no
  Google page shows "Unspecified reason" as an on-screen verdict (it is
  the API value REASON_UNSPECIFIED).

## The text as sent

```
# Gmail Postmaster Tools without the reputation ratings

Google retired the one word rating. What replaced it says more, once
you know how to read it.

For years Gmail Postmaster Tools rated your domain in one word: High,
Medium, Low, or Bad. If you only open it when the newsletter numbers
fall off a cliff, you may open it this time and find that word gone.
Google is retiring the Domain Reputation and IP Reputation
dashboards, and the new Postmaster Tools, V2, doesn't have them. What
you get instead is a short checklist and a one sentence verdict.
Between them they answer a question the old rating never could. Is
Gmail unhappy with how your mail is set up, or with how people treat
it once it lands? Those are different problems, and different people
fix them.

## What changed and what didn't

Less than the empty space suggests. Google's help page says the
dashboards from the old interface carry over to V2, except Domain and
IP Reputation. Spam rate, authentication, encryption, delivery
errors, and the feedback loop view are all still there. The page also
promises a new, more intuitive version of the reputation view, and
says nothing about what it will show or when.

The timing is murkier. The same page says the retirement of the old
interface is postponed, with no new date. Al Iverson at Spam Resource
reported in August 2026 that the pause has been lifted, that V1 is
being phased out across domains and users over time, and that many
senders already see only V2. If you still have V1, enjoy it while it
lasts and plan around V2 anyway.

## The two things to look at

The first is the Compliance status dashboard, a checklist of Google's
sender requirements with each row marked Compliant, Needs work, or No
data found. Most rows are about setup. Three of them cover the DNS
records that let Gmail confirm a message really came from you: SPF,
which lists the servers allowed to send as your domain; DKIM, a
signature your sending platform adds to each message; and DMARC,
which ties the two to the address people see in the From line.
Everyone needs SPF or DKIM. Large senders need both, plus DMARC. The
other setup rows ask whether your mail travels over an encrypted
connection and whether it's formatted properly, and large senders
also get checked on one click unsubscribe and on honoring those
unsubscribes. One row, for everyone, covers the share of recipients
who report your mail as spam.

Large has a precise meaning here. If you've ever sent close to 5,000
messages to personal Gmail accounts in a day, counting every
subdomain of your main domain, Google counts you as a bulk sender,
and the label doesn't come off.

Two details matter when you read the checklist. It reports on your
main domain, but mail from any subdomain counts toward it, so a row
marked Needs work can come from a system you'd forgotten sends mail
in your name. And the status is an average gathered over several
days, so a fix can take up to a week to show. Resist the urge to
change something else on day three.

The second thing is the verdict. Under the checklist sits a
diagnostic called Deliverability analysis, which gives you one
sentence on how Gmail currently sees your domain. Every possible
sentence points either at your setup or at your sending, and knowing
which is most of the diagnosis.

## What each verdict means, and whose job it is

### You don't meet our sender requirements

Your mail is failing at least one of Google's mandatory
requirements. Look at the checklist for the rows marked Needs work.
If they're about authentication, DNS, or encryption, this belongs to
whoever runs your email setup, whether that's your IT person, your
email platform, or a consultant; the checks they need are at the end
of this article. If the rows are about formatting or unsubscribe
handling, the fix is inside the platform you send from, and no DNS
change will clear it. Either way, fix this before anything else.
Gmail can delay or refuse mail that fails its requirements, and
refused mail never reaches the people the other verdicts measure.

### Many messages with delivery errors

A big share of your messages are bouncing, usually after a sudden
jump in volume or because something in the sending setup is off.
Google's advice is to slow down and read the bounce messages, which
carry a code that says what Gmail objected to. That's a technical
job, and the code list at the end of this article is the key to it.
One thing worth knowing even if you never open a bounce: if the
Delivery errors dashboard shows more failures than your own records
do, Google says the extra errors may belong to mail your recipients
are auto forwarding, or to someone replaying your old messages, a
trick known as a DKIM replay attack.

### Your spam rate is above 0.1%

This one is about people, and no setup change will fix it. Google
asks you to keep the share of recipients who report your mail as
spam below 0.1%, and to keep it from ever reaching 0.3%. Above 0.3%,
bulk senders lose access to mitigation, Google's process for lifting
a block, until the rate stays under 0.3% for seven straight days. The
questions to ask are the plain ones. Who are you sending to, how
often, and did they ask for it? If your platform takes part in
Google's feedback loop, the feedback loop dashboard shows which
campaigns are drawing the complaints.

### Users signal that they don't want to get your email messages

People keep marking your mail as spam, or leave it in the spam folder
when they could rescue it. The remedy is the same review of who, how
often, and what. Don't take comfort in a low number on the Spam rate
dashboard. Google measures that rate against mail that reached the
inbox, so once Gmail is already filing much of your mail as spam,
fewer people see it and the rate looks better than it is.

### Users don't take action on your messages

People aren't doing anything that tells Gmail whether they want your
mail. This is the quiet version of the verdict above, and the answer
is a smaller, warmer list. Start by suppressing addresses that
haven't opened or clicked in a long time, or ask them to reconfirm.

### Not enough outgoing email

You haven't sent enough mail to personal Gmail accounts for Google to
decide. Common reasons are a new domain, a restart after a pause, or
a lot of mail going to inactive accounts. Gmail hasn't judged you
yet, which is different from judging you badly. Two cautions. At low
volume a handful of complaints makes a high rate. And Google treats
any domain that hasn't sent more than 5,000 messages a day to
personal Gmail accounts since January 1, 2024 as new, and enforces
its rules on new domains faster. Ramp up steadily, and get the setup
right before you do.

### Users signal they want to get your email messages

Your mail reaches the inbox with few complaints, or people
consistently rescue it when Gmail misfiles it. This is the one you
want. If your numbers still look wrong with this showing, compare
results at other mailbox providers before blaming Gmail.

### Unspecified reason

Google gives no further information. Fall back on the dashboards.

## Setup problem or people problem

The old rating folded everything into one word. A Low told you Gmail
thought less of your mail and left you to guess why. V2 separates the
causes, as long as you read the checklist and the verdict together.

If the checklist shows Needs work on authentication, DNS, or
encryption, that comes first, whatever the verdict says, and it goes
to whoever runs your email setup. If every row is Compliant and the
verdict is about spam reports or people not responding, the setup is
almost certainly fine and the work is in your list and your sending
habits, which nobody can do for you. If every row is Compliant and
the verdict reports delivery errors, remember the checklist is an
average over all your mail, so one system can be failing while the
rest passes; the bounce codes will name it.

Whichever case you're in, a screenshot of the checklist and the
verdict, sent to whoever runs your email, saves a round of questions.
It tells them where to look before they've looked anywhere.

## For the person who runs your email

The checks behind a Needs work row, in the order to run them.

1. SPF. One record, covering every platform that sends as the
   domain, needing no more than 10 of the terms that cause DNS
   lookups (include, a, mx, ptr, exists, and redirect). A second
   record or an eleventh such term is a permanent error, and SPF
   fails. Softfail (~all) and hardfail (-all) count the same here,
   because DMARC counts only a pass.
2. DKIM. Each platform signs with a selector whose public key is
   published at selector._domainkey under your domain, and the
   signing domain is yours.
3. DMARC. A record at _dmarc with a p= tag. RFC 9989, the current
   DMARC standard, which obsoletes RFCs 7489 and 9091, makes the tag
   recommended rather than required, but Gmail defers mail with
   4.7.31 when the record names no policy, so name one. Google's
   requirement is p=none or stronger; it doesn't require quarantine
   or reject.
4. Reverse DNS. Each sending IP has a PTR record, and the hostname
   it returns resolves back to the same IP. PTR records belong to
   whoever controls the IP, so on a provider's shared IPs this one
   is the provider's to fix.
5. TLS. Mail to Gmail arrives over a TLS connection. If the
   Encryption dashboard shows authenticated mail arriving without
   it, find the system sending in the clear.

The first three share a trap, and it's alignment. DMARC needs SPF or
DKIM to pass for a domain that matches the From address, and a setup
can look perfect while neither does: the platform passes SPF for its
own bounce domain, signs DKIM with its own domain, and nothing in
either result is yours.

Gmail's bounce codes map onto the same list. A temporary 4.7.23 and
a permanent 5.7.25 mean the sending IP has no PTR record, or the PTR
hostname doesn't resolve back to that IP. The pairs 4.7.27 and 5.7.27
mean SPF didn't pass, 4.7.29 and 5.7.29 mean the connection wasn't
TLS, and 4.7.30 and 5.7.30 mean DKIM didn't pass. A 4.7.31 means
there's no DMARC record or the record has no policy, and 4.7.32 means
the From domain isn't aligned with the domain SPF or DKIM
authenticated. Codes in the form 4.x.x are rate limiting and 5.x.x
are rejections. When one source is failing while the rest of the
domain passes, the DMARC aggregate reports (the rua tag) will name
it.

### If you pull this data by script

The V2 API covers everything V1 did except Domain and IP reputation,
and adds compliance status, domain management, and batch calls. The
schema is different, so existing scripts need work. Google says the
V1 API will be retired and names no date.

Three changes cover most migrations. The `trafficStats` resource
becomes `domainStats`, and one method, `domains.domainStats.query`,
replaces `trafficStats.get` and `trafficStats.list`.
`domains.getComplianceStatus` is new and returns SPF, DKIM, and DMARC
compliance for a domain. `domainStats.batchQuery` pulls statistics
for several domains in one call.

The verdicts arrive as constants.

| Verdict in Postmaster Tools | API value |
|---|---|
| You don't meet our sender requirements | `SENDER_NOT_COMPLIANT` |
| Many messages with delivery errors | `SMTP_ERRORS_HIGH` |
| Your spam rate is above 0.1% | `SPAM_RATE_HIGH` |
| Users signal that they don't want to get your email messages | `USER_FEEDBACK_NEGATIVE` |
| Users don't take action on your messages | `USER_FEEDBACK_LOW` |
| Not enough outgoing email | `MESSAGE_VOLUME_LOW` |
| Users signal they want to get your email messages | `USER_FEEDBACK_POSITIVE` |
| Unspecified reason | `REASON_UNSPECIFIED` |

dns-audit.com reads a domain's SPF, DKIM, and DMARC records in one
pass, which covers the setup half of this article.
```
