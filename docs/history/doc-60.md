# Doc 60: The DANE article, rewritten

Copy only, for static/articles/dane.html, the last of the
three articles. The current text is the contrarian register: a
two-sentence title, "You were half right", "The honest
version", "That isn't stubbornness. It's a position." Replace
the prose with the text below, word for word. Keep every fact,
number, and the five inline links (the 2015 obituary, RFC
7672, the Zivver sample, the Microsoft October 2024
announcement, and RFC 8460) on the same phrases they anchor
now. Line numbers are from main at 7287a16.

## 1. Title and head

- The title element becomes "DANE for email in 2026 |
  dns-audit.com". The h1 (60) becomes "DANE for email in
  2026". The dbis-article-sub (61) becomes "The browser
  version was abandoned a decade ago. The SMTP version is
  where mail transport security has settled, and the
  operational objections to it have mostly gone."
- The meta description, og and twitter titles and
  descriptions, and the JSON-LD headline and description
  follow the h1 and the subtitle, as Docs 57 and 59 did. Set
  the JSON-LD modified date to the deploy date.
- On static/articles/index.html the card for this article
  takes the new h1 as its title and this blurb: "The browser
  version was abandoned a decade ago. The SMTP version is
  where mail transport security has settled, and the
  operational objections have mostly gone." Recompute the read
  time at 200 words a minute.

## 2. Body

Replace everything from the first dbis-lede (62) to the end of
the article. Section headings are given; every section is a
dbis-section.

[dbis-lede, one paragraph] There are two protocols called
DANE, and most writing about it treats them as one. The
version meant to put TLS keys in DNS for browsers is gone:
Chrome never shipped it, Firefox never shipped it, and Adam
Langley [wrote the obituary in 2015] (keep the link). The
version for mail servers, DANE for SMTP in [RFC 7672] (keep
the link), is alive and carrying a serious share of mail in
the places that adopted it. This article is about the second
one: what it protects, who runs it, and what changed about
running it.

h2: Why the browser version was abandoned

The Chrome case is the cleanest to tell because the people
involved wrote it down, and Langley's reasons still hold. DNS
is unreliable at the edge: Chrome ran experiments looking up
records it knew existed on connections it knew were working,
and four to five percent of users could not get the answer
back, because captive portals, ISPs, and middleboxes stripped
the records. A browser that fails hard on a missing lookup
gets called broken; a browser that ignores the failure is not
doing security.

The web also had a different plan. Certificate Transparency
was the long-term bet for catching misissuance, and CT depends
on certificates from a known set of trusted CAs. Anyone can
publish a TLSA record, which is the point for a mail operator
who wants to skip the CA and a problem for a transparency log
that wants a manageable set of roots. On top of that, DNSSEC
zones at the time were full of 1024-bit RSA keys the web PKI
had spent a decade removing from its own trust stores. No
browser was going to import that.

h2: Why the mail version works

RFC 7672 was published in October 2015, the same year as the
web obituary, and it solved a problem browsers did not have.
SMTP between mail servers has always used opportunistic TLS:
most servers try to encrypt, but a sender has no way to verify
who it is talking to. An attacker on the path who strips the
STARTTLS offer from the greeting gets the mail in cleartext,
and the CA system does not help because SMTP server
certificates rarely map cleanly to MX hostnames.

DANE for SMTP closes that gap. The receiver publishes a TLSA
record for each MX host, signs the zone with DNSSEC, and the
sender validates the chain. The sender then has a
cryptographic requirement: if the connection is downgraded to
cleartext or a different certificate is presented, delivery
fails closed instead of proceeding.

It works where the browser case failed because the endpoints
are servers, not user devices. Servers run validating
resolvers that hotel Wi-Fi cannot interfere with, and mail has
retry semantics, so a temporary DNSSEC failure is a deferral
rather than an error page in front of a person.

h2: What DANE protects, and what it does not

The scope is deliberately narrow. DANE stops STARTTLS
stripping. It stops an attacker from using a certificate
issued by a rogue or compromised CA. It lets self-signed
certificates work, which is useful for internal mail routing.

It does nothing for mail at rest; once the message is in the
mailbox, DANE's job is over. It does not authenticate the
sender, which is what SPF, DKIM, and DMARC do. DANE protects
the connection between two servers, and the authentication
protocols protect the message inside it. A domain that handles
anything sensitive wants both.

h2: Who runs it

SMTP DANE is real, useful, and concentrated by region and by
provider. In a [September 2025 sample of the 10,000 domains
most often emailed by Zivver's Dutch customers] (keep the
link), 12.6% of domains published TLSA records, but those
domains received 25% of the mail by volume. Large receivers do
it; small ones mostly do not.

Microsoft turned on DANE for Exchange Online in two stages:
outbound validation rolled out through 2022, and inbound went
generally available in [October 2024] (keep the link). Inbound
is opt-in per domain. An admin has to enable DNSSEC for the
domain, swap the MX record for the one Exchange Online hands
back, and switch on inbound DANE. Until someone does that, a
Microsoft 365 tenant publishes no TLSA records.

Google publishes no TLSA records for Google Workspace domains
and points senders at MTA-STS instead. MTA-STS fetches a
transport policy over HTTPS and validates the receiver's
certificate through the web PKI, with CT logs as the audit
trail. Google's position is that the web PKI is more
accountable than the DNS hierarchy for transport keys, and
that is a considered position, not neglect. The result is a
provider lottery: a European receiver that publishes TLSA
gives you DANE on the wire, a Microsoft 365 tenant can have it
if an admin does the work, and a Google Workspace domain
cannot have inbound DANE at all unless a secure email gateway
such as Proofpoint or Mimecast sits in front of it. Plenty of
enterprises do exactly that and get DANE at the gateway hop
even though their mailbox provider will not publish TLSA.

h2: The operational objection, and what changed it

DANE couples your certificate to your DNS. The classic failure
is the admin who renews the mail server certificate and
forgets the TLSA record; because DANE fails closed, inbound
mail stops. In a regulated environment that is the trade you
agreed to. Everywhere else it was a standing source of
anxiety, and a fair reason to stay away.

Two things changed that. DNSSEC stopped being hard, as [the
DNSSEC article] (link to /articles/dnssec) covers: at the
major DNS providers, signing the zone is a checkbox, so the
foundation is no longer the obstacle. And certificate
automation caught up. ACME-aware tooling that rotates the TLSA
record alongside the certificate, such as uacme, danectl, and
the DANE paths in current Postfix and Exim deployments, turns
the coupling into a scripted handoff. Publish DANE-EE, usage 3
1 1, with the SPKI selector, and the hash survives renewals
for as long as you keep the same key pair. The friction is not
gone, but it is manageable by a normal operations team.

h2: What to do with this

If you handle sensitive correspondence or regulated data,
publish TLSA records for your MX hosts and validate inbound.
Pair DANE with MTA-STS for senders that will not do DNSSEC,
and pair both with [TLS-RPT] (keep the link) so you hear about
failures before your senders do. If you last looked at the
protocol before 2018, the picture has moved, and the
objections you remember were about operations that have since
been automated.

## Tests

The article link tests cover this page; assert the five inline
links are still present and still resolve. Add the page to the
tone test's banned-string scan with: "You were half right",
"buried in the same obituary", "The honest version",
"That isn't stubbornness", "armored car", "wax seals".

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust only if style.css changes; it should not.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-60.md in the same commit and
add its line to docs/history/README.md.

## Done when

The article carries the new title on the page, in the head,
and on the articles index; the body is the text above with the
five links intact; every heading is sentence case; and the
suite passes. With this, all three articles, About, and
Privacy are in the same register.
