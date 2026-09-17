# Doc 59: The DNSSEC article, rewritten

Copy only, for static/articles/dnssec.html, the same way Doc
57 did the DMARC article. The current text is the viral
register: "The thing that quietly got fixed", "survives
Tuesday", "The closer", "That's not nothing", one-line
paragraphs. Replace the prose with the text below, word for
word. Keep every fact, number, link, and the Further reading
list exactly as they are; keep the six strong leads in the
deployment section as strong elements. Line numbers are from
main at a5c48ba.

## 1. Title and head

- The title element becomes "DNSSEC in 2026: what changed and
  whether you need it | dns-audit.com". The h1 (92) becomes
  "DNSSEC in 2026: what changed and whether you need it". The
  dbis-article-sub (93) becomes "The operational problems
  behind DNSSEC's reputation were fixed by three RFCs and a
  provider rollout that few people noticed. What it protects,
  where it still falls short, and what a good deployment looks
  like."
- The meta description, og and twitter titles and
  descriptions, and the JSON-LD headline and description
  follow the h1 and the subtitle, as Doc 57 did. Set the
  JSON-LD modified date to the deploy date.
- On static/articles/index.html the card for this article
  takes the new h1 as its title and this blurb: "The
  operational problems behind DNSSEC's reputation were fixed
  by three RFCs and a provider rollout. What it protects,
  where it falls short, and what a good deployment looks
  like." Recompute the read time at 200 words a minute.
- While in index.html and dmarcbis.html: the tree walk
  figure's kicker "DNS Tree Walk" and any other title-case
  heading inside the three articles become sentence case ("DNS
  tree walk"). Headings that are proper names or acronyms stay
  as they are.

## 2. Body

Replace everything from the first dbis-lede (94) to the end of
the section before Further reading. Further reading (164
onward) stays exactly as it is.

[dbis-lede, one paragraph] Most opinions about DNSSEC were
formed before 2017 and never revisited. Mine was that it
carried too much operational risk for the threat it closed:
KSK rollovers broke domains, registrars wanted a ticket for
every DS update, and RSA signatures pushed responses into TCP
fallback. That was a fair reading at the time. It is out of
date now, and this article is the check I should have done
sooner: what changed, what DNSSEC protects against, where it
still falls short, and what a good deployment looks like.

[dbis-section] h2: What got fixed

The DNSSEC of the 2010s needed a person at every step. You
signed the zone, copied the DS record out of your DNS host,
pasted it into your registrar's form, and did it again at
every key rollover. Miss the registrar step on a KSK rotation
and every validating resolver treated your domain as bogus.
The cryptography was never the problem. The handoffs were.

Three RFCs removed the handoffs. RFC 7344, in 2014, introduced
CDS and CDNSKEY records: the DNS host publishes the new DS in
the zone itself and the parent picks it up, with no form and
no copying. RFC 8078, in 2017, extended that to the first DS
and to removal, not only rollover. RFC 9615, in July 2024,
closed the last gap, which was how to establish trust for a
zone that has no chain yet. A growing set of registries,
mostly country codes such as .ch, .cz, .li, .se, and .nl, scan
for CDS records directly; in the large generic TLDs the
registrar does that job. CSYNC, RFC 7477, does the same for NS
and glue records.

Algorithm choice changed too. ECDSA P-256, algorithm 13, was
defined in RFC 6605 in 2012 but took most of a decade to
become the provider default. Its signatures are small enough
to fit in a UDP response, and a good share of the old "DNSSEC
broke my domain" stories were TCP fallback from oversized RSA
responses.

The standards took twelve years. The provider work that made
them matter happened mostly in the last six. At Cloudflare,
deSEC, Route 53, NS1, and Google Cloud DNS, signing is a
checkbox and the provider handles the keys and the rollovers.
None of this made news, because slow fixes do not.

[dbis-section] h2: What it protects against

DNSSEC signs DNS answers. When a resolver asks for a domain's
address, DNSSEC lets it verify that the answer came from the
zone's signer and was not altered on the way. That is the
whole job: origin authentication and integrity for DNS data.

It matters. Cache poisoning is real, the Kaminsky attack of
2008 was real, and on-path tampering happens on hotel networks
and cheap ISPs, and some governments do it at national scale.
Any protocol that stores security data in DNS, DANE and SSHFP
among them, depends on DNSSEC to make that data trustworthy.

It also has clear limits, which vendor copy tends to blur.
DNSSEC does not stop phishing: an attacker can register a
lookalike domain and sign it perfectly. It does not stop email
spoofing; that is SPF, DKIM, and DMARC, which sit above it. It
does not encrypt queries; that is DNS over HTTPS or DNS over
TLS, a different protocol for a different problem. And it does
not help if an attacker controls your DNS provider's signer or
hijacks the domain at the registrar, because then the attacker
holds the chain of trust. Within those limits it closes a
class of attack that nothing else closes. Without it, you are
trusting every resolver and every network between a user and
your authoritative servers.

[dbis-section] h2: Where it still falls short

Adoption depends on what you count. Signed zones in the large
TLDs are in the low single digits of registered domains;
Verisign's DNSSEC Scoreboard tracks the .com and .net share,
and it creeps up slowly. Validation is further along. APNIC
Labs measures users behind validating resolvers, and as of
September 2026 it reports 38% worldwide, or 47% counting
partial validation.

The signing number is low because signing is mostly a provider
decision, not a domain owner's. HTTPS went the same way: site
owners did not wake up wanting certificates; Let's Encrypt and
the hosting providers turned it on for them. Providers that
automated DNSSEC have high adoption among their customers, and
providers that did not, do not.

So the practical question is where your DNS lives. At
Cloudflare, deSEC, Route 53, NS1, or Google Cloud DNS, you can
sign in a few clicks, and the only variable is how the DS
reaches the registry: some registrars read CDS records, and
many still want the DS pasted into a form. At a budget
registrar or a shared hosting panel that does not list DNSSEC,
you have a migration ahead of you before the checkbox exists.
On .com, .net, .org, .io, .dev, and .app, the registry takes
the DS only from your registrar, so the registrar is the
bottleneck. Some country-code registries scan your zone for
CDS and skip the registrar. On a long-tail TLD, check the
registry itself: IANA's Root Zone Database shows whether a TLD
is signed, but not whether it automates DS updates.

[dbis-section] h2: What a good deployment looks like

Signed is the floor. A deployment that will still be working
in three years has these properties.

[strong] Algorithm 13 or 15. [/strong] ECDSA P-256 or Ed25519.
RSA-SHA256 remains a recommended algorithm in the IANA
registry, but its signature size is what pushed responses into
TCP fallback. RSA-SHA1, algorithms 5 and 7, is marked MUST NOT
for signing; if a provider still defaults to it, ask why.

[strong] Automated rollover through CDS and CDNSKEY. [/strong]
If a person has to copy a DS record between two panels at each
rollover, you do not have a deployment. You have a future
outage with a date on it.

[strong] A monitored DS at the registrar. [/strong] The DNSSEC
failure mode is not a wrong key; it is a key that used to be
right. When the DS drifts from the zone, the domain goes dark
for every validating resolver, and ordinary uptime monitors do
not notice. Use something that validates the chain,
continuously.

[strong] Validation tested, not assumed. [/strong] Run DNSViz,
Verisign's DNSSEC Analyzer, or dns-audit.com against the
domain and read the chain from the root down. A quiet break
stays quiet until a resolver tightens its validation.

[strong] Hosted signing. [/strong] Unless you run a registry,
a TLD, or a national CERT, you should not be running your own
signers. The large providers run them at a scale and
reliability you will not match, and they are the ones who made
RFC 9615 work in production.

[strong] A rehearsed KSK rollover. [/strong] Most operators
have never rolled a KSK, so the first time happens in
production, under pressure, in a registrar interface nobody
has opened in years. Do one deliberately, take notes, and it
stops being an event.

[dbis-section] h2: Whether you need it

DNSSEC is infrastructure, not a cause, and the decision is the
threat model.

If a DNS hijack of your domain would end up on a regulator's
desk, sign it and meet the bar above. That covers banks,
registrars, certificate authorities, software update channels,
government domains, and anything that publishes DANE records.
Nothing else closes that threat.

If the domain is a marketing site, a blog, or a redirect, sign
it when your provider makes it a checkbox and skip it when it
would mean moving DNS hosting. The threat model does not
justify a migration for a brochure site.

Whichever it is, retire the arguments from 2014. "Too
complicated" was true then and is mostly false now at a
provider that did the work. "It does not encrypt anything"
answers a question DNSSEC never asked. "Nobody uses it" misses
that the operators who need it most already do. Run one of the
validators on a domain you care about and see what the chain
looks like today. Most domains land in one of three states:
signed and clean, signed but broken at the registrar handoff,
or unsigned because the provider offers nothing. Each of those
is a useful answer, and none of them is the one you formed a
decade ago.

[Further reading section: unchanged]

## Tests

The article link tests (RFC links, header, footer, alias,
dashes) cover this page; run them. Add the page to the tone
test's banned-string scan with: "quietly got fixed", "survives
Tuesday", "That's not nothing", "The closer", "Just once",
"Actually, Maybe DNSSEC", "in the early innings". Keep the
Further reading links test green.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust only if style.css changes; it should not.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-59.md in the same commit and
add its line to docs/history/README.md.

## Done when

The article carries the new title on the page, in the head,
and on the articles index; the body is the text above with the
six strong leads and the untouched Further reading list; every
RFC link still resolves; headings inside all three articles
are sentence case; and the suite passes.
