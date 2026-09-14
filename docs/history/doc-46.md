# Doc 46: False and unverified claims in generated text, the articles, and the README

Fourth doc from the Sept 13 review. Every item is a statement
a reader can see that is wrong, unsupported, or contradicted
by the RFC or the vendor's own page. Replacement text is given
for each; use it as written. Line numbers are from main at
ad26fdd; search for the quoted string if one has moved.

## 1. Migration path: t=y is not "safe to test" on RFC 7489 receivers

result_transformer.py:3709: "t=y drops the effective policy
one level, so p=quarantine with t=y acts like p=none. Safe to
test." and 3730: "p=reject with t=y effectively acts as
p=quarantine. Monitor for issues." The About page says most
receivers still run RFC 7489, and RFC 7489 section 6.3 says
unknown tags are ignored, so those receivers apply
p=quarantine in full the moment that record is published. Line
694 of the same file already says receiver behaviour is split.

Replace 3709 with: "t=y asks RFC 9989 receivers to apply one
level below the published policy, so they treat p=quarantine;
t=y as p=none. Receivers still on RFC 7489 ignore t and
quarantine in full. Publish this step only when your reports
already show no legitimate failures." Replace 3730 with the
same shape for reject and quarantine.

Also: the record_after strings for each step rebuild the
record from p, t, and rua only, so a record carrying sp=none;
adkim=r; aspf=r loses those tags at step 2, which silently
changes the subdomain policy. Carry every tag from the current
record through each step and change only the ones the step is
about.

## 2. "Add RFC 9989 tags" that are not RFC 9989 tags

result_transformer.py:3783 to 3784: action "Add RFC 9989 tags:
np=reject, sp=reject", why "These tags close gaps in the old
standard and prepare for RFC 9989." sp is an RFC 7489 tag; np
is imported from RFC 9091 (RFC 9989 Appendix C.5.1). On a
p=reject domain neither changes what receivers do, because
both already inherit reject. Replace the action with "Make
subdomain policy explicit: sp=reject, np=reject" and the why
with "Neither changes what receivers do here, since both
already inherit p=reject. They make the record say what it
means, so a later change to p= cannot loosen subdomains by
accident."

Record builder reasons at 3903 "Closes subdomain policy gap.
Matches root domain enforcement." and 3911 "Protects
non-existent subdomains from spoofing (new in RFC 9989)."
become "Makes the subdomain policy explicit; it already
inherits the root policy." and "Makes the non-existent
subdomain policy explicit; the tag comes from RFC 9091."

The Why RFC 9989 paragraph at 3575 to 3578: "This is a new RFC
9989 tag ... Under RFC 7489, there was no way to control
this." becomes: "np, brought into RFC 9989 from RFC 9091, sets
a policy for subdomains that were never created. Under RFC
7489 they inherited sp, or p when sp was absent, so the two
could not be set separately."

app.js:1835 labels the badge for dmarcbis: 'new' as "New in
RFC 9989" and the backend sets it for np, psd, and t. psd and
t are new in RFC 9989; np is not. Emit dmarcbis: 'imported'
for np and label it "From RFC 9091".

## 3. Tag notes that state things the RFCs do not say

result_transformer.py:2738, the v note: "RFC 9989 tightens
parsing. This MUST be the first tag. Records that place ...
legacy receivers were lenient about tag ordering." RFC 7489
section 6.3 already required v first. Replace with: "Both RFC
7489 and RFC 9989 require v=DMARC1 to be the first tag. A
record with it anywhere else is not a DMARC record."

2918, the rua note: "The mailto: prefix is now strictly
required. Bare email addresses are rejected." RFC 7489 section
6.3 already defined rua as a list of URIs; a bare address was
never valid. Doc 31 fixed this in the article and not here.
Replace with: "Reporting moved into its own documents: RFC
9990 for aggregate reports and RFC 9991 for failure reports.
The size suffix on a URI (such as !10m) was removed (RFC 9989
Appendix C.4). URI syntax is otherwise unchanged."

3048, psd=u: "Receivers fall back to the Public Suffix List."
RFC 9989 section 4.7 says psd=u means use the tree walk of
section 4.10, and Appendix C.3 says the PSL was replaced by
it; the same cell's bracketed note says so. Replace with:
"Undeclared, the RFC 9989 default and the right value for
almost every domain. Receivers determine the organizational
domain with the tree walk. Declare psd=y only if this domain
really is a public suffix." Check 3029 and 1876 for the same
claim and align them.

2869: "RFC 9989 uses the MAIL FROM identity only, not HELO.
RFC 7489 was ambiguous about this." RFC 7489 section 3.1.2
allowed HELO only when MAIL FROM was empty; RFC 9989 section
4.4.2 removes that. Replace the second sentence with: "RFC
7489 let receivers fall back to HELO when MAIL FROM was
empty."

3393: "p=reject may cause issues with mailing lists that
rewrite the From header." Backwards: lists that rewrite From
are the ones that avoid the problem. Replace with: "p=reject
can cause mail sent through mailing lists to be rejected: the
list relays from its own servers, which breaks SPF alignment,
and often edits the subject or footer, which breaks the DKIM
signature. Lists that rewrite the From header avoid this."

2044, 2890, 2966: "no longer send failure reports". Google
never did (support.google.com/a/answer/2466563: Gmail does not
support ruf). Change "no longer send" to "do not send" in all
three.

## 4. Vendor claims

result_transformer.py:6008 and the BIMI detail on the same
card: "Gmail requires a VMC (registered trademark) or CMC
(domain-validated) certificate" beside a detail "Gmail
requires a VMC for BIMI logos." Google's BIMI page says a CMC
is accepted when the logo is not trademarked; CMC issuers
require the logo to have been in continuous use for at least
twelve months, so "domain-validated" is wrong. One sentence,
once per card: "Gmail requires a certificate in the a= tag: a
VMC, which needs a registered trademark, or a CMC, which needs
proof the logo has been in use for at least a year. Apple Mail
and Yahoo Mail display the logo without one." Delete the
"requires a VMC" detail.

7244: "Google recommends setting up rua= first, monitoring for
2 weeks, then moving to enforcement." Google's rollout page
(support.google.com/a/answer/10032473) says one week, and the
site's own rule is that monitoring ends when the sender
inventory is stable, not on a date. Replace with: "Google's
rollout guide starts at p=none with rua= and moves up only
after the reports show every legitimate sender aligning."

7283: "Microsoft DMARC reporting can be configured in the
Microsoft 365 admin center." The admin center adds a DMARC
record only for the onmicrosoft.com domain; a custom domain's
record lives at its DNS host, and Microsoft 365 sends
aggregate reports and no failure reports (Microsoft Learn,
email-authentication-dmarc-configure). Replace with:
"Microsoft 365 sends aggregate reports and no failure reports.
For a custom domain the DMARC record lives at your DNS host,
not in the admin center."

7226, google_workspace dkim_auto_rotation: True. Google's DKIM
setup page describes generating a new key by hand and no
rotation feature. Set it to None and render None as "not
known" rather than a check or a cross. Do the same for every
capability boolean in the provider table (7226 to 7301 and the
rest of that block) that has no source: add a comment with the
source URL next to each value you can verify, and set the rest
to None. Microsoft's True at 7263 is verified (Microsoft
Learn, Set up DKIM: Microsoft 365 handles key rotation
automatically).

7290: "Both must be rotated when key rotation is needed."
Microsoft alternates between selector1 and selector2 on
rotation. Replace with: "Microsoft alternates between
selector1 and selector2 on rotation; both CNAMEs must stay
published."

5140 and 7203 map a selector named selector1 or selector2 to
Microsoft 365 unconditionally. Microsoft 365 DKIM is a CNAME
to the dkim.mail.microsoft namespace (a TXT record at the
selector is not supported), so a TXT key at selector1 is
evidence against Microsoft, not for it. Attribute to Microsoft
only when the selector is a CNAME into that namespace, or when
the MX or SPF include corroborates it; otherwise print
"Vendor: unknown".

## 5. PermError wording that Doc 28 fixed in one place

Doc 45 removed some duplicates; wherever these survive,
replace them: spf_recursive.py:525 "will return a PermError,
treating your SPF as if it doesn't exist",
audit_engine.py:2730 "treating your SPF as if ...",
result_transformer.py around 4041 and 4153 "Fails at most
receivers", anomaly_detector.py around 143 "which most
receivers treat as an SPF failure". RFC 7208 section 4.6.4 is
a MUST and permerror is its own result, not none. Use one
sentence everywhere: "Past 10 lookups, receivers must return
PermError (RFC 7208 section 4.6.4). PermError is not a pass,
so SPF cannot satisfy DMARC for any message from this domain."

result_transformer.py:4429 "-all: Unauthorized servers are
explicitly rejected. Strongest SPF enforcement." sits under a
sentence saying enforcement decisions are made at the DMARC
layer. RFC 9989 section 7.1 notes an SPF hard fail can cause
rejection before DMARC runs. Replace with: "-all: servers not
listed are not authorized. Some receivers reject on SPF fail
before DMARC runs (RFC 9989 section 7.1), so a message that
would pass DMARC on DKIM alone can still bounce." 4426 "~all:
Unauthorized servers are flagged but mail is delivered" is a
delivery prediction; replace with: "~all: servers not listed
are not authorized, and the receiver decides what that costs
the message."

## 6. The homepage FAQ, the article table, and the README

static/index.html:75 (FAQ JSON-LD, which search engines show):
"Set p=reject only after monitoring with rua reports for 30 or
more days". Replace with: "Set p=reject only after the
aggregate reports stop showing new legitimate senders and
every one of them aligns." index.html:87 lists cssSelector
values .hero-description and .faq-section, neither of which
exists on the page; point it at the elements that do, or drop
the speakable block.

index.html:51 and README.md:59: "each check reports pass,
warning, or fail". Doc 38 added two states. Replace with
"pass, warning, fail, not configured, or not checked".

static/articles/dmarcbis.html:134: the np row's RFC 9989 cell
says "New". Change to "Imported from RFC 9091". The t and psd
rows are correct.

README.md:21: "Selector discovery across 1,100+ common
patterns". The list has about 1,130 names but a probe is
capped at 40 vendor guesses plus 156 generic, and the card
says "Checked 196 common selectors". Replace with: "Selector
discovery from a list of about 1,100 known selectors, narrowed
by SPF-based vendor fingerprinting to about 200 lookups per
audit."

README.md:55: "How many of four spoofing vectors the domain's
records close". The tile now names what is unprotected across
three vectors. Replace with: "Whether direct, subdomain, and
non-existent-subdomain spoofing are closed by the DMARC
policy, naming any that are not."

## 7. Google and Yahoo requirement, said two ways

audit_engine.py:1068 "may throttle or deprioritize mail
without one", audit_engine.py:227 "deprioritize or reject",
result_transformer.py:1921 "more likely to be throttled or
sent to spam". Google's page
(support.google.com/a/answer/81126) says non-compliant mail
may be rate limited, blocked, or marked as spam; it does not
say deprioritize. Use one sentence at all three sites and show
it once per card: "Google and Yahoo require a DMARC record
from senders of 5,000 or more messages a day to their users,
and say non-compliant mail may be rate limited, blocked, or
sent to spam."

result_transformer.py:1920 links the word DMARC to RFC 7489.
Point it at https://www.rfc-editor.org/rfc/rfc9989.html. The
section 6.6.3 link at 1875 is about legacy PSL behaviour and
stays.

## 8. Two surfaces that contradict the cards

pdf_report.py:1624 appends "(the lookup did not complete)" to
every unavailable card, but DKIM with unavailable_kind
not_enumerable completed nearly two hundred lookups and its
pill says "Not confirmed". Exclude that kind from the "Not
checked" line and print it separately: "Not confirmed: DKIM
(no selector was supplied and the name cannot be enumerated
from DNS)".

result_transformer.py:7741, 7751, 7761, 7771: the provider
scorecard maps only fail and warn to "no", so a Doc 38 absent
card falls to "unknown" and app.js renders it with the
not-checked icon while the card two sections up says "Not
configured". Add "absent" to the "no" branch in all four.

## 9. Two leftovers from Doc 45

audit_engine.py resilience summary: "If DKIM is configured
(likely), resilience is high." The audit has no basis for
"(likely)". Delete the parenthetical.

A domain with no MX and no SPF: the SPF row is now amber "No
mail", but the overall resilience level still reads red "Low"
and tells the owner to publish SPF and enable DKIM. Add the
branch Claude Code flagged after Doc 45: when the domain has
no MX and no SPF, the level is "Not applicable" with the
sentence "This domain does not send or receive mail. Publish
v=spf1 -all and a DMARC record at p=reject to stop others
sending as it." That is the one recommendation that is right
for a non-mail domain.

## Tests

Extend tests/test_doc32_plurals_and_tone.py or add a Doc 46
file with a banned-string list for every replaced sentence, so
none can come back: "Safe to test", "close gaps in the old
standard", "tightens parsing", "strictly required", "fall back
to the Public Suffix List", "monitoring for 2 weeks", "admin
center", "no longer send failure reports", "treating your SPF
as if", "Fails at most receivers", "30 or more days", "pass,
warning, or fail", "(likely)". Run the three fixture zones
from Doc 44 through run_full_audit and the PDF and assert the
new sentences appear where they should.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-46.md in the same commit.

## Done when

No generated string, article, or README line claims something
the RFC or the vendor's own page contradicts, every vendor
capability shown as a check or cross has a source, the
migration path carries every tag through each step, and the
banned-string test passes.
