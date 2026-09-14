# Doc 40: Homepage copy, one false RFC claim, and the last attacker sentences

Copy and one colour rule. Line numbers are from main at
77c9bc7; re-locate by content if they have moved. Items 3 and
4 are false or misleading statements and go first.

## 1. Headline and tagline

static/index.html:151 and 152. Replace the h1 text and the
subtitle paragraph with:

    <h1 class="audit-title">Check the DNS records mail servers use to verify your email</h1>
    <p class="audit-subtitle">Enter a domain and it reads the public DNS records that control email authentication, transport security, and DNS integrity: SPF, DKIM, DMARC, MTA-STS, DNSSEC, and seven more, plus the public policy files they point to. It tells you what is missing or misconfigured, cites the RFC it checked against, and gives you the corrected record to paste. Nothing to install, nothing to send.</p>

The RFC 9989 readiness link that the current subtitle carries
moves to the end of the second sentence: "cites the RFC it
checked against, including <a href="/articles/dmarcbis"
class="audit-subtitle-link">RFC 9989 readiness</a>, and gives
you the corrected record to paste."

Keep the meta, og, and twitter descriptions as they are; they
are accurate. Keep the title tag.

Why the old headline goes: "your domain's email and DNS" says
the tool looks at email. It reads DNS and the public policy
files DNS points to (the MTA-STS policy over HTTPS, the BIMI
logo, certificate transparency logs) and never touches a
message.

## 2. Privacy line under the form

static/index.html:206 `<p class="audit-privacy-note">No
account. No cookies. Open source.</p>`. Delete it. The form
already shows there is no account, the privacy page is linked
in the footer, and the GitHub link in the footer carries open
source.

Delete the `.audit-privacy-note` rule at static/style.css:8299
and fix the comment at 8303 that refers to it. Check nothing
else uses the class.

## 3. The site claims a section number it does not always give

Every check cites the RFC it works from. About a fifth of
findings also cite a section number, mostly DMARC, SPF, DKIM,
and DANE. Two places claim more than that.

static/index.html:152 is replaced by item 1, which says "cites
the RFC it checked against".

static/about.html:69: "cited the specific RFC section it was
checking against". Change to "cited the RFC it was checking
against".

## 4. np is not new in RFC 9989

Two tag-decoder notes repeat an error Doc 30 fixed in the
README.

result_transformer.py:2731 to 2732, the np note: "This tag is
NEW in RFC 9989. RFC 7489 had no way to set policy for
subdomains that don't exist in DNS. Attackers exploit this by
inventing subdomains. np= closes that gap."

RFC 9989 Appendix C lists np as imported from RFC 9091. Under
RFC 7489 a non-existent subdomain inherited sp, or p when sp
was absent, so it was covered; what it could not have was a
policy of its own. Replace with: "RFC 9989 brings np in from
RFC 9091. Under RFC 7489 a subdomain that does not exist
inherited sp, or p when sp was absent, so it could not be set
separately. np lets you hold sp=none while a real subdomain is
still being aligned and reject mail from names that were never
created at the same time."

result_transformer.py:2704 to 2706, the sp note: "The new np=
tag extends subdomain protection to cover non-existent
subdomains, something RFC 7489 had no concept of." Replace
with: "RFC 9989 clarifies inheritance. sp covers subdomains
that have no DMARC record of their own; np, imported from RFC
9091, lets non-existent subdomains carry a stricter policy
than real ones."

Also: the sp row in the tag table prints the full p=none
paragraph a second time, because 2710 calls
`_explain_policy_value(value)` for sp exactly as p does. Give
sp its own one-line explanation: f"Subdomain policy {value}.
Applies to mail from subdomains of this domain that have no
DMARC record of their own." The p row keeps the long form.

## 5. The last sentences about attackers

Doc 32 and Doc 38 removed the ones that predicted attacks.
What is left falls in two groups. Rewrite the first group;
leave the second.

Rewrite, because each states what attackers do or want as a
fact the audit did not observe:

- result_transformer.py:2505 summary "Attackers can invent any
  subdomain." to "Invented subdomains are unprotected."
- 2506 detail, replace whole string: f"A subdomain that was
  never created, such as secure-portal.{domain}, has no record
  of its own, so mail claiming to come from it is judged by
  the policy it inherits. Here that policy is not enforcing.
  RFC 9091 added the np tag for exactly this case."
- 2742: "Attackers can invent subdomains like
  secure-login.{_dom} and spoof mail from them." to f"Mail
  from an invented name like secure-login.{_dom} is delivered
  as if no policy existed."
- 2768 to 2770, replace whole string: f"Non-existent
  subdomains such as secure-login.{_dom} currently fall to
  {resolved_via}={resolved}, so mail from an invented name is
  not rejected. Consider adding np=reject."
- 3686 why: "Close the subdomain policy gap. Attackers target
  subdomains to bypass your root policy." to "Close the
  subdomain policy gap. With sp=none, mail from any subdomain
  is delivered as if no policy existed."
- 2581: "If an attacker wanted to spoof this domain, they
  would send directly as user@{domain} since the policy is
  p={policy} and no mail is blocked." to f"The easiest path to
  spoofing this domain is direct: mail sent as user@{domain}
  is not blocked, because the policy is p={policy}."
- 2583: to f"The easiest path to spoofing this domain is
  through a subdomain such as mail.{domain}, because the
  subdomain policy is weaker than the root."
- 2585: to f"The easiest path to spoofing this domain is an
  invented subdomain such as secure-login.{domain}, because
  there is no np policy."
- pdf_report.py:1013 heading "Attacker Perspective" to
  "Easiest path to spoofing". Check whether the web block at
  app.js:1643 has a visible heading for `as-attacker`; if it
  does, rename it the same way.
- audit_engine.py:199 SPF_NO_RECORD: "Without SPF, attackers
  can send email claiming to be from your domain, exposing
  customers to phishing and damaging brand trust." to "Without
  SPF, receivers have no list of servers allowed to send as
  your domain, so mail claiming to be from you cannot be
  checked against one."
- 242 DMARC_PCT_LOW: to "Partial enforcement leaves some
  failing messages delivered, so a fraction of spoofed mail
  still reaches inboxes."
- 247 DMARC_TEST_MODE: to "Test mode signals receivers to
  apply a softer policy than published, so the policy in
  effect is the relaxed one, not the one you intended."
- 2954 and 3010: "Attackers may be able to forge DNSSEC
  signatures using this algorithm." to "This algorithm is no
  longer recommended in the IANA DNSSEC algorithm registry and
  its signatures are not considered secure."
- result_transformer.py:6634: "DANE is INEFFECTIVE. Without
  DNSSEC, attackers can forge TLSA records. Senders
  implementing RFC 7672 will ignore non-DNSSEC TLSA records."
  to "DANE is ineffective here. Without DNSSEC, TLSA records
  cannot be authenticated, and senders implementing RFC 7672
  ignore TLSA records from unsigned zones."
- pdf_report.py:1804 sample data "Attackers can spoof any
  subdomain." to "Any subdomain can be spoofed."

Leave, because each is a conditional scenario or a mechanism
explanation, which is what an attack surface section is for:
the vector details at 2386, 2439, 2459, 2474, and 2498 ("An
attacker could send..."), the MTA-STS explanation at 5541, the
DANE and DNSSEC mechanism notes at 6371, 6388, and
audit_engine.py:3988, and the sample strings at
pdf_report.py:1801 and 1812.

Test: extend tests/test_doc32_plurals_and_tone.py so the
plural word "attackers" does not appear in any generated
string in result_transformer.py, audit_engine.py,
checks_extra.py, pdf_report.py, or static/app.js. The singular
"an attacker" stays allowed. Comments are excluded from the
check.

## 6. Protocol Coverage ring is red when nothing is wrong

result_transformer.py:457 to 464 colours coverage red below 4
of 9 and amber below 7 of 9; app.js:2555 to 2557 and the PDF
cover follow it. On the fixture the ring is red at 3/9 with 0
issues, beside a Spoofing tile that Doc 38 correctly made
amber. Coverage is a count of what is adopted, not a defect,
and under the four-state rule red means an essential is
missing or broken.

Fix: the ring and the PDF cover count use the primary colour
(var(--primary) on the web, the existing primary constant in
pdf_report.py) whenever the count is assessable, and the
neutral colour when it is not. Keep `cov_color` in the JSON
for one release but stop using it for the ring; note that in
the commit message.

## 7. One plural

result_transformer.py:1992 and 1999: "{n} destination(s)".
Pluralize on the count as Doc 32 did elsewhere: "1
destination", "2 destinations".

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js and style.css change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-40.md in the same commit.

## Done when

The homepage says what the tool reads and does not say it
reads email, the About page claims an RFC citation and not a
section number, the np notes agree with RFC 9989 Appendix C,
no generated string contains the plural "attackers", the
coverage ring is never red, and the destination count
pluralizes.
