# Doc 47: Tone, repetition, plurals, placeholders, and plain wording

Fifth doc from the Sept 13 review. Nothing here changes a
status or a fact; every item is how something is said.
Replacement text is given; use it as written. Line numbers are
from main at 3d28899; search for the quoted string if one has
moved.

## 1. Delivery predictions at p=none

Doc 18 banned telling a reader that mail "is delivered" under
p=none, because p=none requests no action and every receiver
decides for itself; the executive summary already says exactly
that. Eight strings still predict delivery. Replace each with
the sentence below, or with the variant noted.

The sentence: "p=none requests no action, so each receiver
applies only its own filtering to mail that fails."

- result_transformer.py:2700 to 2705, the p=none tag
  explanation: replace the whole paragraph with: "Monitoring
  only: the record asks receivers for no action. p=none
  requests no action, so each receiver applies only its own
  filtering to mail that fails. It is the right first step for
  collecting aggregate reports; the goal is to progress to
  p=quarantine and then p=reject once every legitimate sender
  aligns."
- 3390 to 3394, the Monitoring mode warning: replace with:
  "Monitoring mode. p=none requests no action, so each
  receiver applies only its own filtering to mail that fails.
  Review your aggregate reports and progress to p=quarantine
  then p=reject once every legitimate sender aligns."
- 2459 (comment) and 2490, the pct detail: "the rest are
  delivered normally" becomes "the rest get the next weaker
  treatment".
- 1956: "for the message to be delivered normally" becomes
  "for the message to pass DMARC".
- audit_engine.py:237, BUSINESS_RISK DMARC_P_NONE: replace
  "Mail that fails authentication is still delivered as if it
  came from you." with the sentence.
- audit_engine.py:6129, resilience summary: replace "Spoofed
  messages will still be delivered." with the sentence.
- audit_engine.py:241, DMARC_NO_RUA: "Spoofing attacks may
  already be happening undetected." becomes "Without aggregate
  reports you cannot see who is sending as your domain or
  whether their mail passes."
- static/app.js:2870: the disposition label for none is
  'delivered'; make it 'no action requested'.

## 2. Marketing register on the DMARC card

result_transformer.py:2226 to 2231: "Without DMARC, Gmail,
Yahoo, and Outlook increasingly penalize your domain. ...
DMARC tells receivers you take your email reputation
seriously. If you send marketing emails, sales outreach, or
business communications, this gap is likely hurting your inbox
placement right now." Unsourced, and a claim about inbox
placement the tool cannot measure. Replace the whole string
with the Google and Yahoo sentence from Doc 46 item 7 and
nothing else.

2240 to 2245: "They often treat unaligned mail with suspicion.
... Moving to p=quarantine or p=reject signals that you
control your email and generally improves inbox placement."
Replace with: "With p=none, receivers apply their own
filtering to mail that fails. Google and Yahoo require a DMARC
record from bulk senders, and p=none satisfies that
requirement."

2971 and 3215: "This record serves no purpose." A p=none
record without rua still satisfies the bulk-sender
requirement. Replace 2971 with "No enforcement and no
reporting." and 3215 with: "At p=none the record enforces
nothing, and without rua it reports nothing, so it only
satisfies the bulk-sender requirement. Add rua= to get the
reports the policy exists for." Drop "immediately" at 3205,
3210, and 3215; the sentence that names the cost is enough.

667: "Anyone can send email as your domain." Anyone can send
mail as any domain; DMARC changes what receivers do with it.
Replace with: "Receivers have no policy for mail that fails
authentication, and you get no reports about who is sending as
you." 1455: "can be freely spoofed" becomes "carry no policy
of their own".

## 3. Labels and voice

pdf_report.py around line 985 prints "[PROTECTED]",
"[PARTIAL]", "[EXPOSED]" beside attack vectors, and
app.js:1621 prints "Partially Protected" in title case. Doc 38
allows uppercase only on the tier tags and section labels. Use
"Protected", "Partly protected", "Exposed" in both places. The
readiness labels at result_transformer.py:428 to 430, "In
Progress" and "Action Needed", sit beside "Monitoring only"
and "Not assessed" which are already sentence case; make them
"In progress" and "Action needed". static/app.js:2994 emits
"OVER LIMIT" and "NEAR LIMIT" as text; make them "Over limit"
and "Near limit".

pdf_report.py:1627 "Comprehensive DNS Security Audit" and 1761
"Comprehensive security audit report": use the scope label the
report already carries ("Complete Audit", "Email Security",
and so on) in both.

First person plural on a one-person site:
result_transformer.py:1089 and app.js:1359 "We are now
tracking this domain." becomes "This domain is now tracked;
run another audit later to see what changed." 1444 "We found
{n} active subdomains" becomes "This audit found {n} active
subdomains".

## 4. Plurals and a false count

"(s)" survives in five places. Pluralize on the count as Doc
32 did: audit_engine.py:1933 "valid URI(s)", 1009 and 1010
"TXT record(s)"; result_transformer.py:3446 "domain(s)";
anomaly_detector.py:286 "destination(s)".
result_transformer.py:6374 "which CA(s) you use" becomes
"which CAs you use".

result_transformer.py:737 "Rotate weak DKIM keys to 2048-bit"
and its impact line "These keys are below current
recommendations" render for a single 1024-bit key. Count the
weak selectors and pluralize both.

## 5. Placeholders and an em dash

result_transformer.py:2429, 2751, 3168 fall back to
"yourdomain.com" when domain is empty, and
audit_engine.py:1440 and 1456 and anomaly_detector.py:166
print rua=mailto:...@yourdomain.com in fix text. Every one of
these runs inside a function that has the audited domain in
scope. Use the real domain. anomaly_detector.py:294 prints
"<yourdomain.com>._report._dmarc.<destination-domain>" as a
template, which is fine as a template but should use the real
domain too.

static/app.js:1274 writes "&mdash;" into the structural-errors
banner and 1688 and 1692 write the em dash character (U+2014)
into the subdomain table's empty cells. The dash test only
catches the literal character. Replace 1274 with: "This record
has structural errors that affect parsing, so the results
below may be unreliable." and the two cells with "n/a".

## 6. The same sentence, several times on one page

- "requests no action from receivers, who each decide
  independently what to do with failing mail" appears in the
  cover verdict (result_transformer.py:345), the
  deliverability line (558), the DMARC explanation (1945), and
  the Priorities row impact that 324 feeds. Keep it in the
  verdict. The Priorities impact becomes "Nothing is blocked
  yet, and every receiver is making its own call on mail that
  fails." The explanation at 1945 keeps its first clause and
  drops the "who each decide independently" clause.
- "phishing or malware to your customers and partners ...
  erode trust" at 2704 and 3392 is on the same card twice;
  item 1 above removes both.
- 2944 to 2957, the rua note: "These show which sources send
  mail as your domain and whether they pass or fail
  authentication." then "These show every source sending as
  your domain." Delete the second sentence and keep "Review
  before moving to enforcement." 2949: "These reports are the
  only way to know if legitimate mail is being silently
  rejected." A rejected message bounces to its sender, so
  reports are not the only signal. Replace with: "These
  reports are how you find legitimate senders failing
  authentication before their mail is rejected."
- The pct and ri rows in the tag table print their explanation
  and then an appended warning that says the same thing ("Safe
  to remove. ! Removed in RFC 9989. Safe to remove."). When
  the explanation already carries the sentence, do not append
  the warning.
- An enforcing record without rua says "No aggregate
  reporting" in the explanation (1973 and 1980), in a detail,
  in a second detail ("You are enforcing DMARC at p=quarantine
  with no aggregate reporting..."), and in Configuration
  Warnings. Keep the explanation sentence and one detail.
- CAA at 6368 and the paragraph above it both say any CA may
  issue certificates; BIMI at 6066, 6077, and 6107 says three
  times that it is brand recognition, not security. Once each.

## 7. Plain wording for a non-specialist

Replace these where they appear (result_transformer.py roadmap
impacts at 761, 767, 772, and the tooltips in app.js):

- 761 "Without MTA-STS, email encryption can be silently
  stripped." becomes "Without MTA-STS, a sending server that
  cannot reach your mail server over TLS falls back to
  plaintext and nothing tells you."
- 767 "TLS downgrade attacks go undetected." becomes "You get
  no report when a sending server fails to reach your mail
  server over TLS."
- 772 "Inbound mail TLS relies solely on the CA system, with
  no DNS-pinned backstop if a CA is compromised or coerced."
  becomes "Without DANE, a sending server has no way to check
  your mail server's certificate against DNS; it trusts
  whichever certificate authority issued it."
- 5104, the ARC sentence on the DKIM card, has no connection
  to the finding it sits under. Delete it from the card.
- app.js:143 "Forces encrypted TLS connections between mail
  servers" becomes "Tells sending servers that support it to
  require TLS when delivering to your domain." app.js:151
  "Public log of all certificates issued for your domain"
  becomes "Public logs of certificates issued for your
  domain."
- 4694, 616, 4963, 4985: "Enter your selector in the field
  above" appears in the PDF, where there is no field. Use
  "Re-run the audit at dns-audit.com with the selector
  entered" in text that reaches the PDF, and keep "above" only
  in strings the web page alone renders.
- The SPF-missing detail "No SPF record tells receivers which
  servers can send your email" parses as "there is no record
  that tells". Replace with: "Without an SPF record, receivers
  have no list of the servers allowed to send your email."

## Tests

Extend the tone test with the banned strings: "delivered
normally", "still delivered", "delivered to their inbox",
"increasingly penalize", "hurting your inbox placement",
"serves no purpose", "immediately", "We are now tracking", "We
found", "OVER LIMIT", "yourdomain.com" outside comments,
"(s)", "&mdash;", the U+2014 character, "only way to know",
"Comprehensive". Add a repetition test: for the three Doc 44
fixture zones, no sentence of more than eight words appears
twice within one card's rendered text.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-47.md in the same commit.

## Done when

No generated string predicts delivery at p=none or sells inbox
placement, labels are sentence case, plurals follow their
counts, the audited domain replaces every placeholder, no card
says the same sentence twice, and the plain rewrites above are
live.
