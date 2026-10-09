# Doc: report copy, part 1 (address leak, false statements, naming)

Repo: dns-security-auditor. Written against main at 3b9308c. Line
numbers are from that commit. Re-read each site before editing; if
a line has moved, find the string by its text.

Scope: text a visitor sees on the results page or in the PDF. Do
not restyle anything outside the items below. A later doc covers
tone and jargon across the rest.

Rules for every string you write here:
1. No dashes as punctuation (em dash, en dash, or spaced hyphen).
   Hyphens inside compound words are fine.
2. Sentence case.
3. No banned words: leverage, optimize, streamline, enhance,
   robust, seamless, just, very, really, basically.
4. Say what DMARC does accurately: receiving mail servers are
   asked to act on mail that fails authentication. That can
   include real mail from a sender the owner missed. Do not say
   mail "pretends" to be from the domain, and do not state a
   requested action as a certain outcome.

## Part A. Email address published in plain text

The live homepage serves mailto:dns@dns-audit.com unobfuscated.
The address is allowed only in the footer and the results note,
and only with Cloudflare email obfuscation applied.

A1. Every page wraps the address in <!--email_off--> ...
    <!--/email_off-->. Those tags tell Cloudflare NOT to obfuscate.
    Remove the tags (keep the link) in index.html, about.html,
    privacy.html, 404.html, and every file in static/articles/.
    grep -rn "email_off" static/ must return nothing afterward.

A2. app.js line 4453 builds the mailto inside a JS string.
    Cloudflare only rewrites HTML responses, so the address sits in
    plain text in app.js no matter what. Remove the email link from
    the results note entirely. Keep LinkedIn only. The footer on the
    same page carries the protected email link.
    grep -n "dns@dns-audit" static/app.js must return nothing.

## Part B. Contact note: placement and wording

B1. index.html places #results-contact-note after the collapsed
    "Services found in your DNS" section, so "these" reads as the
    services. Move the note so it renders directly after the
    What to do section (#priority-section).

B2. Replace the text in _renderContactNote (app.js about 4456):

    Fail or warn case:
    If you'd like help with these changes, I do this work for
    clients. <a>Message me on LinkedIn</a>.

    Clean case (sendsMail and no unavailable checks):
    No problems found in this domain's DNS. If its mail still goes
    to spam, the cause is outside what this audit checks, such as
    sender reputation or how the mail is sent. I work on that too.
    <a>Message me on LinkedIn</a>.

## Part C. One name for the action list

The section is headed What to do. Other text calls it "the plan"
or "listed below". Use What to do everywhere on the web page.

C1. app.js 3024 button "See the plan" -> "See what to do".
C2. result_transformer.py 930 and app.js 3108 fallback:
    "Nothing urgent. The plan has smaller improvements." ->
    "No urgent problems. Smaller improvements are under What to do."
C3. result_transformer.py 712 and 715 verdicts:
    712 -> "Receiving mail servers are asked to refuse mail that
    fails authentication for this domain and its subdomains."
    715 -> "Receiving mail servers are asked to refuse mail that
    fails authentication for this domain. Smaller improvements are
    under What to do."
    With 715, the line under it would repeat the same point. When
    the verdict already names What to do, the es-first note must
    not print the C2 sentence as well.
C4. result_transformer.py 1044: "The plan below has what to
    tighten." -> "What to do lists what to tighten."

## Part D. Statements that are false or misleading

Fix each. Where a string appears in more than one place, fix all
of them.

D1. Missing p= with a valid rua. 4545, 1484, 3299 in
    result_transformer.py, and 1401 to 1406 and 1419 in
    audit_engine.py say RFC 7489 receivers ignore the record. Wrong.
    RFC 7489 section 6.6.3 says a record with no valid p= but a
    valid rua SHOULD be treated as p=none, same as RFC 9989. There
    is no split behavior and no interop hazard. Rewrite as:
    "This record has no p= tag. Because it has a report address,
    receiving mail servers treat it as p=none. Add p= so the record
    states its policy." Drop the severity from critical to advisory
    so a working record no longer gets a red Misconfigured badge.
    Fix the 1484 plan action to "Add a p= tag to the DMARC record".
    Before citing a section number in text, confirm which RFC 9989
    section holds this rule. Strings now cite both 4.7 and 4.10.1.

D2. "Pretends to be from" at result_transformer.py 662, 682, 1366.
    662 -> "Your domain has no DMARC record, so receiving mail
    servers get no instruction for mail that fails authentication."
    682 -> "Your DMARC policy is p=none, which asks receiving mail
    servers to take no action on mail that fails authentication.
    Each server decides on its own."
    1366 -> "Receiving mail servers have no instruction for mail
    that fails your authentication checks."

D3. result_transformer.py 1857: "Bring the subdomain policy up to
    p={_p_val}". The record attached changes sp=. Change to
    "Raise the subdomain policy to sp={_p_val}".

D4. result_transformer.py 4002 and 4008: "This domain can be
    spoofed through {name}." When the only exposed vector is
    Reporting Intelligence, this prints "spoofed through reporting
    intelligence", which is false. Use one sentence per vector:
    exact domain: "Mail sent as your exact domain is not blocked."
    subdomains: "Mail from your subdomains is not blocked."
    nonexistent: "Mail from made-up subdomains is not blocked."
    reporting: "Some of your DMARC reports are not delivered."
    4011 says "exposed" in the branch where nothing is exposed.
    Change to "Some routes are only partly covered."

D5. result_transformer.py 4828 and 5047: "RFC 9989 splits the
    specification into three separate RFCs". RFC 9989 is one of the
    three. Change to "DMARC is now three documents: RFC 9989 for
    the core, RFC 9990 for aggregate reports, and RFC 9991 for
    failure reports." Confirm 9990 and 9991 map that way first.

D6. result_transformer.py 6859: "A DKIM key is published. Signed
    mail gives receivers a domain to attach reputation to." This
    prints on failed cards with unusable keys (SHA-1 only, bad v=,
    unknown k=, unparseable p=). Show it only when status is pass.

D7. result_transformer.py 7967: the DNSSEC explanation "DNSSEC is
    enabled ... This prevents cache poisoning" shows on fail and
    warn cards too (DS mismatch, signed_unanchored). On pass:
    "DNSSEC is on. Resolvers that check signatures can confirm your
    DNS answers were not altered." On fail or warn: "The zone is
    signed, but resolvers cannot verify it yet, so it gets none of
    DNSSEC's protection."

D8. result_transformer.py 7853: "Google 8.8.8.8 in DNSSEC mode".
    Google Public DNS validates by default. Remove "in DNSSEC mode".

D9. result_transformer.py 6973 and the card detail near 6628: keys
    under 1024 bits are labeled "can be factored and forged" and
    "upgrade recommended". RFC 8301 section 3.2: verifiers MUST NOT
    treat signatures from RSA keys under 1024 bits as valid, so
    these already fail. Label: "Under 1024 bits. Receiving servers
    must reject signatures from keys this small (RFC 8301), so this
    key fails now. Replace it with a 2048-bit key."

D10. result_transformer.py 1667: SPF over the limit says the list
    is "too long". The limit is DNS lookups, not length. Change to
    "Your approved sender list needs more DNS lookups than
    receiving servers allow, so some or all of your mail fails
    this check."

D11. SPF at exactly 10 lookups gives three answers on one card:
    5703 "cannot satisfy DMARC alignment for any message", 5908
    "some or all of your mail fails", 5917 "will break SPF for all
    your email". At 10, nothing fails yet. Make all three say:
    "Your SPF record is at the 10 lookup limit. One more include,
    a, mx, or exists will push it over, and receiving servers will
    return an error instead of a pass." Also 5713 "Any addition
    will cause a PermError" is wrong, since ip4 and ip6 cost no
    lookup. Use the same sentence.

D12. result_transformer.py 5644: no MX does not mean the domain
    sends no mail. Change to "No SPF record found. This domain has
    no MX records, so it does not receive email. If it sends none
    either, publish v=spf1 -all to say so."

D13. result_transformer.py 7458 MTA-STS enforce verdict "Inbound
    email must use encryption" overclaims. Change to "Enforced:
    senders that support MTA-STS must use encryption".

D14. result_transformer.py 7596: TLS-RPT reports arrive after the
    failures, so "before they affect delivery" is wrong. Change to
    "Without TLS-RPT, you don't hear about encryption failures when
    other servers deliver to you. Senders that support it send a
    daily report."

D15. audit_engine.py 6723 and 6773: the fix assumes every SPF
    PermError is a lookup overflow. It can also be two SPF records,
    a syntax error, or void lookups. 6723 -> "Fix the SPF error
    shown on the SPF check first. Until SPF works, this domain can
    pass DMARC only through DKIM." 6773 -> "Fix the SPF error shown
    on the SPF check to restore the second way to pass DMARC."
    Check that 6723's wording fits its condition; if DKIM is also
    absent on that path, say "has no way to pass DMARC".

D16. audit_engine.py 4211 and 4218: "crt.sh was temporarily
    unavailable. This does not affect the audit results." The CT
    result is missing, so it does. Change to "The certificate log
    service (crt.sh) didn't respond, so this check is incomplete.
    The other checks are unaffected."

D17. pdf_report.py 1995 refers to "The Protocol Coverage figure on
    the cover". That tile is now labeled Records published and sits
    at the start of Part 2. Point at it by its real name and place.

D18. pdf_report.py 1850, 2086, 746: one section is called "Path to
    enforcement" in its heading and "Migration path" in the
    contents and in the plan text. Use "Path to enforcement" in all
    three, and in the web strings that say "migration steps" or
    "migration path" (app.js 154 to 160, 2588).

## Done when

1. Tests updated for every changed string. Full suite passes. Say
   the before and after test counts.
2. grep checks in A1 and A2 return nothing.
3. Each D item reproduced before the fix and shown correct after,
   with a mocked audit through run_full_audit, not by reading the
   diff.
4. After deploy, curl the live homepage and app.js and confirm no
   plain dns@dns-audit.com in either, and that Cloudflare's
   /cdn-cgi/l/email-protection link appears in the footer. If it
   doesn't, Email Address Obfuscation is off in Cloudflare Scrape
   Shield; report that, don't work around it.
5. Report back in one fenced markdown block: commit SHA, each item
   with done or skipped and why, test counts.
