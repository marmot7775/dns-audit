# Doc 91: site copy accuracy

Drafted 2026-10-01 by a cloud review agent against main at 1a63ebe. RFC text fetched from
rfc-editor.org. Line numbers refer to that commit. Spot-checked by Claude: items 13, 16 and
20 confirmed against the code.

Decision needed before this runs: items 11, 18, 23 and 24 (and the result_transformer note
under "Unsure") change how the tool labels its p=reject path. Today the tool calls the
enforcement path "Migration path to RFC 9989" and gates "RFC 9989 Ready" on an enforcing
policy and an rua address. RFC 9989 itself accepts p=none. Either keep the gate and rename it
(this draft), or keep the name and drop the gate.

## static/index.html

**1.** FAQ JSON-LD, "What is the most important DNS record for email security?" (line 77)

- Current: "Set p=reject only after the aggregate reports stop showing new legitimate senders and every one of them aligns."
- Replacement: "Move to p=quarantine and then p=reject only after the aggregate reports stop showing new legitimate senders and every one of them aligns, and sign all mail with DKIM first. RFC 9989 says a domain at p=reject must not rely on SPF alone, and that domains whose users post to mailing lists should not publish p=reject."
- Evidence: RFC 9989 section 7.4.

## static/about.html

No problems found in the first three paragraphs.

## static/app.js

**2.** Defensive DNS banner (line 828)

- Current: "This domain is configured to not send or receive email. The DNS records explicitly reject all email activity, which is a security best practice for non-mail domains."
- Replacement: "This domain publishes records that say it does not handle email. The signals below show which directions are closed. Publishing them is a security best practice for non-mail domains."
- Evidence: audit_engine.py:5178 sets is_defensive from any two of null MX, v=spf1 -all and p=reject. A domain with working MX plus -all and p=reject gets this banner even though it receives mail.

**3.** Tree walk footnote (line 2721)

- Current: "This subdomain inherits its DMARC policy from the organizational domain."
- Replacement: "This subdomain has no DMARC record of its own, so receivers apply the policy found at the domain named above."
- Evidence: dmarc_tree_walk.py:474-479; with psd=y the policy comes from the PSD record (RFC 9989 section 4.10.1).

**4.** Tree walk "Walk Queries" row (line 2713)

- Current: "${walkQueries} of 8 max"
- Replacement: "${walkQueries} of 7 max, after the lookup at the domain itself"
- Evidence: dmarc_tree_walk.py:81-84 and 236. query_count excludes the Author Domain query and is capped at 7.

**5.** Report delivery chain intro (line 3412)

- Current: "All report destinations are properly configured to receive DMARC reports."
- Replacement: "No report destination failed the RFC 9990 authorization check."
- Evidence: audit_engine.py:556-575. A failed authorization lookup and a destination with no MX both still produce this sentence.

**6.** Report destination label (line 3434)

- Current: "Same domain (no external authorization needed)"
- Replacement: "Same organizational domain (no external authorization needed)". When authorization_check_failed is true, use "Authorization not confirmed (lookup failed)", which needs its own branch.
- Evidence: audit_engine.py:556-565; RFC 9990 section 4 compares Organizational Domains.

**7.** Report chain section summary (line 1460)

- Current: "${n} destinations, all authorized"
- Replacement: "${n} destinations, no authorization failures"
- Evidence: app.js:1457 counts only authorized === false.

**8.** Report destination mail line (line 3441)

- Current: "Cannot receive mail (no MX)"
- Replacement: "No MX record found"
- Evidence: audit_engine.py:571-575 sets has_mx False on any DNS exception; with no MX, senders fall back to A/AAAA (RFC 5321 section 5.1).

**9.** SPF trace intro (line 3266)

- Current: "Receivers that enforce this limit will return a permanent error."
- Replacement: "RFC 7208 requires a receiver to return a permanent error (permerror) when evaluation reaches the eleventh lookup."
- Evidence: RFC 7208 section 4.6.4.

**10.** DMARC Evaluation section summary (line 1450)

- Current: "SPF and DKIM aligned"
- Replacement: "SPF and DKIM can both align"
- Evidence: spf_execution_engine.py:320; the card body already says "alignment possible".

**11.** Migration panel heading (line 2302)

- Current: "Migration path to RFC 9989"
- Replacement: "Path to enforcement"
- Evidence: result_transformer.py:4400-4470 and 4098-4110; RFC 9989 sections 4.7 and 7.4. See the decision note at the top.

**12.** Priority row "How to confirm" (line 3111)

- Current: "This row disappears when the check passes."
- Replacement: "This row disappears once the change is live."
- Evidence: result_transformer.py:1220 adds a "make np explicit" row while the DMARC card passes.

**13.** Cache badge button tooltip (line 4254)

- Current: "Force a fresh audit"
- Replacement: "Run again. Results are cached for five minutes, so a re-run inside that window returns this same result."
- Evidence: server.py:799 (nocache removed from the public API); config.py CACHE_TTL 300.

**14.** Subdomain table button tooltip (line 2027)

- Current: "Run full audit on ${subdomain}"
- Replacement: "Audit ${subdomain} with the scope selected above"
- Evidence: app.js:374 sends the currently selected scope.

## README.md

**15.** DKIM row (line 19)

- Current: "Selector discovery from a list of about 1,100 known selectors, narrowed by SPF-based vendor fingerprinting to about 200 lookups per audit."
- Replacement: "Selector discovery from a list of about 1,100 known selectors. Up to 40 are tried first, chosen from vendors detected in SPF and MX, and a sweep of 156 common names runs only when those find nothing."
- Evidence: spf_intelligence.py:262 and 350-361.

**16.** MX row (line 25)

- Current: "Mail exchanger discovery, vendor fingerprinting, FCrDNS validation, redundancy analysis, dangling MX detection, null MX (RFC 7505) recognition."
- Replacement: "Mail exchanger discovery, vendor fingerprinting, redundancy analysis, dangling MX detection, null MX (RFC 7505) recognition."
- Evidence: no PTR or FCrDNS code exists; removed in d0dc0d0.

**17.** TLS-RPT row (line 27)

- Current: "SMTP TLS reporting record validation, report destination verification (`mailto` and HTTPS)."
- Replacement: "SMTP TLS reporting record validation, including the syntax of each report destination (`mailto` and `https`)."
- Evidence: checks_extra.py _validate_tls_rpt_record checks only scheme and format.

**18.** Summary metrics table (line 52)

- Current: "Ready, Compatible, In progress, or Action needed"
- Replacement: "Ready, Compatible, In progress, Action needed, or Not assessed. Ready also requires an enforcing policy (p=quarantine or p=reject) and an rua address, which RFC 9989 itself does not require."
- Evidence: result_transformer.py:626-640 and 4098-4110. See the decision note at the top.

**19.** Features list (line 68)

- Current: "**Vendor detection**: from MX hosts, SPF includes, DMARC `rua` addresses, and DKIM selectors."
- Replacement: "**Vendor detection**: from MX hosts, SPF includes, and DMARC and TLS-RPT `rua` addresses."
- Evidence: advanced_fingerprinting.py:58-76 has no DKIM step.

**20.** Tests (line 142)

- Current: "1,086 tests, run against fake DNS zones."
- Replacement: "1,951 tests, run against fake DNS zones." (Recount at run time; three test files were added on 2026-10-01.)
- Evidence: pytest --collect-only.

**21.** What it does not do (line 147)

- Current: "Outbound traffic is DNS plus HTTPS fetches of MTA-STS policies, BIMI logos, and crt.sh."
- Replacement: "Outbound traffic is DNS plus HTTPS fetches of MTA-STS policies, BIMI logos, and crt.sh, and error reports to Sentry when SENTRY_DSN is set."
- Evidence: server.py _init_sentry.

## pdf_report.py

**22.** Roadmap confirm line (line 705)

- Current: "This item disappears when the check passes."
- Replacement: "This item disappears once the change is live."
- Evidence: same as item 12.

**23.** Migration section heading (line 1710)

- Current: "Migration path to RFC 9989"
- Replacement: "Path to enforcement"
- Evidence: same as item 11.

**24.** Migration step count (line 1728)

- Current: "{n} steps to reach RFC 9989 Ready status:"
- Replacement: "{n} steps from the current record to an enforcing policy:"
- Evidence: same as item 11.

**25.** Methodology (line 1865)

- Current: "This report was generated using live DNS queries against published DNS records."
- Replacement: "This report was generated from live DNS queries, plus HTTPS fetches of the MTA-STS policy file, the BIMI logo, and certificate records from crt.sh."
- Evidence: checks_extra.py:584 and 1097, audit_engine.py:4081.

## Unsure, needs a human look

- index.html line 107, SPF DefinedTerm: "specifies which mail servers are authorized to send email for a domain". RFC 7208 authorizes hosts for MAIL FROM and HELO, not the visible From. Possible replacement: "A DNS record that lists the hosts allowed to send mail using a domain in the SMTP MAIL FROM (envelope sender) and HELO identities, defined in RFC 7208."
- README.md line 61, "38 finding codes": a count of the strict validator's codes gives 39. Count mechanically before changing.
- pdf_report.py line 1799, "DMARC audited against RFC 9989, 9990, and 9991": nothing tests RFC 9991 behavior. "Against RFC 9989 and 9990" may be more accurate.
- about.html paragraph 3, "no cookies, and no tracking": settled 2026-10-01. No Set-Cookie on /, /about or /api/health, and Bot Fight Mode's cf_clearance is gone. No change needed.
- result_transformer.py:4199 says the readiness scale "reflects how completely the record matches RFC 9989", but a fully conformant p=none record is rated Monitoring. Same root as items 11, 18, 23 and 24.
- dmarc_tree_walk.py:375-378 labels every walked name with two or fewer labels "Organizational Domain", including _dmarc.com and co.uk.
