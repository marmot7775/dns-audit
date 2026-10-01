# Doc 92: results people can read

Audited locally at 48ea434: google.com (clean), intelligentsia.com (small business, p=none, no rua), gitlab.com (13 SPF lookups) and example.com (parked). Captured screenshots at 390 and 1280 px, plus a dump of every visible text node and its position. The repo is unchanged.

## Findings

What works: closed cards, "What this is", and plan rows split into Why, What to change and How to confirm. The overload is what sits in front of the plan, plus the page disagreeing with itself. Ranked:

**1. The first screen never says what to do in plain words.** On a phone it shows:
- the domain, a cache badge, a Request ID and three buttons
- the verdict, three metric tiles, a risk box and a deliverability line

The first plan row is 1,340 to 1,450 px down, about 1.6 phone screens, and five counter tiles sit in between. The "biggest risk" headline is always a technical instruction, for example "Add aggregate reporting (rua=)" or "Check zone transfer (AXFR/IXFR) configuration and ensure all secondaries are in sync."

**2. Jargon comes before meaning.** Distinct technical terms:

| | First screen | Whole collapsed page | Before the first plain sentence about what is wrong |
|---|---|---|---|
| google.com | 15 | 28 | 8 |
| gitlab.com | 9 | 25 | 9, and no plain sentence appears at all |
| intelligentsia.com | 8 | 25 | 5 |
| example.com | 4 | 21 | 3 |

None of the four first screens has a plain sentence saying what to do.

**3. The page contradicts itself.** These cost trust with both readers.

| Domain | What the page says | What else the page says |
|---|---|---|
| gitlab.com | Verdict: "blocks spoofed email across all vectors, with minor improvements available" | "None of your mail passes SPF", and the SPF card is red |
| gitlab.com | Biggest risk is DKIM key length | The broken SPF record is the more serious finding |
| gitlab.com | "None of your mail passes SPF" | The site's own SPF article says the order of the record decides which mail fails, so this overstates |
| intelligentsia.com | DMARC card: amber "Warning" | Readiness tile: red "Action needed". Breakdown: "Misconfigured: This record has critical issues" |
| intelligentsia.com | Subdomain header: "20 subdomains probed, none exposed" | 20 red "Exposed" rows, all for names that do not exist |
| intelligentsia.com | One fact, four framings: "Several routes to spoofing this domain are open", "Every spoofing vector exposed", "3 of 4 paths exposed", "Moderate Risk" | |
| google.com | Biggest risk: an SOA serial mismatch | This is usually transient propagation |
| example.com | "blocks spoofed email across all vectors, with minor improvements available", "Compatible", "3/9" | The domain handles no mail. "Defensive DNS Detected" sits below the card list heading |

**4. Numbers have no meaning attached.**
- The coverage ring reads "3/9".
- There are five counters, and "Not configured 6" looks worse than "Passing 4" although those six are optional.
- On example.com, four "Not configured" checks are really "Not applicable".
- "Not checked 1" showed on all four audits because crt.sh timed out. The page does not say so.

**5. The same point is repeated.**
- On intelligentsia, missing reporting is stated seven times: the risk box, the plan's Why, the card note, two detail rows, "Business impact" and "Reporting Intelligence".
- On gitlab, "Mixed DKIM key strengths" in What's unusual repeats the DKIM plan row.
- The SPF lookup count appears in two panels.
- Every panel title appears twice.
- The PDF prints the tally on pages 1 and 2.

**6. Everything gets the same weight.**
- BIMI, CAA and DANE rows look the same as DMARC.
- "Remove the tags RFC 9989 retired" is medium, the same as MTA-STS, although receivers ignore those tags.
- Status words come from six vocabularies:
  - card pills: Pass, Warning, Fail, Not configured, Not applicable, N/A, Not checked, Not confirmed, Null MX
  - counters and PDF: Failing, Issue, Issues
  - tiers: critical, high, medium, low
  - attack surface: Exposed, Partly protected, Moderate Risk
  - breakdown: Misconfigured
  - resilience: High, Moderate

**7. On a phone a closed row says almost nothing.** The verdict line is hidden at 390 px (style.css:3352), so each row is an acronym and a pill.

**8. RFC notes come before the finding.** Inside the DMARC card, the second warning row is RFC 9989 section C.5.2 text in the same amber as the p=none warning. Fully expanded, the page runs 4,193 to 6,504 words.

**9. The top action has nothing to paste.** The intelligentsia "Add aggregate reporting" row (high) is prose only, while the cosmetic retired-tags row (medium) has a record to copy. A p=none record without rua also never gets the "Progress from p=none to enforcement" row.

## Proposal

One page in three layers. Nothing is deleted.

**Layer 1, the short answer, on the first screen for everyone.** The domain, one plain verdict and at most three numbered actions. Each action states the consequence first, then the instruction, with the term in grey parentheses:

> **intelligentsia.com**
> Your domain does not yet ask receivers to block mail that pretends to be from you. Each receiver decides on its own.
> 1. You get no reports on who sends mail as you. Add a report address to your DMARC record. (rua)
> 2. When the reports show all your real mail passing, ask receivers to block the rest. (p=none to quarantine, then reject)
>
> [See the plan] [Technical summary]

The actions are the top non-optional plan rows. Optional extras never appear here. "Technical summary" opens today's three tiles and the deliverability line, unchanged.

**Layer 2, the plan, for the owner or IT person.** Today's "What to do" list.
- A closed row leads with the plain consequence, with the current action under it.
- An open row shows Why it matters, What to paste (host, record, Copy), Who does this ("your DNS host" or "your email provider") and How to confirm.
- Absent optional protocols are grouped at the end under "Optional extras (3)", closed.
- The counters become one line below the plan.

**Layer 3, technical details.** Headed "Technical details: all 12 checks". It holds every card, panel, citation, trace, What's unusual and vendor table, with the same content. Titles lead with a plain name and keep the protocol. The verdict line shows on phones. Request ID and the cache badge move to the bottom.

## Element-by-element changes

| Element | Change | Layer |
|---|---|---|
| Domain, timestamp, PDF/Export/Share | Keep | 1 |
| Cache badge, Request ID | Move to the bottom | 3 |
| Verdict | Reword. Add branches for a failing essential card and for a no-mail domain | 1 |
| Spoofing, Readiness and Coverage tiles | Collapse into "Technical summary" and relabel. Readiness is never redder than the DMARC card | 3 |
| Biggest risk box | Merge into "Do these first" (up to three actions) | 1 |
| Deliverability line | Collapse into "Technical summary" | 3 |
| What to do / View Attack Surface buttons | Keep "See the plan". Move the other button into the summary | 1/3 |
| Five counters | Merge into one line above the cards | 2 |
| Plan rows | Reword the head. Add "Who does this". Group optional extras | 2 |
| Tier pills | Reword: Fix now / Important / Recommended / Optional | 2 |
| rua row | Add a record to paste | 2 |
| What's unusual | Hide when a plan row covers that protocol. Otherwise move it into the card | 3 |
| Defensive DNS box | Merge into the verdict | 1 |
| Card title | Plain name first, protocol in parentheses. Keep the id | 3 |
| Card verdict line | Show at 390 px | 3 |
| DMARC detail rows | Order policy, then reporting, then RFC notes in grey | 3 |
| Subdomain rows, breakdown verdict | Reword (below) | 3 |
| Panel heading repeating its sub-header | Remove | 3 |
| Email Services + Your email platform | Merge into one closed section, "Services found in your DNS" | 3 |

## Rewritten strings

**Verdicts** (result_transformer.build_executive_summary, 535 to 573)

| Current | Proposed |
|---|---|
| Your domain publishes neither an SPF record nor a DMARC record. Receivers have no way to tell... | Your domain is missing the two records that let receivers tell your real mail from forgeries (SPF and DMARC). |
| Your domain has no DMARC record. SPF alone cannot prevent email spoofing. | Your domain does not tell receivers what to do with mail that pretends to be from you (no DMARC record). |
| Your domain is monitoring email authentication but not yet enforcing it. This requests no action... | Your domain does not yet ask receivers to block mail that pretends to be from you (DMARC p=none). Each receiver decides on its own. |
| Spoofing of this domain is blocked at every level checked. | Receivers are asked to refuse mail that pretends to be from this domain or its subdomains. |
| Your domain blocks spoofed email across all vectors, with minor improvements available. | Receivers are asked to refuse mail that pretends to be from this domain. A few smaller improvements are listed below. |
| (new: essential card fails) | Receivers are asked to refuse forged mail, but one record is broken: {plain name} ({protocol}). |
| (new: no-mail domain) | This domain is set up to send and receive no email, and asks receivers to refuse any mail that uses its name. Nothing to fix. |
| Your domain has strong email authentication with most attack vectors covered. | Receivers are asked to block most forged mail from this domain. One route is only partly covered. |
| Several routes to spoofing this domain are open. | Your settings do not ask receivers to block forged mail sent as {routes}. Each receiver decides on its own. |
| Your domain has email authentication, but {vector} is still open. | Your settings block most forged mail, but not {route}. |
| Your domain partially blocks spoofed email but enforcement could be stronger. | Receivers are asked to send forged mail to spam rather than refuse it (p=quarantine). |
| Your domain blocks spoofed email but has no visibility into what is being blocked. | Receivers are asked to block forged mail, but you get no reports on what they block or whether your own mail passes. |

Routes:
- Direct Domain Spoofing becomes "your exact domain".
- Subdomain Spoofing becomes "your subdomains".
- Non-Existent Subdomain Spoofing becomes "made-up subdomains".

I did not use the brief's example, "Anyone can send email pretending to be you". It is pinned out by test_ui_consistency_a11y.py:312 and test_dmarc_p_none_delivery_claims.py, and it overstates, because receivers still filter at p=none.

**Summary labels**

| Current | Proposed |
|---|---|
| Your biggest risk right now | Do these first |
| No urgent risks found. The plan below names smaller improvements. | Nothing urgent. The plan has smaller improvements. |
| Spoofing Protection | Forged mail blocked |
| RFC 9989 Readiness | Ready for the 2026 DMARC standard (RFC 9989) |
| Action needed | Edits suggested |
| Protocol Coverage 3/9 | Records published: 3 of 9 (6 optional) |
| Passing / Warnings / Failing / Not configured / Not checked | Fine / Could be stronger / Broken / Optional, not set up / Not checked |

When it applies, "Not checked" gets the note "(a public certificate log did not answer)".

**Plan row heads** (the current action stays underneath)

| Current | Proposed head |
|---|---|
| Add aggregate reporting (rua=) | You get no reports on who sends mail as you. |
| Progress from p=none to enforcement | Your settings do not ask receivers to block forged mail yet. |
| Reduce SPF lookups (13/10) | Your approved sender list is too long for receivers to finish reading, so some or all of your mail fails this check. Mail with a valid DKIM signature can still pass. |
| Free up SPF lookups (9/10) | Your approved sender list is close to its limit. One more service could break it. |
| Rotate 2 weak DKIM keys to 2048-bit | Two of your email signing keys are shorter than recommended. They still work. |
| Check zone transfer (AXFR/IXFR)... | Your DNS servers gave different versions of your records. This usually clears within hours. If it lasts a day, ask your DNS host. |
| Configure MTA-STS for TLS enforcement | Optional: sending servers are not told to require encryption when they deliver to you. |
| Configure TLS-RPT for failure visibility | Optional: you would not hear about failed encrypted deliveries to you. |
| Remove the tags RFC 9989 retired: pct, ri | Tidy-up: your DMARC record has settings the new standard dropped. Receivers ignore them. |
| Consider adding an explicit np= tag | Optional: subdomains already get your policy. |
| Merge the duplicate SPF records into one | Your approved sender list is published twice, so receivers ignore both. |

At lines 796 and 1072, "None of your mail passes SPF" becomes "Some or all of your mail fails SPF, depending on the order of the record."

**Card titles**

| Current | Proposed |
|---|---|
| DMARC | Spoofing policy (DMARC) |
| SPF | Approved senders (SPF) |
| DKIM | Email signatures (DKIM) |
| MX Records | Where your mail arrives (MX) |
| Nameservers | DNS servers (nameservers) |
| MTA-STS | Encryption for incoming mail (MTA-STS) |
| TLS-RPT | Encryption failure reports (TLS-RPT) |
| BIMI | Logo in inboxes (BIMI) |
| DNSSEC | Signed DNS answers (DNSSEC) |
| CAA | Who can issue your web certificates (CAA) |
| DANE | Mail server certificate check (DANE) |
| Certificate Transparency | Certificates issued for your domain (CT logs) |

**Pills**

| Current | Proposed |
|---|---|
| Pass | Pass |
| Warning | Could be stronger |
| Fail, Issue | Needs fixing |
| Not configured | Optional, not set up |
| N/A, Not applicable | Does not apply |
| Null MX | No mail, by design |
| Not checked, Not confirmed | Unchanged |

The verdict line keeps its technical wording as the detail, for example "p=none (monitoring only, no enforcement)".

**Other**

| Current | Proposed |
|---|---|
| Subdomain row that does not exist: "Exposed" | Does not exist |
| Breakdown at p=none without rua: "Misconfigured / This record has critical issues" | Needs attention / This record blocks nothing and reports nothing |

## PDF

Today, page 1 has the tally, three tiles and the contents. Page 2 has the verdict, a red risk box, the tally again and the attack surface table. Proposed:

| Page | Content |
|---|---|
| Page 1, "The short answer" | The plain verdict and "Do these first" (the same three actions as the web), plus the line "Page 2 is the plan for whoever manages your DNS. Part 2 holds the evidence." |
| Page 2, "The plan" | Today's What to do, with the plain heads and records. The tally appears once, as one line |
| Start of Part 2 | The tiles, the attack surface table and the contents |

The risk box is red only for critical items. Today a missing rua prints red in the PDF and amber on the web.

Code: pdf_report._cover_page (377), _executive_summary_page (562, colours 588 to 600), _roadmap_page (805), _build_sections (1921).

## Articles

Add an `<aside class="short-version">` headed "The short version" after `.article-card-meta`. Each term below gets a definition on first use.

**What RFC 9989 changes for your DMARC record**
> In May 2026 the rules for DMARC, the record that tells receivers what to do with mail pretending to be from you, became an official internet standard, RFC 9989. Receivers will slowly change how they find your main domain, asking DNS directly instead of reading a shared list. For most domains nothing breaks and there is no deadline. Your record may need small edits: remove three retired settings (pct, rf, ri), drop any size limit on a report address, and confirm your report service accepts your reports.

| Term | Definition |
|---|---|
| DMARC | A DNS record telling receivers what to do with mail that fails authentication, and where to send reports. |
| Organizational domain | The main domain a policy belongs to, such as example.co.uk for mail.example.co.uk. |
| Public Suffix List | A volunteer-kept list of suffixes like co.uk that DMARC used to find that domain. |
| DNS tree walk | Asking DNS for _dmarc records one level up at a time. |
| Aggregate report (rua) | A daily summary from receivers of who sent mail as you and whether it passed. |
| t tag | A test switch asking receivers to apply one level below your policy. |
| np tag | The policy for subdomains that do not exist. |

**DNSSEC in 2026**
> DNSSEC signs your domain's DNS answers so computers can tell they were not forged on the way. It does not stop phishing, email spoofing, or someone taking over your registrar account. The setup problems behind its bad name have mostly been fixed, and at many DNS hosts it is now a checkbox. Banks, registrars and anyone publishing DANE records should sign; for a brochure site, sign if your host makes it easy, and do not move hosts just for this.

| Term | Definition |
|---|---|
| Resolver | The server that looks up DNS answers for a device. |
| Validating resolver | A resolver that checks signatures and rejects forged answers. |
| DS record | The record at your registrar linking your signed zone to its parent. |
| KSK rollover | Replacing the main signing key, which means updating the DS. |
| CDS/CDNSKEY | Records that let the parent pick up a new DS without a manual form. |

**DANE for email in 2026**
> DANE lets a sending mail server confirm, through signed DNS, that it reached your real mail server, so an attacker on the network cannot quietly remove the encryption. It protects the connection between servers, not the message or who sent it. Availability depends on your provider: Microsoft 365 supports it once an admin turns it on, and Google Workspace does not offer it for incoming mail. If you handle sensitive or regulated mail, set it up alongside MTA-STS and TLS-RPT.

| Term | Definition |
|---|---|
| STARTTLS | The step where two mail servers switch to an encrypted connection. |
| TLSA record | DNS record holding a fingerprint of your mail server's certificate. |
| MX host | The server that accepts mail for your domain. |
| Certificate authority | A company that issues certificates. |
| MTA-STS | A web-published policy telling senders to require encryption. |
| Fails closed | If the check fails, mail waits instead of going out unencrypted. |

**What to check before you publish p=reject**
> p=reject asks receivers to refuse mail that fails DMARC, and it is where most domains should end up. Since May 2026 the standard adds one condition: every service that sends mail as you must sign it with DKIM rather than rely on SPF alone, because forwarding breaks SPF and leaves DKIM intact. Your DMARC reports show which services pass on DKIM. Move to reject when all of them do and the list has stopped changing; there is no deadline.

| Term | Definition |
|---|---|
| p=none, quarantine, reject | Ask receivers to take no action, send failing mail to spam, or refuse it. |
| DKIM | A signature added to each message, checked against a key in your DNS. |
| SPF | A DNS list of servers allowed to send as your domain. |
| Aligned | The signing or sending domain matches the From domain or shares its main domain. |
| Stream | Any system that sends mail as your domain. |
| Forwarding | An address that passes mail on to another, which breaks SPF. |

**SPF permerror from too many lookups**
> Your SPF record lists the services allowed to send mail as you, and receivers stop reading it after 10 DNS lookups. Past that point some of your mail fails SPF, and which mail depends on the order of the record. Mail with a valid DKIM signature can still pass DMARC, so the damage is often smaller than it looks, but it is real. The fix is usually cleanup: remove unused services, drop old a, mx and ptr entries, and move bulk senders to a subdomain.

| Term | Definition |
|---|---|
| Lookup | One extra DNS query a receiver makes to read your record. |
| include | A term that pulls in another domain's SPF list, costing at least one lookup. |
| permerror | SPF's result for a record it cannot finish. It counts as a fail. |
| Flattening | Replacing includes with the addresses they hold today. |
| Return path (smtp.mailfrom) | The envelope address SPF actually checks. |

## Implementation plan

Each step ships alone. Run the full suite each time (CI is py3.11) and cache-bust after any static change.

| # | Change | Code | Size | Tests at risk |
|---|---|---|---|---|
| 1 | Show the verdict line on phones | style.css:3352 | Small | test_results_page_controls:122 (320 px), the 390 px layout checks in test_ui_consistency_a11y |
| 2 | Fix the contradictions | Subdomain rows: result_transformer:1815 to 1832. Breakdown: 4025 to 4035. SPF wording: 796 and 1072. New verdict branches: 544 to 564. SOA text: audit_engine:3677 | Small to medium | test_dmarc_grades, test_summary_hears_unavailable, test_report_major_verdicts, test_report_critical_verdicts, test_status_semantics:260, test_findings_link_articles:88 |
| 3 | Within a tier, sort fail before warn before absent | result_transformer:1311 | Small | test_status_semantics:324 to 331, test_plan_and_pdf_consistency |
| 4 | Add `plain_name` and the plan fields. Add the rua record and the p=none row | `plain_name` via attach_what_this_is (117). `plain_head` and `who` in build_security_roadmap (960 to 1311). rua record at 1019. p=none row at 1037 | Medium | Low, since only fields are added. New strings must pass test_no_dashes_in_user_facing_text and the BANNED list in test_tone_and_repetition |
| 5 | Layer 1 block and "Technical summary" | renderExecutiveSummary, app.js:2890 | Medium | test_ui_consistency_a11y:659 ("What to do"), test_results_page_controls:62 ("View Attack Surface"), test_results_page_hierarchy:143, test_protocol_coverage_ring |
| 6 | Plan rows: heads, tier labels, Who does this, optional group | renderPriorities, app.js:2987 | Medium | test_plan_section_ui:53 to 73. It pins the `.priority-action` text and the last two parts, and both are kept |
| 7 | Move the counters and the Request ID | index.html:248 to 270, app.js:663 to 667 and 741 to 747 | Small | test_summary_row, test_status_semantics:220 |
| 8 | Card titles: render `plain_name`, keep the id from `check.name` | createResultCard, app.js:1073 | Small | Any test reading `.result-title`. Grep first |
| 9 | Pills | STATUS_LABELS (app.js:59) and each transform's `pill_label` | Small for the safe subset (N/A to "Does not apply", one word for fail) | "Not configured" is a CLAUDE.md rule pinned by test_status_semantics:100 to 110, so Neil decides |
| 10 | What's unusual and the services sections | app.js:834 to 858 and 927 to 954 | Small | |
| 11 | PDF pages 1 and 2 | pdf_report:377, 562 and 1921 | Medium to large | test_pdf_two_parts, test_pdf_report_accuracy, test_report_agrees_with_itself, test_tone_and_repetition:295 to 298, test_status_semantics:220 |
| 12 | Article boxes and definitions, plus a `.short-version` CSS rule (CSP forbids inline styles) | The five article files and style.css | Small | PAGE_BANNED in test_tone_and_repetition, the dash test, test_article_rfc_links (no RFC links in the box), test_css_hygiene, test_visual_system, test_asset_version_is_current |
