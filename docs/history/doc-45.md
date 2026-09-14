# Doc 45: The other checks: SPF, DANE, CAA, BIMI, TLS-RPT, MTA-STS, DKIM, MX, and a PDF crash

Third doc from the Sept 13 review. Each item changes a status,
a count, or a verdict on a non-DMARC card. Anchors are given
by content as well as line, from main at eec05ae; Docs 43 and
44 moved lines in audit_engine.py and result_transformer.py,
so search for the quoted string when a number is off.
Reproduce and test through run_full_audit with
tests/conftest.py FakeZone, as Doc 44 did.

## 1. SPF: registered modifiers fail the card, and v=spf10 is accepted as SPF

audit_engine.py around 2542 to 2548, the branch "elif
mod_name_lower not in KNOWN_MODIFIERS" calls _add_syntax with
"Unknown modifier: ... is not a recognized SPF modifier",
severity error, so the card fails. RFC 7208 section 6:
unrecognized modifiers MUST be ignored no matter where or how
often they appear. RFC 6652 registers ra, rp, and rr with
IANA. Reproduced: "v=spf1 mx -all ra=postmaster rp=10 rr=all"
is a red Fail card with three error rows.

Fix: add ra, rp, rr to KNOWN_MODIFIERS, and grade any other
unknown modifier as an info detail ("Unknown modifier 'x' is
ignored by receivers (RFC 7208 section 6)"), never a failure.

Also: the three places that detect an SPF record with
startswith("v=spf1") (around 2434, 4475, 4603) accept "v=spf10
..." as SPF. RFC 7208 section 4.5: the version section is
"v=spf1" followed by a space or the end of the record;
anything else is not an SPF record. Match "v=spf1" followed by
whitespace or end of string, case insensitive.

## 2. SPF: the same finding three times on one card

The engine emits its own ptr warning (around 2614, "Deprecated
'ptr' mechanism") and its own lookup-limit findings, then
merges spf_recursive's issues, which carry the same two
findings (spf_recursive.py near lines 518, 538, 681), and the
transformer adds a third lookup-limit row
(result_transformer.py around 4181, 4203, 4205). Reproduced:
"v=spf1 ptr mx -all" shows the ptr warning twice; a record at
exactly 10 lookups shows three "at the limit" rows; over 10
shows three error rows.

Fix: keep spf_recursive as the single source for ptr and
lookup-count findings, delete the engine copies, and have the
transformer add its budget line only when spf_recursive
produced none. Test: each of the three records shows exactly
one row for the finding.

## 3. DANE is judged by the wrong zone's DNSSEC

audit_engine.py around 3906 to 3918: dnssec_ok is computed
from the audited domain's DNSKEY and DS, and the DANE verdict
is keyed on it. RFC 7672 section 2.2.1: the TLSA RRset that
must validate lives at _25._tcp.MXHOST in the MX host's zone,
and hosted domains that are not signed still benefit from a
provider's signed TLSA records. So an unsigned domain whose MX
is a signed provider with TLSA is told "TLSA found but DNSSEC
missing" and that senders will ignore the records
(result_transformer.py around 6452), which is false for those
records, and a signed domain whose MX sits in an unsigned zone
is told "DNSSEC is enabled and the DANE chain of trust is
valid" (around 6487), also false.

Fix: the TLSA query already goes through _get_dnssec_resolver
with DO set; read the AD flag on each TLSA answer (the pattern
at 2951 and 3009 does this for DNSKEY) and use it per MX host
for "TLSA validates" or "TLSA present but not DNSSEC
validated". Keep the audited domain's own DNSSEC state only
for the separate statement that an unsigned MX RRset can be
redirected. The FakeZone harness cannot model per-zone AD, so
add a unit test that feeds a fake TLSA answer with and without
AD and asserts the per-host result; the transformer strings
follow from that.

While there: on a domain whose MX list mixes its own host with
a provider's (10 mail.example.test, 20 aspmx.l.google.com),
the DANE card says mail is handled by Google Workspace so the
MX hostnames are not under the domain's control. That is false
for the priority 10 host. Gate the hosted-provider wording on
every MX host belonging to the provider.

## 4. DANE, MTA-STS, and TLS-RPT on a domain with no MX

A domain with no MX gets a DANE card with status absent, pill
"N/A", and verdict "No MX hosts to check", counted under Not
configured. "N/A" is outside the Doc 38 pill vocabulary. And
on the same domain the roadmap can name MTA-STS as the biggest
risk ("email encryption can be silently stripped") for a
domain that receives no mail.

Fix: keep status absent for DANE, MTA-STS, and TLS-RPT when
there is no MX, with pill "Not applicable" and a verdict that
says why ("No MX records, so there is no inbound mail to
protect"), and exclude the three from the roadmap and the
biggest-risk line when has_mx is false, which
remediation_planner already does. Test: a zone with A and NS
only has no MTA-STS, TLS-RPT, or DANE roadmap rows.

## 5. CAA tag matching is case sensitive

audit_engine.py around 3434 to 3447 compares tag == "issue",
"issuewild", "iodef". RFC 8659 section 4.1: matching of tags
is case insensitive. Reproduced: 0 ISSUE "letsencrypt.org"
gives pass with no Authorized CA row, no issuewild advice, and
an empty authorized_cas list, which silently disables the
certificate transparency versus CAA comparison. Fix: compare
tag.lower().

## 6. Two parse errors become "Not checked" instead of findings

checks_extra.py around 1260 catches only ET.ParseError when
parsing the BIMI logo. defusedxml raises EntitiesForbidden, a
ValueError, for any DTD with an internal entity, which
Illustrator SVG exports carry routinely. Reproduced: a BIMI
record plus such a logo gives BIMI unavailable, "Not checked
by this audit". The right answer is a finding: "Logo declares
XML entities, which SVG Tiny PS forbids". Fix: catch
(ET.ParseError, ValueError) and emit that finding.

checks_extra.py calls urlparse on record-supplied URIs (around
728 for the TLS-RPT rua, 890 and 900 for the BIMI l= and a=).
urlparse("https://[bad") raises ValueError. Reproduced:
rua=https://[bad in TLS-RPT and l=https://[bad/logo.svg in
BIMI both produce Error cards. Fix: wrap each in try/except
ValueError and emit an "invalid URI" issue.

## 7. MTA-STS and TLS-RPT are stricter than their RFCs about unknown and duplicate fields

checks_extra.py around 417: an unknown MTA-STS policy field is
a warning, amber card. RFC 8461 section 3.2: unknown fields
SHALL be ignored, and the grammar has sts-policy-extension for
them. Around 703: an unknown TLS-RPT tag is a warning. RFC
8460 section 3: parsers MUST accept records implementing a
superset of the specification and ignore unknown fields. Both
become info details.

Around 422 to 429: a duplicated non-mx policy field is graded
error with the text "The second value silently overwrites the
first", and the parser around 351 and 360 keeps the last
value. RFC 8461 section 3.2: for duplicated fields all entries
except the first SHALL be ignored. Keep the first value, and
grade the duplicate a warning that says the first value is the
one in force.

## 8. The PDF crashes on a long DMARC record

pdf_report.py around 862, the tag-by-tag table puts each tag
value in one cell. ReportLab cannot split one row across a
page, so a rua value taller than a page raises LayoutError and
/api/audit/DOMAIN/pdf returns 500. Reproduced: 10 rua
addresses render, 20 do not, at a record length the engine
itself anticipates with its "very long record" warning. Fix:
splitInRow=1 on that Table, or render rua and ruf as a wrapped
Paragraph under the table with a length cap and a "and N more"
tail. Test: a record with 25 rua addresses renders.

## 9. DKIM: "Tested 0 selectors" beside a found key, and a revoked key counted as a working path

audit_engine.py sets tested_count = 1 only on the not-found
and failed branches of the user-supplied selector path (around
5018 and 5029); the success branch never sets it, so the card
prints "1 DKIM public key published" beside "Tested 0
selectors". Set tested_count before the lookup.

spf_execution_engine.py:280 dkim_result = "configured" if
found_selectors. A selector publishing p= (revoked) is in
found_selectors. Reproduced: the DKIM card says "published but
retired" while the DMARC evaluation panel on the same page
says "SPF and DKIM are configured ... providing redundant
paths to DMARC pass". Use _split_dkim_selectors as
audit_engine.py already does near its comment "the fourth
place" that read found_selectors as a boolean.

## 10. MX: a false statement and a contradiction

mx_check.py:281 to 282, the no-MX warning: "Most modern mail
servers require MX records and will not attempt delivery
without them. Email delivery will fail for most senders." RFC
5321 section 5.1: with no MX, the address is treated as if it
had an implicit MX pointing at the domain's A or AAAA host.
The card's own explanation (result_transformer.py, "If this
domain is not intended to receive email, this is expected")
says the opposite. Replace the warning with: "No MX records
for {domain}. Senders fall back to the domain's A or AAAA
record (RFC 5321 section 5.1), so mail is still attempted if
that host runs SMTP." and the impact line with "Mail arrives
at the A record host, or bounces if nothing listens there."

Single MX host: mx_check.py:361 says "inbound mail queues at
the sending server and may eventually bounce", the explanation
on the same card says "inbound email delivery will fail until
it recovers". Keep the first, delete the second sentence.

## 11. The resilience block disagrees with the cards beside it

app.js around 715 to 717 maps a mechanism status of missing to
fail, so on a domain with no mail the SPF card is amber "No
mail" while the resilience row is red "Missing". Map no-mail
to warn, or have the transformer emit a distinct status for
it.

audit_engine.py _build_resilience_analysis (around 5678
onward): when DMARC is at reject and only DKIM is inconclusive
(no selector supplied), the level drops to Moderate, so the
executive summary says "Full" in green and the resilience
block two sections down says "Moderate" in amber for the same
domain. An inconclusive mechanism is unknown, not weak; do not
lower the level for it, and render it with the info tag rather
than warn.

## Tests

One fixture zone per item through run_full_audit, asserting on
card status, pill, details, the roadmap, and the resilience
block where the item touches them. Item 3 gets a unit test
with a fake TLSA answer. Item 8 asserts the PDF renders.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-45.md in the same commit.

## Done when

SPF ignores what RFC 7208 says to ignore and says each finding
once; DANE is judged on the MX host's zone; a no-MX domain is
not told to add transport protocols; CAA tags match regardless
of case; a BIMI logo with entities and a bad URI are findings
rather than "Not checked"; MTA-STS and TLS-RPT ignore unknown
fields and keep the first duplicate; a long DMARC record
renders as a PDF; DKIM counts what it tested and does not
count a revoked key as working; the MX card agrees with
itself; and the resilience block agrees with the cards.
